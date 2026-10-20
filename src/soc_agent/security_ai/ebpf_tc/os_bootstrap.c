/* OS-authenticated fixed entry. Never setuid; never calls PAM or accepts a path. */
#define _GNU_SOURCE
#include "handoff.h"
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int number(const char *s,unsigned *out) {
    if(!s || !*s || strlen(s)>10)return -1;
    for(const char *c=s;*c;c++)if(*c<'0' || *c>'9')return -1;
    char *end;unsigned long n=strtoul(s,&end,10);
    if(*end || !n || n>=0xffffffffUL)return -1;*out=n;return 0;
}
static int hex(const char *text,uint8_t *out,int size) {
    if(!text || strlen(text)!=(size_t)size*2)return -1;
    for(int i=0;i<size;i++) {
        char a=text[2*i],b=text[2*i+1];
        if(!strchr("0123456789abcdef",a) || !strchr("0123456789abcdef",b))return -1;
        char pair[]={a,b,0};out[i]=strtoul(pair,NULL,16);
    }return 0;
}
static int root_copy(int fd,const uint8_t expected[32]) {
    struct stat st;uint8_t sha[32];
    if(fstat(fd,&st) || st.st_size<1 || st.st_size>1048576 || soc_fd_sha(fd,sha) ||
       memcmp(sha,expected,32))return -1;
    char *body=malloc(st.st_size);if(!body)return -1;
    int target=memfd_create("soc-os-session",MFD_ALLOW_SEALING|MFD_CLOEXEC);
    if(target<0 || pread(fd,body,st.st_size,0)!=st.st_size ||
       write(target,body,st.st_size)!=st.st_size || fcntl(target,F_ADD_SEALS,15)) {
        if(target>=0)close(target);target=-1;
    }free(body);return target;
}
static int bootstrap(unsigned uid,unsigned gid,const uint8_t app[16],
                     const uint8_t approval[32],const uint8_t manifest[32]) {
    /* This is an independent qualification gate, not a caller-supplied auth flag. */
    if(!soc_native_gate() || !soc_os_auth_admitted())return -EPERM;
    if(getuid() || geteuid() || getgid() || getegid())return -EPERM;
    unsigned invoking_uid=0,invoking_gid=0;
    if(number(getenv("SUDO_UID"),&invoking_uid) || number(getenv("SUDO_GID"),&invoking_gid) ||
       invoking_uid!=uid || invoking_gid!=gid || !isatty(0))return -EPERM;
    /* SUDO_* alone is never proof. Qualified OS policy + root credentials + fixed
     * sudo parent inode + kernel Controller peer and exact session are required. */
    int sudo_fd=soc_trusted("/usr/bin/sudo",NULL);struct stat trusted,parent;
    char path[64];snprintf(path,sizeof(path),"/proc/%u/exe",getppid());
    if(sudo_fd<0 || fstat(sudo_fd,&trusted) || stat(path,&parent) ||
       trusted.st_dev!=parent.st_dev || trusted.st_ino!=parent.st_ino)return -EPERM;
    close(sudo_fd);
    if(clearenv() || setenv("PATH","/usr/bin:/bin",1) || setenv("LANG","C",1) ||
       chdir("/") || close_range(3,~0U,0))return -EPERM;
    sigset_t empty;sigemptyset(&empty);
    if(sigprocmask(SIG_SETMASK,&empty,NULL))return -EPERM;
    signal(SIGALRM,SIG_DFL);signal(SIGINT,SIG_DFL);signal(SIGTERM,SIG_DFL);
    umask(077);signal(SIGPIPE,SIG_IGN);alarm(15);
    struct rlimit memory={268435456,268435456},cpu={19,20},core={0,0},files={64,64};
    if(setrlimit(RLIMIT_AS,&memory) || setrlimit(RLIMIT_CPU,&cpu) ||
       setrlimit(RLIMIT_CORE,&core) || setrlimit(RLIMIT_NOFILE,&files))return -EPERM;
    int channel=soc_handoff_connect(uid,gid,app),plan=-1,audit=-1;
    struct soc_release_envelope e;uint8_t hash[32];
    if(channel<0 || soc_handoff_receive(channel,uid,gid,app,approval,manifest,&e,&plan,&audit) ||
       flock(audit,LOCK_EX|LOCK_NB) ||
       soc_release_check(&e.plan,e.manifest_sha,e.release_version,1))return -EPERM;
    int executable=soc_trusted(SOC_INSTALL "broker",e.plan.broker_sha);
    int object=soc_trusted(SOC_INSTALL "tc.bpf.o",e.plan.program_sha);
    if(executable<0 || object<0 || soc_fd_sha(plan,hash))return -EPERM;
    int authority=root_copy(plan,hash),code=root_copy(object,e.plan.program_sha);
    if(authority<0 || code<0 || soc_peer(channel,&e.plan) ||
       soc_release_check(&e.plan,e.manifest_sha,e.release_version,1) ||
       soc_handoff_reply(channel,&e,1,1))return -EPERM;
    int originals[]={channel,authority,code,audit,executable},copies[5];
    for(int i=0;i<5;i++)if((copies[i]=fcntl(originals[i],F_DUPFD_CLOEXEC,32))<0)return -EPERM;
    for(int i=0;i<5;i++)if(dup2(copies[i],3+i)<0)return -EPERM;
    if(close_range(8,~0U,0) || soc_reduce(uid,gid))return -EPERM;
    alarm(0);char *const args[]={"broker","3","4","5","6",NULL};
    fexecve(7,args,soc_clean_environment());return -errno;
}
int main(int argc,char **argv) {
    if(argc==2 && !strcmp(argv[1],"--inspect") && getuid()==geteuid() && getuid()) {
        puts("{\"stage\":\"B2J_OS_HANDOFF\",\"native_gate\":false,\"pam_invoked\":false,\"os_auth_qualification\":\"PENDING\"}");return 0;
    }
    if(!soc_native_gate() || !soc_os_auth_admitted()) {
        fputs("EBPF_B2A_NATIVE_EXECUTION_BLOCKED:OS_AUTH_QUALIFICATION_PENDING\n",stderr);return 2;
    }
    unsigned uid,gid;uint8_t app[16],approval[32],manifest[32];
    if(argc!=7 || strcmp(argv[1],"--os-handoff") || number(argv[2],&uid) ||
       number(argv[3],&gid) || hex(argv[4],app,16) ||
       hex(argv[5],approval,32) || hex(argv[6],manifest,32))return 2;
    return bootstrap(uid,gid,app,approval,manifest)?2:0;
}
