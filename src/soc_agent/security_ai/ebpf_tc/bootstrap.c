#define _GNU_SOURCE
#include "native.h"
#include "pam_abi.h"
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern char **environ;
static const char policy[]="auth required pam_unix.so\naccount required pam_unix.so\n";
static int conversation(int n,const struct pam_message **m,struct pam_response **r,void *data) {
    int *challenges=data;
    if(n<1 || n>4)return PAM_CONV_ERR;
    for(int i=0;i<n;i++) {
        if(m[i]->msg_style==PAM_PROMPT_ECHO_OFF) {if(++*challenges!=1)return PAM_CONV_ERR;}
        else if(m[i]->msg_style!=PAM_TEXT_INFO && m[i]->msg_style!=PAM_ERROR_MSG)return PAM_CONV_ERR;
    }
    /* System terminal conversation owns ephemeral password buffers, not Python/GUI. */
    return misc_conv(n,m,r,NULL);
}
int soc_password(uid_t uid) {
    if(!soc_native_gate())return -EPERM;
    int fd=soc_trusted(SOC_POLICY,NULL);if(fd<0)return -EPERM;
    char body[sizeof(policy)+1]={0};ssize_t n=read(fd,body,sizeof(body));close(fd);
    if(n!=(ssize_t)strlen(policy) || memcmp(body,policy,strlen(policy)))return -EPERM;
    struct passwd *user=getpwuid(uid);if(!user || !user->pw_name || !uid)return -EPERM;
    int tty=open("/dev/tty",O_RDWR|O_CLOEXEC|O_NOCTTY);struct stat st;
    if(tty<0)return -ENOTTY;
    if(!isatty(tty) || fstat(tty,&st) || st.st_uid!=uid || tcgetsid(tty)!=getsid(0) ||
       tcgetpgrp(tty)!=getpgrp()) {close(tty);return -ENOTTY;}
    /* Bind system PAM's conversation to the OS terminal. No stdin pipe/askpass fallback. */
    if(dup2(tty,0)<0 || dup2(tty,1)<0 || dup2(tty,2)<0) {close(tty);return -EIO;}close(tty);
    int challenges=0;struct pam_conv conv={conversation,&challenges};pam_handle_t *handle=NULL;
    alarm(60);int rc=pam_start("soc-agent-ebpf",user->pw_name,&conv,&handle);
    if(rc==PAM_SUCCESS)rc=pam_authenticate(handle,PAM_DISALLOW_NULL_AUTHTOK);
    if(rc==PAM_SUCCESS && challenges==1)rc=pam_acct_mgmt(handle,0);else rc=PAM_CONV_ERR;
    if(handle)pam_end(handle,rc);alarm(0);
    struct soc_auth_facts facts={uid,getgid(),getuid(),geteuid(),st.st_uid,1,1,1,
        challenges,rc,0};
    return soc_auth_contract(&facts);
}
static int sealed_copy(int fd,const uint8_t expected[32]) {
    struct stat st;uint8_t hash[32];
    if(fstat(fd,&st) || soc_fd_sha(fd,hash) || memcmp(hash,expected,32))return -EPERM;
    void *body=malloc(st.st_size);if(!body)return -ENOMEM;
    int out=memfd_create("soc-root-approved-object",MFD_ALLOW_SEALING);
    if(out<0 || pread(fd,body,st.st_size,0)!=st.st_size ||
       write(out,body,st.st_size)!=st.st_size || fcntl(out,F_ADD_SEALS,15)) {
        if(out>=0)close(out);free(body);return -EIO;
    }free(body);return out;
}
static int bootstrap(int channel,int plan_fd,int audit_fd) {
    if(!soc_native_gate())return -EPERM;
    /* Intended future deployment is one audited root-owned setuid bootstrap. No
     * sudo path is admitted: sudo changes real UID to root and is rejected here.
     * Consequently no cached/NOPASSWD sudo policy substitutes for this PAM challenge. */
    uid_t uid=getuid();gid_t gid=getgid();
    if(!uid || !gid || geteuid()!=0 || !isatty(0) || clearenv())return -EPERM;
    struct stat audit;int audit_flags=fcntl(audit_fd,F_GETFL);
    if(fstat(audit_fd,&audit) || !S_ISREG(audit.st_mode) || audit.st_uid!=uid ||
       audit.st_nlink!=1 || audit.st_size || (audit.st_mode&0777)!=0600 ||
       audit_flags<0 || !(audit_flags&O_APPEND) || flock(audit_fd,LOCK_EX|LOCK_NB))return -EPERM;
    struct soc_plan p;uint8_t psha[32];struct stat plan_info;
    if(fstat(plan_fd,&plan_info) || plan_info.st_size!=sizeof(p) || pread(plan_fd,&p,sizeof(p),0)!=sizeof(p) || soc_fd_sha(plan_fd,psha) ||
       soc_sealed(plan_fd,psha) || soc_plan_validate(&p) || p.uid!=uid || p.gid!=gid ||
       p.controller_pid!=(uint32_t)getppid() || soc_peer(channel,&p))return -EPERM;
    int mf=soc_trusted(SOC_INSTALL "manifest.bin",NULL);struct soc_manifest manifest;
    if(mf<0)return -EPERM;
    struct stat st;int ok=!fstat(mf,&st) && st.st_size==sizeof(manifest) &&
        read(mf,&manifest,sizeof(manifest))==sizeof(manifest);close(mf);
    if(!ok || memcmp(manifest.bootstrap,p.bootstrap_sha,32) ||
       memcmp(manifest.broker,p.broker_sha,32) || memcmp(manifest.program,p.program_sha,32) ||
       memcmp(manifest.loader,p.loader_sha,32) || memcmp(manifest.bundle,p.bundle_sha,32))return -EPERM;
    int self=soc_trusted(SOC_INSTALL "bootstrap",manifest.bootstrap);
    int broker=soc_trusted(SOC_INSTALL "broker",manifest.broker);
    int loader=soc_trusted(SOC_INSTALL "libnative-tc.so",manifest.loader);
    int object=soc_trusted(SOC_INSTALL "tc.bpf.o",manifest.program);
    if(self<0 || broker<0 || loader<0 || object<0)return -EPERM;
    close(self);close(loader);
    int code=sealed_copy(object,p.program_sha);close(object);if(code<0)return code;
    /* Root-side display/confirmation prevents a hidden malicious CLI scope swap. */
    FILE *tty=fopen("/dev/tty","r+");if(!tty)return -ENOTTY;
    char approval[65]={0},answer[80]={0};
    for(int i=0;i<32;i++)snprintf(approval+2*i,3,"%02x",p.approval[i]);
    const uint8_t *digests[]={p.bootstrap_sha,p.broker_sha,p.loader_sha,p.program_sha,p.bundle_sha};
    const char *names[]={"Bootstrap","Broker","Loader","Program","Bundle"};
    for(int k=0;k<5;k++) {char hex[65];for(int j=0;j<32;j++)snprintf(hex+2*j,3,"%02x",digests[k][j]);
        fprintf(tty,"%s SHA256 %s\n",names[k],hex);}
    fprintf(tty,"SOC eBPF scope: lo index %u hook %u namespace %llu, 300s, 4096 events, "
        "256MiB RSS, 20 CPU seconds. Native AI BLOCKED.\nApproval %s\nType digest: ",
        p.ifindex,p.hook,(unsigned long long)p.namespace_inode,approval);fflush(tty);
    alarm(60);if(!fgets(answer,sizeof(answer),tty))return -EPERM;alarm(0);fclose(tty);
    answer[strcspn(answer,"\r\n")]=0;if(strcmp(answer,approval))return -EPERM;
    if(soc_password(uid) || soc_peer(channel,&p) || soc_plan_validate(&p))return -EPERM;
    /* Fixed verified executable FD only, never a user-supplied path or shell. */
    int authority=sealed_copy(plan_fd,psha);if(authority<0)return -EPERM;
    /* Root-owned sealed authority exists only after the fresh PAM challenge.
     * It is inherited solely by the broker and is never returned/persisted. */
    int source[]={channel,authority,code,audit_fd,broker},temporary[5];
    for(int i=0;i<5;i++)if((temporary[i]=fcntl(source[i],F_DUPFD_CLOEXEC,32))<0)return -EPERM;
    for(int i=0;i<5;i++)if(dup2(temporary[i],3+i)<0)return -EPERM;
    if(close_range(8,~0U,0) || soc_reduce(uid,gid))return -EPERM;
    char *args[]={"broker","3","4","5","6",NULL};
    char *env[]={"PATH=/usr/bin:/bin","LANG=C",NULL};fexecve(7,args,env);return -errno;
}
int main(int argc,char **argv) {
    if(argc==2 && !strcmp(argv[1],"--inspect") && geteuid()==getuid() && getuid()) {
        puts("{\"stage\":\"B2A\",\"native_gate\":false,\"pam_invoked\":false,\"plan_bytes\":272}");return 0;
    }
    /* Unconditional phase boundary before TTY, PAM, manifest or privileged syscalls. */
    if(!soc_native_gate()) {fputs("EBPF_B2A_NATIVE_EXECUTION_BLOCKED\n",stderr);return 2;}
    if(argc!=4)return 2;
    int fd[3];for(int i=0;i<3;i++) {char *end;long n=strtol(argv[i+1],&end,10);
        if(*end || n<3 || n>31)return 2;fd[i]=n;}
    if(fd[0]==fd[1] || fd[0]==fd[2] || fd[1]==fd[2])return 2;
    return bootstrap(fd[0],fd[1],fd[2])?2:0;
}
