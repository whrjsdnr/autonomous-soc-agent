/* Authentication-only qualification: no libbpf, map, load, attach or data channel.
 * Separate from the still-closed Kernel gate. Only STATUS and STOP are accepted.
 */
#define _GNU_SOURCE
#include "handoff.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <dirent.h>
static volatile sig_atomic_t closing;
static void stop(int sig) {(void)sig;closing=1;}
static int rejected(const char *stage) {
    /* Fixed stage labels only. Never print policy lines, account data or hashes. */
    fprintf(stderr,"OS_AUTH_POLICY_REJECTED:%s\n",stage);return -EPERM;
}
static int shadow_metadata(const struct stat *st) {
    /* /etc/shadow is commonly root:shadow 0640, not a root:root executable.
     * Its group can read but cannot write. Do not resolve names through NSS or
     * relax soc_trusted(), which still protects every executable/other file. */
    unsigned mode=st->st_mode&07777;
    return !S_ISREG(st->st_mode) || st->st_uid || st->st_nlink!=1 ||
        (mode!=0600 && mode!=0640)?-EPERM:0;
}
static int shadow_open(void) {
    /* Fixed path only, held directory FDs, no symlink or parent-path reopening. */
    int root=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC),folder=-1,fd=-1;
    struct stat st;
    if(root<0 || fstat(root,&st) || !S_ISDIR(st.st_mode) ||
       st.st_uid || st.st_gid || (st.st_mode&022))goto done;
    folder=openat(root,"etc",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(folder<0 || fstat(folder,&st) || !S_ISDIR(st.st_mode) ||
       st.st_uid || st.st_gid || (st.st_mode&022))goto done;
    fd=openat(folder,"shadow",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd>=0 && (fstat(fd,&st) || shadow_metadata(&st))) {close(fd);fd=-1;}
done:
    if(folder>=0)close(folder);if(root>=0)close(root);return fd;
}
static int text(const char *path,char *body,size_t size) {
    int fd=!strcmp(path,"/etc/shadow")?shadow_open():soc_trusted(path,NULL);
    struct stat before,after;
    if(fd<0)return -EPERM;
    if(fstat(fd,&before)) {close(fd);return -EPERM;}
    ssize_t n=pread(fd,body,size-1,0);
    int rc=n<0 || (size_t)n>=size-1 || fstat(fd,&after) || before.st_size!=n ||
        before.st_dev!=after.st_dev || before.st_ino!=after.st_ino ||
        before.st_size!=after.st_size || before.st_uid!=after.st_uid ||
        before.st_gid!=after.st_gid || before.st_mode!=after.st_mode ||
        before.st_nlink!=after.st_nlink ||
        before.st_mtim.tv_sec!=after.st_mtim.tv_sec || before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec!=after.st_ctim.tv_sec || before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec;
    close(fd);if(rc)return -EPERM;body[n]=0;return 0;
}
static void normalize(char *s) {
    char *out=s;int space=0;
    for(char *c=s;*c;c++) {
        if(*c==' ' || *c=='\t' || *c=='\r') {if(out!=s)space=1;continue;}
        if(space)*out++=' ';space=0;*out++=*c;
    }*out=0;
}
/* Deliberately small supported policy, never a permissive sudoers parser.
 * Reject aliases, exemptions, NOPASSWD, alternate plugins and unknown Defaults.
 * sudo itself makes the actual allow/deny/account decision before this process.
 */
static int sudoers_file(const char *path,int main_file) {
    char body[16384];if(text(path,body,sizeof(body)))return -EPERM;
    char *save,*line=strtok_r(body,"\n",&save);
    for(;line;line=strtok_r(NULL,"\n",&save)) {
        normalize(line);if(!*line)continue;
        if(main_file && (!strcmp(line,"@includedir /etc/sudoers.d") ||
                         !strcmp(line,"#includedir /etc/sudoers.d")))continue;
        if(line[0]=='#' && strncmp(line,"#include",8))continue;
        const char *allowed[]={"Defaults env_reset","Defaults mail_badpass","Defaults use_pty",
          "Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin\"",
          "Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"",
          "root ALL=(ALL:ALL) ALL","%admin ALL=(ALL) ALL","%sudo ALL=(ALL:ALL) ALL"};
        int known=0;for(unsigned i=0;i<sizeof(allowed)/sizeof(*allowed);i++)if(!strcmp(line,allowed[i]))known=1;
        if(!known)return -EPERM;
    }return 0;
}
static int policy(unsigned uid,unsigned gid) {
    if(sudoers_file("/etc/sudoers",1))return rejected("SUDOERS_POLICY");
    int folder=open("/etc/sudoers.d",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);struct stat ds;
    if(folder<0)return -EPERM;
    if(fstat(folder,&ds) || ds.st_uid || ds.st_gid || (ds.st_mode&022)) {close(folder);return -EPERM;}
    DIR *d=fdopendir(folder);if(!d) {close(folder);return -EPERM;}
    struct dirent *entry;int count=0,rc=0;
    while((entry=readdir(d))) {
        if(!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..") ||
           strchr(entry->d_name,'.') || entry->d_name[strlen(entry->d_name)-1]=='~')continue;
        char path[256];if(++count>32 || snprintf(path,sizeof(path),"/etc/sudoers.d/%s",entry->d_name)>=(int)sizeof(path) ||
           sudoers_file(path,0)) {rc=-EPERM;break;}
    }closedir(d);if(rc)return rejected("SUDOERS_INCLUDED_POLICY");
    char body[32768];
    /* Non-default sudo plugins or debug/policy configuration require review. */
    if(access("/etc/sudo.conf",F_OK)==0) {
        if(text("/etc/sudo.conf",body,sizeof(body)))return -EPERM;
        char *save,*line=strtok_r(body,"\n",&save);
        for(;line;line=strtok_r(NULL,"\n",&save)) {normalize(line);if(*line && *line!='#')return -EPERM;}
    }
    if(text("/etc/nsswitch.conf",body,sizeof(body)))return -EPERM;
    char *save,*line=strtok_r(body,"\n",&save);
    for(;line;line=strtok_r(NULL,"\n",&save)) {
        normalize(line);if(!strncmp(line,"sudoers:",8) && strcmp(line,"sudoers: files"))return -EPERM;
    }
    /* Require the exact OS pam_unix password stack, not an unchecked PAM success.
     * Hashes of these public OS configuration files are compiled into this release.
     */
#ifndef SOC_AUTH_PAM_SHA
    return -EPERM;
#else
    const char *paths[]={"/etc/pam.d/sudo","/etc/pam.d/common-auth","/etc/pam.d/common-account"};
    const char *hexes[]={SOC_AUTH_PAM_SHA,SOC_AUTH_COMMON_SHA,SOC_AUTH_ACCOUNT_SHA};
    for(int i=0;i<3;i++) {
        int fd=soc_trusted(paths[i],NULL);uint8_t hash[32];char hex[65];
        if(fd<0 || soc_fd_sha(fd,hash)) {if(fd>=0)close(fd);return -EPERM;}
        close(fd);for(int j=0;j<32;j++)snprintf(hex+2*j,3,"%02x",hash[j]);
        if(strcmp(hex,hexes[i]))return -EPERM;
    }
#endif
    const char *name=getenv("SUDO_USER");if(!name || !*name || strlen(name)>64 || strchr(name,':') || strchr(name,'\n'))return -EPERM;
    if(text("/etc/passwd",body,sizeof(body)))return -EPERM;
    char prefix[80];snprintf(prefix,sizeof(prefix),"%s:",name);int found=0;
    line=strtok_r(body,"\n",&save);
    for(;line;line=strtok_r(NULL,"\n",&save))if(!strncmp(line,prefix,strlen(prefix))) {
        char expected[128];snprintf(expected,sizeof(expected),"%s:x:%u:%u:",name,uid,gid);
        if(strncmp(line,expected,strlen(expected)))return -EPERM;found++;
    }
    if(found!=1)return rejected("LOCAL_ACCOUNT_IDENTITY");
    if(text("/etc/shadow",body,sizeof(body)))return rejected("SHADOW_FILE_TRUST");
    found=0;line=strtok_r(body,"\n",&save);
    for(;line;line=strtok_r(NULL,"\n",&save))if(!strncmp(line,prefix,strlen(prefix))) {
        /* nullok cannot bypass the challenge for a nonempty local password hash. */
        char *hash=line+strlen(prefix),*end=strchr(hash,':');
        if(!end || end-hash<20 || *hash!='$') {
            explicit_bzero(body,sizeof(body));return rejected("LOCAL_PASSWORD_REQUIRED");
        }found++;
    }
    explicit_bzero(body,sizeof(body));return found==1?0:rejected("LOCAL_PASSWORD_IDENTITY");
}
static int drop(unsigned uid,unsigned gid) {
    for(int cap=0;cap<=CAP_LAST_CAP;cap++)if(prctl(PR_CAPBSET_DROP,cap,0,0,0))return -EPERM;
    if(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0) || setgroups(0,NULL) ||
       setresgid(gid,gid,gid) || setresuid(uid,uid,uid) || prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return -EPERM;
    struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct caps[2]={{0}};
    if(syscall(SYS_capget,&h,caps))return -EPERM;
    for(int i=0;i<2;i++)if(caps[i].effective || caps[i].permitted || caps[i].inheritable)return -EPERM;
    return 0;
}
int soc_os_password_policy_only(unsigned uid,unsigned gid) {
    struct rlimit no_core={0,0};if(setrlimit(RLIMIT_CORE,&no_core))return -EPERM;
    if(!uid || !gid || getuid() || geteuid() || getgid() || getegid() || !isatty(0))return rejected("ROOT_TTY");
    const char *u=getenv("SUDO_UID"),*g=getenv("SUDO_GID");
    char wanted[32];snprintf(wanted,sizeof(wanted),"%u",uid);
    if(!u || strcmp(u,wanted))return rejected("SUDO_UID");
    snprintf(wanted,sizeof(wanted),"%u",gid);if(!g || strcmp(g,wanted))return rejected("SUDO_GID");
    return policy(uid,gid);
}
int soc_os_password_policy(unsigned uid,unsigned gid) {
    if(soc_os_password_policy_only(uid,gid))return -EPERM;
    int sudo_fd=soc_trusted("/usr/bin/sudo",NULL);struct stat trusted,parent;
    char path[64];snprintf(path,sizeof(path),"/proc/%u/exe",getppid());
    if(sudo_fd<0 || fstat(sudo_fd,&trusted) || stat(path,&parent) ||
       trusted.st_dev!=parent.st_dev || trusted.st_ino!=parent.st_ino) {if(sudo_fd>=0)close(sudo_fd);return rejected("SUDO_PARENT_IDENTITY");}
    close(sudo_fd);
    /* Require the OS process itself to have ignored the timestamp for this
     * fixed command. A Controller assertion or SUDO_* variable is insufficient.
     * Setuid sudo's proc memory/argv are outside the invoking user's write scope. */
    snprintf(path,sizeof(path),"/proc/%u/cmdline",getppid());
    int command=open(path,O_RDONLY|O_CLOEXEC);char arguments[4096];
    if(command<0)return rejected("SUDO_PARENT_ARGUMENTS_UNAVAILABLE");
    ssize_t n=read(command,arguments,sizeof(arguments));close(command);
    if(n<1 || n>=(ssize_t)sizeof(arguments) || arguments[n-1])return rejected("SUDO_PARENT_ARGUMENTS_INVALID");
    const char *fixed[]={"-k","-u","root","--",SOC_INSTALL "bootstrap"};
    size_t offset=strnlen(arguments,n)+1;
    for(unsigned i=0;i<sizeof(fixed)/sizeof(*fixed);i++) {
        if(offset>=(size_t)n || strcmp(arguments+offset,fixed[i]))return rejected("SUDO_FRESH_FIXED_COMMAND");
        offset+=strlen(arguments+offset)+1;
    }
    if(offset>=(size_t)n || (strcmp(arguments+offset,"--auth-qualification") &&
                            strcmp(arguments+offset,"--live-qualification")))return -EPERM;
    return 0;
}
static int auth_wait_controller_close(int channel) {
    /* The terminal ACK must remain attributable to the same live process while
     * the Controller validates SCM credentials and PID/start ticks. Wait for its
     * socket close after ACK; never exit before that identity check can finish. */
    uint64_t deadline=soc_now()+5000000000ULL;
    while(!closing && soc_now()<deadline) {
        struct pollfd wait={channel,POLLIN,0};int ready=poll(&wait,1,100);
        if(ready<0 && errno==EINTR)continue;
        if(ready<0 || (wait.revents&(POLLERR|POLLNVAL)))return -EIO;
        if(!ready)continue;
        char byte;ssize_t n=recv(channel,&byte,1,MSG_PEEK|MSG_DONTWAIT);
        if(!n)return 0;
        if(n<0 && (errno==EAGAIN || errno==EINTR))continue;
        return -EPROTO; /* No command, replay or trailing bytes after STOP. */
    }
    return -ETIMEDOUT;
}
static int auth_serve(int channel,const struct soc_plan *plan) {
    uint64_t born=soc_now();uint32_t sequence=0;
    for(unsigned count=0;!closing && count<2048 && soc_now()-born<3600000000000ULL;count++) {
        struct pollfd wait={channel,POLLIN,0};int ready=poll(&wait,1,100);
        if(ready<0 && errno==EINTR)continue;
        if(ready<0 || soc_peer(channel,plan))return -EPERM;
        if(!ready){count--;continue;}
        struct soc_request q={0};
        if(soc_receive_request(channel,plan,sequence,&q))return -EPROTO;
        /* Wire ABI: STATUS=3, STOP=5. CLEANUP=6 is not an auth-only command. */
        if(q.operation!=3 && q.operation!=5)return -EPERM;
        sequence=q.sequence;
        struct {uint32_t sequence,state;int32_t error;uint32_t reserved;struct soc_owner owner;} reply={sequence,3,0,0,{0}};
        if(send(channel,&reply,sizeof(reply),MSG_NOSIGNAL)!=sizeof(reply))return -EPIPE;
        if(q.operation==5)return auth_wait_controller_close(channel);
    }
    return -ETIMEDOUT;
}
int soc_auth_qualification(unsigned uid,unsigned gid,const uint8_t app[16],
                           const uint8_t approval[32],const uint8_t manifest[32],const uint8_t purpose[32]) {
    if(soc_os_password_policy(uid,gid))return -EPERM;
    if(clearenv() || setenv("PATH","/usr/bin:/bin",1) || setenv("LANG","C",1) || chdir("/"))return -EPERM;
    umask(077);signal(SIGPIPE,SIG_IGN);signal(SIGTERM,stop);signal(SIGINT,stop);
    struct rlimit memory={268435456,268435456},cpu={19,20},core={0,0};
    if(setrlimit(RLIMIT_AS,&memory) || setrlimit(RLIMIT_CPU,&cpu) || setrlimit(RLIMIT_CORE,&core))return -EPERM;
    int channel=soc_handoff_connect(uid,gid,app),plan=-1,audit=-1;
    struct soc_release_envelope e;
    if(channel<0 || soc_handoff_receive(channel,uid,gid,app,approval,manifest,&e,&plan,&audit) ||
       soc_release_check(&e.plan,e.manifest_sha,e.release_version,1))return -EPERM;
    const char label[]="SOC_AUTH_ONLY_V1";uint8_t body[sizeof(label)+sizeof(e)],hash[32];
    memcpy(body,label,sizeof(label));memcpy(body+sizeof(label),&e,sizeof(e));
    if(soc_sha(body,sizeof(body),hash) || memcmp(hash,purpose,32) ||
       soc_handoff_reply(channel,&e,1,3) || drop(uid,gid) ||
       soc_handoff_reply(channel,&e,2,3))return -EPERM;
    /* No privileged FD or BPF object exists. This is an unprivileged status-only
     * broker; it cannot become a Native ATTACH session. */
    int rc=auth_serve(channel,&e.plan);
    close(audit);close(plan);close(channel);return rc;
}
