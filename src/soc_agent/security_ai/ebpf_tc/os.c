#define _GNU_SOURCE
#include "native.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <grp.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
uint64_t soc_now(void) {struct timespec t;if (clock_gettime(CLOCK_MONOTONIC,&t)) return 0;
    return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;}
int soc_fd_sha(int fd,uint8_t md[32]) {
    struct stat st;if (fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size<1 || st.st_size>1048576)
        return -EINVAL;
    unsigned char *body=malloc(st.st_size);if (!body) return -ENOMEM;
    ssize_t n=pread(fd,body,st.st_size,0);int rc=n==st.st_size?soc_sha(body,n,md):-EIO;
    free(body);return rc;
}
int soc_sealed(int fd,const uint8_t expected[32]) {
    int seals=fcntl(fd,F_GET_SEALS);uint8_t md[32];
    if (seals<0 || (seals&15)!=15 || soc_fd_sha(fd,md) || memcmp(md,expected,32)) return -EPERM;
    return 0;
}
int soc_trusted(const char *path,const uint8_t expected[32]) {
    /* All path components must be root-owned directories, no symlink traversal.
     * openat on directory FDs also prevents parent replacement TOCTOU. */
    if (!path || path[0]!='/' || strstr(path,"//") || path[strlen(path)-1]=='/') return -EPERM;
    char copy[256];if (strlen(path)>=sizeof(copy)) return -EINVAL;strcpy(copy,path+1);
    struct stat root;
    int d=open("/",O_DIRECTORY|O_CLOEXEC),fd=-1;
    if(d<0 || fstat(d,&root) || root.st_uid || (root.st_mode&022)) {if(d>=0)close(d);return -EPERM;}char *save=NULL,*part=strtok_r(copy,"/",&save);
    while (part && d>=0) {
        if(!strcmp(part,".") || !strcmp(part,"..")) {close(d);return -EPERM;}
        char *next=strtok_r(NULL,"/",&save);struct stat st;
        fd=openat(d,part,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|(next?O_DIRECTORY:O_NONBLOCK));
        if (fd<0 || fstat(fd,&st) || st.st_uid || (st.st_mode&022) ||
            (next?!S_ISDIR(st.st_mode):(!S_ISREG(st.st_mode) || st.st_nlink!=1))) {if(fd>=0)close(fd);close(d);return -EPERM;}
        close(d);d=fd;part=next;
    }
    uint8_t md[32];if (d<0 || (expected && (soc_fd_sha(d,md) || memcmp(md,expected,32)))) {
        if(d>=0)close(d);return -EPERM;
    }
    return d; /* caller executes/reads the already verified descriptor, never the path */
}
int soc_scope_environment(const struct soc_plan *p) {
    struct stat ns;
    return stat("/proc/self/ns/net",&ns) || ns.st_ino!=p->namespace_inode ||
        if_nametoindex("lo")!=p->ifindex?-EPERM:0;
}
int soc_environment(const struct soc_plan *p) {
    char path[64],body[4096];if(soc_scope_environment(p))return -EPERM;
    snprintf(path,sizeof(path),"/proc/%u/stat",p->controller_pid);
    int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return -ESRCH;
    ssize_t n=read(fd,body,sizeof(body)-1);close(fd);if(n<=0)return -ESRCH;body[n]=0;
    char *end=strrchr(body,')');if(!end)return -ESRCH;
    char *save=NULL,*token=strtok_r(end+2," ",&save);uint64_t ticks=0;
    for(int i=0;token;i++,token=strtok_r(NULL," ",&save)) if(i==19)ticks=strtoull(token,NULL,10);
    snprintf(path,sizeof(path),"/proc/%u",p->controller_pid);
    struct stat process;if(stat(path,&process) || process.st_uid!=p->uid || ticks!=p->controller_ticks)
        return -ESRCH;
    return 0;
}
int soc_peer(int fd,const struct soc_plan *p) {
    struct ucred peer;socklen_t n=sizeof(peer);int type=0;socklen_t tn=sizeof(type);
    if (getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&n) || n!=sizeof(peer) ||
        getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&tn) || type!=SOCK_SEQPACKET ||
        peer.pid!=(pid_t)p->controller_pid || peer.uid!=p->uid || peer.gid!=p->gid) return -EPERM;
    return soc_environment(p);
}
int soc_reduce(uid_t uid,gid_t gid) {
    if(!soc_native_gate() || !uid || !gid || geteuid()!=0)return -EPERM;
    uint64_t mask=(1ULL<<CAP_BPF)|(1ULL<<CAP_NET_ADMIN);
    for(int cap=0;cap<=CAP_LAST_CAP;cap++)if(cap!=CAP_BPF && cap!=CAP_NET_ADMIN)
        if(prctl(PR_CAPBSET_DROP,cap,0,0,0))return -EPERM;
    if(prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0) || prctl(PR_SET_DUMPABLE,0) ||
       setgroups(0,NULL) || prctl(PR_SET_KEEPCAPS,1) || setresgid(gid,gid,gid) ||
        setresuid(uid,uid,uid))return -EPERM;
    struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct d[2]={{0}};
    for(int i=0;i<2;i++)d[i].effective=d[i].permitted=d[i].inheritable=(uint32_t)(mask>>(32*i));
    if(syscall(SYS_capset,&h,d) || prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_RAISE,CAP_BPF,0,0) ||
        prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_RAISE,CAP_NET_ADMIN,0,0) ||
        prctl(PR_SET_KEEPCAPS,0) || prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return -EPERM;
    return 0;
}

int soc_receive_request(int fd,const struct soc_plan *p,uint32_t sequence,struct soc_request *q) {
    if(soc_peer(fd,p))return -EPERM;
    union {struct cmsghdr align;char body[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(4*sizeof(int))];} control={0};
    struct iovec iov={q,sizeof(*q)};struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,
        .msg_control=control.body,.msg_controllen=sizeof(control.body)};
    ssize_t n=recvmsg(fd,&msg,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);int valid=0,bad=0;
    for(struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c)) {
        if(c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_RIGHTS) {
            /* Received descriptors are never commands/authority. Close all installed FDs. */
            size_t bytes=c->cmsg_len>=CMSG_LEN(0)?c->cmsg_len-CMSG_LEN(0):0;
            int *fds=(int *)CMSG_DATA(c);for(size_t i=0;i<bytes/sizeof(int);i++)close(fds[i]);bad=1;
        } else if(c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_CREDENTIALS &&
                  c->cmsg_len==CMSG_LEN(sizeof(struct ucred))) {
            struct ucred peer;memcpy(&peer,CMSG_DATA(c),sizeof(peer));
            if(valid || peer.uid!=p->uid || peer.gid!=p->gid || peer.pid!=(pid_t)p->controller_pid)bad=1;
            valid=1;
        } else bad=1;
    }
    if(n!=sizeof(*q) || !valid || bad)return -EPROTO;
    return soc_request_validate(p,q,sequence,msg.msg_flags);
}
