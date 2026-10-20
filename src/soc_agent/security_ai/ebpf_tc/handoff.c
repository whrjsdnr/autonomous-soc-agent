/* Linux abstract seqpacket rendezvous. No inherited descriptor/sudo -C dependency. */
#define _GNU_SOURCE
#include "handoff.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int soc_os_auth_admitted(void) {
    /* Effective OS policy / fresh password / capability qualification is pending.
     * No caller, manifest, environment or fixture switch can admit Native auth. */
    return 0;
}
static int connect_channel(uid_t uid,gid_t gid,const uint8_t session[16],int data) {
    if(!uid || !gid || !session)return -EPERM;
    char hex[33];for(int i=0;i<16;i++)snprintf(hex+2*i,3,"%02x",session[i]);
    struct sockaddr_un a={.sun_family=AF_UNIX};
    int length=snprintf(a.sun_path+1,sizeof(a.sun_path)-1,data?"soc-ebpf-data.%u.%s":"soc-ebpf.%u.%s",uid,hex);
    if(length<1 || length>=(int)sizeof(a.sun_path)-1)return -EINVAL;
    int fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);if(fd<0)return -errno;
    int enabled=1,size=32768;struct timeval timeout={5,0};struct ucred peer;socklen_t n=sizeof(peer);
    if(setsockopt(fd,SOL_SOCKET,SO_PASSCRED,&enabled,sizeof(enabled)) ||
       setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) ||
       setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)) ||
       setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size)) ||
       connect(fd,(struct sockaddr *)&a,offsetof(struct sockaddr_un,sun_path)+1+length) ||
       getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&n) || n!=sizeof(peer) ||
       peer.uid!=uid || peer.gid!=gid) {close(fd);return -EPERM;}
    return fd;
}
int soc_handoff_connect(uid_t uid,gid_t gid,const uint8_t session[16]) {
    return connect_channel(uid,gid,session,0);
}
int soc_handoff_connect_data(uid_t uid,gid_t gid,const uint8_t session[16]) {
    return connect_channel(uid,gid,session,1);
}
int soc_handoff_receive(int fd,uid_t uid,gid_t gid,const uint8_t session[16],
                        const uint8_t approval[32],const uint8_t manifest[32],
                        struct soc_release_envelope *e,int *plan,int *audit) {
    *plan=*audit=-1;
    union {struct cmsghdr align;char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(8*sizeof(int))];} control={0};
    struct iovec io={e,sizeof(*e)};struct msghdr msg={.msg_iov=&io,.msg_iovlen=1,
        .msg_control=control.bytes,.msg_controllen=sizeof(control.bytes)};
    ssize_t size=recvmsg(fd,&msg,MSG_CMSG_CLOEXEC);int count=0,seen=0,bad=0,files[8];
    struct ucred credential={0},peer;socklen_t length=sizeof(peer);
    for(struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c)) {
        if(c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_RIGHTS && c->cmsg_len>=CMSG_LEN(0)) {
            size_t bytes=c->cmsg_len-CMSG_LEN(0);int *values=(int *)CMSG_DATA(c);
            if(bytes%sizeof(int))bad=1;
            for(size_t i=0;i<bytes/sizeof(int);i++) {
                if(count<8)files[count++]=values[i];else {close(values[i]);bad=1;}
            }
        } else if(c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_CREDENTIALS &&
                  c->cmsg_len==CMSG_LEN(sizeof(credential)) && !seen++)memcpy(&credential,CMSG_DATA(c),sizeof(credential));
        else bad=1;
    }
    if(size!=sizeof(*e) || msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC) || bad || seen!=1 || count!=2 ||
       getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&length) || length!=sizeof(peer) ||
       credential.pid!=peer.pid || credential.uid!=uid || credential.gid!=gid ||
       peer.uid!=uid || peer.gid!=gid || soc_envelope_validate(e) ||
       e->plan.uid!=uid || e->plan.gid!=gid || memcmp(session,e->plan.application,16) ||
       memcmp(approval,e->approval,32) || memcmp(manifest,e->manifest_sha,32) ||
       soc_peer(fd,&e->plan))goto denied;
    struct stat p,a;struct soc_release_envelope held;uint8_t hash[32];
    int flags=fcntl(files[1],F_GETFL);
    if(fstat(files[0],&p) || p.st_uid!=uid || p.st_size!=sizeof(*e) ||
       soc_fd_sha(files[0],hash) || soc_sealed(files[0],hash) ||
       pread(files[0],&held,sizeof(held),0)!=sizeof(held) || memcmp(&held,e,sizeof(held)) ||
       fstat(files[1],&a) || !S_ISREG(a.st_mode) || a.st_uid!=uid || a.st_nlink!=1 ||
       a.st_size || (a.st_mode&07777)!=0600 || flags<0 || !(flags&O_APPEND))goto denied;
    *plan=files[0];*audit=files[1];return 0;
denied:
    for(int i=0;i<count;i++)close(files[i]);return -EPERM;
}
int soc_handoff_reply(int fd,const struct soc_release_envelope *e,unsigned phase,unsigned source) {
    char body[4096];FILE *file=fopen("/proc/self/stat","re");if(!file)return -EPERM;
    char *line=fgets(body,sizeof(body),file);fclose(file);if(!line)return -EPERM;
    char *end=strrchr(body,')'),*save=NULL;if(!end)return -EPERM;
    uint64_t ticks=0;char *token=strtok_r(end+2," ",&save);
    for(int i=0;token;i++,token=strtok_r(NULL," ",&save))if(i==19)ticks=strtoull(token,NULL,10);
    struct soc_handoff_reply r={.magic=SOC_HANDOFF_MAGIC,.phase=phase,.source=source,
        .pid=getpid(),.uid=getuid(),.gid=getgid(),.ticks=ticks};
    if(!ticks || soc_sha(e,sizeof(*e),r.envelope_sha))return -EPERM;
    memcpy(r.broker_sha,e->plan.broker_sha,32);
    return send(fd,&r,sizeof(r),MSG_NOSIGNAL)==sizeof(r)?0:-EIO;
}
