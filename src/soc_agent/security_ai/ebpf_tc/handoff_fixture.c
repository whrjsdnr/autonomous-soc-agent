/* Ordinary UID transport peer. No authentication, capabilities, load or attach. */
#define _GNU_SOURCE
#include "handoff.h"
#include <sys/socket.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int record(struct soc_state *s,const char *kind) {
    struct {uint8_t plan[32];char kind[32];struct soc_owner owner;
        uint32_t sequence,ordinal;uint8_t previous[32],digest[32];} row={0};
    if(strlen(kind)>=32 || s->audit_records>=1024)return -1;
    memcpy(row.plan,s->plan.approval,32);strcpy(row.kind,kind);
    row.sequence=s->sequence;row.ordinal=++s->audit_records;
    memcpy(row.previous,s->audit_previous,32);
    if(soc_sha(&row,sizeof(row)-32,row.digest) ||
       write(s->audit_fd,&row,sizeof(row))!=sizeof(row) || fsync(s->audit_fd))return -1;
    memcpy(s->audit_previous,row.digest,32);
    if(send(s->ipc_fd,&row,sizeof(row),MSG_NOSIGNAL)!=sizeof(row) && !s->stopping)return -1;
    return 0;
}
int main(int argc,char **argv) {
    if(!getuid() || getuid()!=geteuid() || argc!=4 || strlen(argv[1])!=32 ||
       strlen(argv[2])!=64 || strlen(argv[3])!=64)return 2;
    uint8_t app[16],approval[32],manifest[32];uint8_t *outputs[]={app,approval,manifest};
    for(int j=0;j<3;j++)for(int i=0;i<(j?32:16);i++) {
        if(!strchr("0123456789abcdef",argv[j+1][2*i]) ||
           !strchr("0123456789abcdef",argv[j+1][2*i+1]))return 2;
        char pair[]={argv[j+1][2*i],argv[j+1][2*i+1],0};outputs[j][i]=strtoul(pair,NULL,16);
    }
    int fd=soc_handoff_connect(getuid(),getgid(),app),plan=-1,audit=-1;
    struct soc_release_envelope e;
    if(fd<0 || soc_handoff_receive(fd,getuid(),getgid(),app,approval,manifest,&e,&plan,&audit) ||
       flock(audit,LOCK_EX|LOCK_NB) || soc_handoff_reply(fd,&e,1,2))return 2;
    struct soc_state s={.plan=e.plan,.audit_fd=audit,.ipc_fd=fd};
    memcpy(s.release_sha,e.manifest_sha,32);memcpy(s.release_version,e.release_version,16);
    if(soc_release_record(&s) || record(&s,"OS_AUTH_HANDOFF_VERIFIED") ||
       record(&s,"BROKER_SESSION_BOUND") || record(&s,"BROKER_READY") ||
       soc_handoff_reply(fd,&e,2,2))return 2;
    uint64_t born=soc_now(),last=born,slots[32]={0};uint32_t cursor=0;int rc=0;
    while(!s.stopping && s.sequence<2048) {
        uint64_t now=soc_now();struct pollfd p={fd,POLLIN,0};
        if(soc_peer(fd,&s.plan) || now-born>=3600000000000ULL || now-last>15000000000ULL) {
            rc=2;record(&s,"BROKER_SESSION_EXPIRED");break;
        }
        int ready=poll(&p,1,100);if(ready<0) {rc=2;break;}if(!ready)continue;
        struct soc_request q;
        if(soc_receive_request(fd,&s.plan,s.sequence,&q) || soc_rate_allow(slots,&cursor,now)) {rc=2;break;}
        s.sequence=q.sequence;last=now;
        /* No simulated Kernel ACTIVE and no fabricated Link. Existing TCX fixture
         * separately covers attach/detach; this peer tests the transport boundary. */
        int error=q.operation==2 || q.operation==4?-EPERM:0;
        struct {uint32_t sequence,state;int32_t error;uint32_t reserved;struct soc_owner owner;} reply={q.sequence,3,error,0,{0}};
        if(send(fd,&reply,sizeof(reply),MSG_NOSIGNAL)!=sizeof(reply)) {rc=2;break;}
        if(error) {rc=2;break;}if(q.operation==6)s.stopping=1;
    }
    s.stopping=1;
    if(record(&s,"CLEANUP_VERIFIED") || record(&s,"BROKER_STOPPED"))rc=2;
    close(plan);close(audit);close(fd);return rc;
}
