#define _GNU_SOURCE
#include "data.h"
#include "handoff.h"
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
static int row(struct soc_state *s,unsigned kind,const struct soc_event *event) {
    if(s->data_fd<0 || !s->data_source || s->data_sequence>=65568)return -EPERM;
    struct soc_data_row r={.magic=SOC_DATA_MAGIC,.version=1,.kind=kind,
        .source=s->data_source,.sequence=s->data_sequence,.loss=s->data_loss};
    if(kind!=SOC_DATA_READY)r.sequence=++s->data_sequence;
    memcpy(r.application,s->plan.application,16);memcpy(r.approval,s->data_approval,32);
    memcpy(r.program,s->plan.program_sha,32);if(event)r.event=*event;
    if(send(s->data_fd,&r,sizeof(r),MSG_DONTWAIT|MSG_NOSIGNAL)!=(ssize_t)sizeof(r)) {
        s->data_loss++;return -ENOBUFS;
    }return 0;
}
int soc_data_open(struct soc_state *s,unsigned source,const uint8_t approval[32]) {
    memcpy(s->data_approval,approval,32);
    if(source!=1 && source!=2)return -EPERM;
    s->data_fd=soc_handoff_connect_data(s->plan.uid,s->plan.gid,s->plan.application);
    if(s->data_fd<0 || soc_peer(s->data_fd,&s->plan))return -EPERM;
    int bytes=32768;if(setsockopt(s->data_fd,SOL_SOCKET,SO_SNDBUF,&bytes,sizeof(bytes)))return -EPERM;
    s->data_source=source;return row(s,SOC_DATA_READY,NULL);
}
int soc_data_emit(struct soc_state *s,const void *body,size_t size) {
    const struct soc_event *e=body;
    if(size!=sizeof(*e) || e->generation!=s->generation ||
       e->ifindex!=s->plan.ifindex || e->hook!=s->plan.hook)return -EPROTO;
    return row(s,SOC_DATA_PACKET,e);
}
int soc_data_end(struct soc_state *s,unsigned reason) {
    if(!s->generation || s->data_ended_generation==s->generation)return 0;
    s->data_ended_generation=s->generation;
    /* End of observation does not establish flow completeness. */
    struct soc_event e={.generation=s->generation,.frame_length=reason};
    return row(s,SOC_DATA_RUN_END,&e);
}
int soc_data_close(struct soc_state *s) {
    if(s->data_fd<0)return 0;
    int rc=row(s,SOC_DATA_CLOSED,NULL);if(close(s->data_fd))rc=-EIO;s->data_fd=-1;return rc;
}
