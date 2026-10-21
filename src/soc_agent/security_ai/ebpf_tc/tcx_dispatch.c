/* Broker-local TCX dispatcher. Same six commands, no public Link FD/ID input. */
#define _GNU_SOURCE
#include "tcx.h"
#include "diagnostics.h"
#include <linux/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
static uint64_t own_ticks(void) {
    char body[4096];FILE *f=fopen("/proc/self/stat","r");if(!f)return 0;
    char *line=fgets(body,sizeof(body),f);fclose(f);if(!line)return 0;
    char *end=strrchr(body,')'),*save=NULL;if(!end)return 0;
    char *token=strtok_r(end+2," ",&save);
    for(int n=0;token;n++,token=strtok_r(NULL," ",&save))
        if(n==19)return strtoull(token,NULL,10);
    return 0;
}
static int cleanup_failed(struct soc_tcx *l,int api,int rc) {
    struct soc_state *s=l->session;
    struct soc_load_diagnostic d={.stage=SOC_LOAD_CLEANUP,.api=api,.result=rc,
        .errno_source=SOC_CONTRACT_ERROR,.link_fd=l->fd>=0};
    if(l->fd>=0)d.resources|=SOC_LINK_FD_SEEN;
    soc_diagnostic_record(s,&d,NULL,0);s->failed=1;s->cleanup_verified=0;return -EUCLEAN;
}
int soc_tcx_cleanup(struct soc_tcx *l) {
    struct soc_state *s=l->session;s->stopping=1;int first=0,api=0,rc;
    if(s->attached || l->fd>=0) {
        rc=s->ops->enable(s,0);
        if(rc)return cleanup_failed(l,SOC_DIAG_ENABLE,rc);
        rc=soc_tcx_detach(l);
        if(rc)return cleanup_failed(l,SOC_DIAG_LINK_DETACH,rc);
        s->attached=0;
    }
    if(s->context && s->ops==&soc_real_ops && s->tcx_snapshot_valid) {
        struct soc_snapshot after;rc=soc_snapshot_tcx(s,&after);
        if(rc || memcmp(&after,&s->before,sizeof(after))) {
            first=rc?rc:-EUCLEAN;api=SOC_DIAG_SNAPSHOT;
        }
    }
    if(s->context && s->ops==&soc_real_ops && (s->diagnostic_resources&SOC_RING_READY)) {
        rc=soc_final_drain_counters(s);
        if(rc && !first) {first=rc;api=SOC_DIAG_DRAIN;}
    }
    /* Never skip freeing the owned, unattached object merely because evidence
     * collection failed. No guessed Link detach, no foreign-resource cleanup. */
    if(s->loaded || s->context) {
        rc=s->ops->release(s);
        if(rc && !first) {first=rc;api=SOC_DIAG_OBJECT_RELEASE;}
        if(!rc) {s->loaded=0;s->diagnostic_resources|=SOC_OBJECT_RELEASED;}
    }
    if(first)return cleanup_failed(l,api,first);
    if(s->failed)return cleanup_failed(l,SOC_DIAG_CAPTURE_FAILED,-EUCLEAN);
    s->cleanup_verified=1;return 0;
}
int soc_tcx_dispatch(struct soc_tcx *l,const struct soc_request *q) {
    struct soc_state *s=l->session;
    if(l->ops==&soc_tcx_real_ops && !soc_tcx_native_admitted())return -EPERM;
    /* Authentication, IPC identity/sequence and rate checks remain at broker ingress. */
    if(!s || s->plan.version!=SOC_TCX_VERSION || soc_plan_validate(&s->plan) ||
       memcmp(q->approval,s->plan.approval,32) || !q->sequence || q->sequence>2048 ||
       q->operation<1 || q->operation>6 ||
       soc_request_validate(&s->plan,q,q->sequence-1,0) || s->failed)return -EPERM;
    if(q->operation==1)return s->loaded || s->attached?-EPERM:s->ops->validate(s);
    if(q->operation==3)return 0;
    if(q->operation==4) {
        if(memcmp(&s->owner,&q->owner,sizeof(q->owner)))return -EPERM;
        return soc_tcx_cleanup(l);
    }
    if(q->operation==5 || q->operation==6)return soc_tcx_cleanup(l);
    if(!q->generation || !q->handle || s->loaded || s->attached ||
       s->attempts>=16 || l->attempted)return -EPERM;
    s->stopping=0;s->packet_budget_reached=0;s->tcx_snapshot_valid=0;
    s->diagnostic_failed=s->diagnostic_cleanup=0;s->diagnostic_resources=0;
    s->generation=q->generation;s->handle=q->handle;s->started_ns=soc_now();
    s->cleanup_verified=0;s->attempts++;
    int prepared=s->ops->validate(s),prepare_api=SOC_DIAG_VALIDATE;
    if(!prepared) {prepared=s->ops->record(s,"LOAD_REQUESTED");prepare_api=SOC_DIAG_LOAD_RECORD;}
    if(prepared) {
        struct soc_load_diagnostic d={.stage=SOC_LOAD_PREPARE,.api=prepare_api,
            .result=prepared,.errno_source=SOC_CONTRACT_ERROR};
        soc_diagnostic_record(s,&d,NULL,0);s->failed=1;return prepared;
    }
    prepared=s->ops->load(s);
    if(prepared) {s->failed=1;return prepared;}
    s->loaded=1;
    int verified=s->owner.program_id?s->ops->record(s,"LOAD_VERIFIED"):-EINVAL;
    if(verified) {
        struct soc_load_diagnostic d={.stage=SOC_MAP_INIT,
            .api=s->owner.program_id?SOC_DIAG_VERIFIED_RECORD:SOC_DIAG_PROGRAM_INFO,
            .result=verified,.errno_source=SOC_CONTRACT_ERROR};
        soc_diagnostic_record(s,&d,NULL,0);s->failed=1;return verified;
    }
    l->program_fd=soc_program_fd(s);
    l->owner=(struct soc_tcx_identity){.generation=s->generation,
        .namespace_inode=s->plan.namespace_inode,.broker_ticks=own_ticks(),
        .program_id=s->owner.program_id,.ifindex=s->plan.ifindex,
        .attach_type=s->plan.hook==1?BPF_TCX_INGRESS:BPF_TCX_EGRESS,
        .broker_pid=getpid()};
    memcpy(l->owner.program_tag,s->owner.tag,8);
    memcpy(l->owner.application,s->plan.application,16);
    memcpy(l->owner.program_sha,s->plan.program_sha,32);
    int rc=soc_tcx_attach(l);s->attached=l->fd>=0;
    if(rc) {
        struct soc_load_diagnostic d={.stage=SOC_TCX_ATTACH,.api=SOC_DIAG_LINK_ATTACH,
            .result=rc,.errno_source=SOC_CONTRACT_ERROR,.link_fd=l->fd>=0};
        if(l->fd>=0)d.resources|=SOC_LINK_FD_SEEN;
        soc_diagnostic_record(s,&d,NULL,0);s->failed=1;return -EUCLEAN;
    }
    if(s->ops->enable(s,1)) {s->failed=1;return -EUCLEAN;}
    return 0;
}
/* Versioned TCX rows coexist with unchanged 192-byte Legacy rows. No FD recorded. */
int soc_tcx_journal(struct soc_tcx *l,const char *kind) {
    struct soc_state *s=l->session;
    struct {uint8_t plan[32];char kind[32];struct soc_tcx_identity owner;
        uint32_t sequence,ordinal;uint8_t previous[32],digest[32];} row={0};
    _Static_assert(sizeof(row)==240,"TCX journal ABI");
    if(!s || strncmp(kind,"TCX_",4) || strlen(kind)>=32 || s->audit_records>=1024)return -EINVAL;
    memcpy(row.plan,s->plan.approval,32);strcpy(row.kind,kind);row.owner=l->owner;
    row.sequence=s->sequence;row.ordinal=s->audit_records+1;
    memcpy(row.previous,s->audit_previous,32);
    if(soc_sha(&row,sizeof(row)-32,row.digest) ||
       write(s->audit_fd,&row,sizeof(row))!=sizeof(row) || fsync(s->audit_fd))return -EIO;
    memcpy(s->audit_previous,row.digest,32);s->audit_records++;
    ssize_t sent=send(s->ipc_fd,&row,sizeof(row),MSG_DONTWAIT|MSG_NOSIGNAL);
    return sent==sizeof(row) || s->stopping?0:-ENOBUFS;
}
