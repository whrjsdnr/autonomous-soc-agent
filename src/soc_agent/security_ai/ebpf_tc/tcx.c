/* TCX link lifetime core and separately closed real libbpf provider. */
#include "tcx.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
static int fail(struct soc_tcx *l) {
    if(l->phase!=SOC_LINK_ORPHANED)l->phase=SOC_LINK_UNVERIFIED;l->ops->record(l,"TCX_CLEANUP_UNVERIFIED");return -EUCLEAN;
}
static int same(const struct soc_tcx_identity *a,const struct soc_tcx_identity *b) {
    return !memcmp(a,b,sizeof(*a));
}
int soc_tcx_attach(struct soc_tcx *l) {
    uint8_t zero[32]={0};
    if(l->owner.link_id || !memcmp(l->owner.application,zero,16) ||
       !memcmp(l->owner.program_sha,zero,32) || l->attempted || l->fd!=-1 || l->phase!=SOC_LINK_NOT_ATTACHED ||
       !l->owner.generation || !l->owner.namespace_inode || !l->owner.broker_pid ||
       !l->owner.broker_ticks || l->owner.pinned || !l->owner.program_id ||
       !l->owner.ifindex || (l->owner.attach_type!=BPF_TCX_INGRESS &&
       l->owner.attach_type!=BPF_TCX_EGRESS) || l->ops->validate(l))return -EPERM;
    l->attempted=1;l->phase=SOC_LINK_ATTACH_PENDING;
    if(l->ops->record(l,"TCX_ATTACH_REQUESTED"))return fail(l);
    int rc=l->ops->create(l);
    if(rc || l->fd<0)return fail(l); /* Provider retains a partial owned FD on failure. */
    struct soc_tcx_identity found={0},expected=l->owner;
    if(l->ops->record(l,"TCX_LINK_CREATED"))return fail(l);
    if(l->ops->info(l,&found) || !found.link_id)return fail(l);
    expected.link_id=found.link_id;
    if(!same(&expected,&found))return fail(l);
    l->owner=found;
    if(l->ops->record(l,"TCX_LINK_VERIFIED"))return fail(l);
    l->phase=SOC_LINK_ACTIVE;return 0;
}
int soc_tcx_detach(struct soc_tcx *l) {
    if(l->phase==SOC_LINK_DETACHED)return 0;
    if(l->fd<0 || !l->owner.link_id || l->owner.pinned || l->ops->validate(l))return fail(l);
    struct soc_tcx_identity found={0};
    if(l->ops->info(l,&found) || !same(&l->owner,&found))return fail(l);
    l->phase=SOC_LINK_DETACH_PENDING;
    if(l->ops->record(l,"TCX_DETACH_REQUESTED") || l->ops->detach(l))return fail(l);
    /* Detach acts on held link object, never on interface/priority or a global ID. */
    struct soc_tcx_identity after={0},expected=l->owner;expected.ifindex=0;
    if(l->ops->info(l,&after) || !same(&expected,&after))return fail(l);
    int rc=l->ops->close(l);l->fd=-1; /* Never retry a possibly consumed Linux FD. */
    if(rc)return fail(l);
    if(l->ops->record(l,"TCX_LINK_RELEASED"))return fail(l);
    if(l->ops->record(l,"TCX_CLEANUP_VERIFIED"))return fail(l);
    l->phase=SOC_LINK_DETACHED;return 0;
}
static int validate(struct soc_tcx *l) {
    if(!soc_tcx_native_admitted() || !l->session || !l->owner.broker_pid ||
       l->owner.broker_pid!=(uint32_t)getpid())return -EPERM;
    char body[4096];FILE *stat=fopen("/proc/self/stat","r");if(!stat)return -EPERM;
    char *line=fgets(body,sizeof(body),stat);fclose(stat);if(!line)return -EPERM;
    char *end=strrchr(body,')'),*save=NULL;uint64_t ticks=0;if(!end)return -EPERM;
    char *token=strtok_r(end+2," ",&save);
    for(int n=0;token;n++,token=strtok_r(NULL," ",&save))if(n==19)ticks=strtoull(token,NULL,10);
    if(ticks!=l->owner.broker_ticks)return -EPERM;
    struct soc_state *s=l->session;
    if((l->phase==SOC_LINK_NOT_ATTACHED || l->phase==SOC_LINK_ATTACH_PENDING) &&
       soc_peer(s->ipc_fd,&s->plan))return -EPERM;
    if(soc_sealed(s->object_fd,s->plan.program_sha))return -EPERM;
    if(l->owner.generation!=s->generation || l->owner.ifindex!=s->plan.ifindex ||
       l->owner.program_id!=s->owner.program_id || memcmp(l->owner.program_tag,s->owner.tag,8) ||
       soc_plan_validate(&s->plan) || soc_scope_environment(&s->plan) ||
       memcmp(l->owner.application,s->plan.application,16) ||
       memcmp(l->owner.program_sha,s->plan.program_sha,32) ||
       l->owner.namespace_inode!=s->plan.namespace_inode ||
       l->owner.attach_type!=(s->plan.hook==1?BPF_TCX_INGRESS:BPF_TCX_EGRESS))return -EPERM;
    return 0;
}
static int create(struct soc_tcx *l) {
    if(validate(l))return -EPERM;
    struct bpf_prog_info p={0};uint32_t size=sizeof(p);
    if(bpf_prog_get_info_by_fd(l->program_fd,&p,&size) || p.type!=BPF_PROG_TYPE_SCHED_CLS ||
       p.id!=l->owner.program_id || memcmp(p.tag,l->owner.program_tag,8))return -EPERM;
    if(soc_snapshot_tcx(l->session,&l->session->before))return -EPERM;
    l->session->tcx_snapshot_valid=1;
    if(l->session->before.count)return -EPERM;
    struct bpf_prog_query_opts query={.sz=sizeof(query)};
    if(bpf_prog_query_opts(l->owner.ifindex,l->owner.attach_type,&query) || query.prog_cnt || !query.revision)return -EPERM;
    /* Kernel revision compare makes empty-hook admission atomic against another
     * manager's insert. No replacement/order/pin flags and no Legacy mutation. */
    struct bpf_link_create_opts opts={.sz=sizeof(opts)};
    opts.tcx.expected_revision=query.revision;
    l->fd=bpf_link_create(l->program_fd,l->owner.ifindex,l->owner.attach_type,&opts);
    if(l->fd<0)return -errno;
    return fcntl(l->fd,F_SETFD,FD_CLOEXEC)?-errno:0;
}
static int info(struct soc_tcx *l,struct soc_tcx_identity *out) {
    if(validate(l) || l->fd<0)return -EPERM;
    struct bpf_link_info i={0};uint32_t size=sizeof(i);
    if(bpf_link_get_info_by_fd(l->fd,&i,&size) || i.type!=BPF_LINK_TYPE_TCX)return -EPERM;
    *out=l->owner;out->link_id=i.id;out->program_id=i.prog_id;
    out->ifindex=i.tcx.ifindex;out->attach_type=i.tcx.attach_type;return 0;
}
static int detach(struct soc_tcx *l) {
    return validate(l)?-EPERM:bpf_link_detach(l->fd);
}
static int close_link(struct soc_tcx *l) {
    if(validate(l))return -EPERM;
    return close(l->fd)?-errno:0;
}
static int record(struct soc_tcx *l,const char *kind) {
    if(validate(l))return -EPERM;
    return soc_tcx_journal(l,kind);
}
const struct soc_tcx_ops soc_tcx_real_ops={validate,create,info,detach,close_link,record};
