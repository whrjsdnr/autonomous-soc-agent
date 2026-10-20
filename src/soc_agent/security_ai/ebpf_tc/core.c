#include "native.h"
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
/* No environment, CLI flag, sudo cache or fixture can open this gate. B-2B needs
 * a reviewed code/release change, new hashes and explicit installation approval. */
static int qualification_admitted;
int soc_native_gate(void) {return qualification_admitted;}
/* Admission is process-local and has no environment/CLI toggle. The root entry
 * calls this only after OS policy and purpose-bound human scope verification.
 * An exec'd Broker must present a root-created, sealed authority FD, never an
 * approval JSON or the Controller's own user-owned memfd. */
int soc_qualification_admit(int fd,const struct soc_release_envelope *e,int stage) {
    if(qualification_admitted || !e || (stage!=1 && stage!=2) ||
       soc_envelope_validate(e) || e->plan.hook!=1 || soc_environment(&e->plan) ||
       soc_release_check(&e->plan,e->manifest_sha,e->release_version,stage))return -EPERM;
    if(stage==1) {
        if(getuid() || geteuid() || getgid() || getegid())return -EPERM;
    } else {
        struct stat st;uint8_t hash[32];struct soc_release_envelope held;
        if(getuid()!=e->plan.uid || getgid()!=e->plan.gid || fstat(fd,&st) ||
           st.st_uid || st.st_size!=sizeof(held) || soc_fd_sha(fd,hash) || soc_sealed(fd,hash) ||
           pread(fd,&held,sizeof(held),0)!=sizeof(held) || memcmp(e,&held,sizeof(held)) ||
           soc_capabilities())return -EPERM;
    }
    qualification_admitted=1;return 0;
}
int soc_auth_contract(const struct soc_auth_facts *f) {
    return !f->uid || !f->gid || f->uid!=f->real_uid || f->effective_uid ||
        f->tty_owner!=f->uid || f->tty_present!=1 || f->foreground!=1 ||
        f->policy_exact!=1 || f->challenge_count!=1 || f->authentication_status ||
        f->cached_only?-EPERM:0;
}
int soc_sha(const void *body,size_t size,uint8_t out[32]) {
    unsigned int n=0;
    return EVP_Digest(body,size,out,&n,EVP_sha256(),NULL)==1 && n==32?0:-EINVAL;
}
int soc_plan_validate(const struct soc_plan *p) {
    if ((p->version!=SOC_VERSION && p->version!=SOC_TCX_VERSION) || !p->uid || !p->gid || !p->controller_pid ||
        !p->controller_ticks || !p->namespace_inode || !p->ifindex ||
        (p->hook!=1 && p->hook!=2) || p->duration!=300 || p->events!=4096 ||
        p->queue!=32 || p->rss_mib!=256 || p->cpu_seconds!=20 || p->reserved) return -EINVAL;
    uint8_t zero[32]={0},md[32];struct soc_plan copy=*p;memset(copy.approval,0,32);
    if (!memcmp(p->application,zero,16) || !memcmp(p->program_sha,zero,32) ||
        !memcmp(p->loader_sha,zero,32) || !memcmp(p->bootstrap_sha,zero,32) ||
        !memcmp(p->broker_sha,zero,32) || !memcmp(p->bundle_sha,zero,32) ||
        soc_sha(&copy,sizeof(copy),md) || memcmp(md,p->approval,32)) return -EINVAL;
    return 0;
}
static int failed(struct soc_state *s) {s->failed=1;s->cleanup_verified=0;return -EUCLEAN;}
static int same_foreign(struct soc_state *s,const struct soc_snapshot *after,int include_own) {
    struct soc_snapshot expected=s->before;
    if (include_own) {
        if (expected.count>=SOC_LIMIT_FILTERS) return 0;
        struct soc_filter *f=&expected.filters[expected.count++];memset(f,0,sizeof(*f));
        f->parent=s->plan.hook==1?0xfffffff2:0xfffffff3;f->handle=s->handle;
        f->priority=SOC_PRIORITY;f->program_id=s->owner.program_id;strcpy(f->kind,"bpf");
    }
    if (expected.clsact!=after->clsact || expected.count!=after->count) return 0;
    for (uint32_t i=0;i<expected.count;i++) {
        int seen=0;for (uint32_t j=0;j<after->count;j++)
            if (!memcmp(&expected.filters[i],&after->filters[j],sizeof(struct soc_filter))) seen++;
        if (seen!=1) return 0;
    }
    return 1;
}
int soc_prepare(struct soc_state *s) {
    if (s->failed || s->loaded || s->attached || soc_plan_validate(&s->plan) ||
        s->ops->validate(s) || !s->generation || !s->handle || s->attempts>=16) return -EPERM;
    if (s->ops->snapshot(s,&s->before) || !s->before.clsact ||
        s->before.count>=SOC_LIMIT_FILTERS) return failed(s);
    uint32_t parent=s->plan.hook==1?0xfffffff2:0xfffffff3;
    for (uint32_t i=0;i<s->before.count;i++) {
        struct soc_filter *f=&s->before.filters[i];
        if (f->parent==parent && f->priority==SOC_PRIORITY && f->handle==s->handle)
            return failed(s);
    }
    s->cleanup_verified=0;
    if (s->ops->record(s,"LOAD_REQUESTED") || s->ops->load(s)) return failed(s);
    s->loaded=1;s->attempts++;
    if (!s->owner.program_id || s->ops->record(s,"LOAD_VERIFIED")) return failed(s);
    return 0;
}
int soc_attach(struct soc_state *s) {
    struct soc_snapshot current;
    if (s->failed || !s->loaded || s->attached || s->ops->validate(s) ||
        s->ops->snapshot(s,&current) || !same_foreign(s,&current,0)) return failed(s);
    if (s->ops->record(s,"ATTACH_REQUESTED")) return failed(s);
    int rc=s->ops->attach(s);
    /* A failed mutation can be ambiguous. Retain object/lease and never retry. */
    if (rc) {s->attached=1;return failed(s);}
    s->attached=1;
    uint32_t id=0;uint8_t tag[8];
    if (s->ops->query(s,&id,tag) || id!=s->owner.program_id ||
        memcmp(tag,s->owner.tag,8) || s->ops->snapshot(s,&current) ||
        !same_foreign(s,&current,1) || s->ops->record(s,"ATTACH_VERIFIED") ||
        s->ops->enable(s,1)) return failed(s);
    return 0;
}
int soc_detach(struct soc_state *s) {
    uint32_t id=0;uint8_t tag[8];struct soc_snapshot current;
    s->stopping=1;
    if (!s->attached) return 0;
    if (s->ops->enable(s,0)) return failed(s);
    if (memcmp(s->owner.application,s->plan.application,16) ||
        s->owner.ifindex!=s->plan.ifindex || s->owner.hook!=s->plan.hook ||
        s->owner.namespace_inode!=s->plan.namespace_inode ||
        s->owner.generation!=s->generation || s->owner.handle!=s->handle ||
        s->ops->validate(s) || s->ops->query(s,&id,tag) ||
        id!=s->owner.program_id || memcmp(tag,s->owner.tag,8) ||
        s->ops->snapshot(s,&current) || !same_foreign(s,&current,1)) return failed(s);
    if (s->ops->record(s,"DETACH_REQUESTED") || s->ops->detach(s)) return failed(s);
    /* Missing completion evidence remains UNVERIFIED even if deletion happened. */
    if (s->ops->snapshot(s,&current) || !same_foreign(s,&current,0) ||
        s->ops->record(s,"DETACH_VERIFIED")) return failed(s);
    s->attached=0;return 0;
}
int soc_cleanup(struct soc_state *s) {
    if (soc_detach(s)) {s->ops->record(s,"CLEANUP_UNVERIFIED");return -EUCLEAN;}
    if (s->ops->release(s) || s->ops->record(s,"CLEANUP_VERIFIED")) return failed(s);
    s->loaded=0;s->stopping=0;s->cleanup_verified=1;return 0;
}

int soc_request_validate(const struct soc_plan *p,const struct soc_request *q,uint32_t sequence,int flags) {
    struct soc_owner zero={0};
    if(flags&(MSG_TRUNC|MSG_CTRUNC) || sequence>=2048 || q->sequence!=sequence+1 ||
       memcmp(q->approval,p->approval,32) || q->operation<1 || q->operation>6 ||
       (q->operation!=2 && (q->generation || q->handle)) ||
       (q->operation==2 && (!q->generation || !q->handle)) ||
       (q->operation!=4 && memcmp(&q->owner,&zero,sizeof(zero))) ||
       (q->operation!=5 && q->reason) ||
       (q->operation==5 && (q->reason<1 || q->reason>7)))return -EPROTO;
    return 0;
}

int soc_rate_allow(uint64_t slots[32],uint32_t *cursor,uint64_t now) {
    if(!now || *cursor>=32)return -EPROTO;
    uint64_t last=slots[(*cursor+31)%32],old=slots[*cursor];
    if(now<last || (old && now-old<1000000000ULL))return -EAGAIN;
    slots[*cursor]=now;*cursor=(*cursor+1)%32;return 0;
}
