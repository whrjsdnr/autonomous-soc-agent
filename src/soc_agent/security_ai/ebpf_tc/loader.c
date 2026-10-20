#define _GNU_SOURCE
extern char **environ;
#include "native.h"
#include "tcx.h"
#include "data.h"
#include "../ebpf/event.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
struct runtime {struct bpf_object *object;struct ring_buffer *ring;
    int program,config;uint32_t emitted;};
static int validate(struct soc_state *s) {
    if(!soc_native_gate() || (s->plan.version==SOC_TCX_VERSION && !soc_tcx_native_admitted()))return -EPERM;
    return soc_plan_validate(&s->plan) ||
        (s->stopping?soc_scope_environment(&s->plan):soc_peer(s->ipc_fd,&s->plan)) ||
        soc_sealed(s->object_fd,s->plan.program_sha)?-EPERM:0;
}
static int emit(void *arg,void *body,size_t size) {
    struct soc_state *s=arg;struct runtime *r=s->context;
    if(size!=sizeof(struct soc_event) || ++r->emitted>s->plan.events)return -EOVERFLOW;
    struct soc_event *e=body;
    if(e->generation!=s->generation || e->ifindex!=s->plan.ifindex || e->hook!=s->plan.hook)
        return -EPROTO;
    /* Dedicated bounded nonblocking metadata channel; no stdout/payload persistence. */
    return soc_data_emit(s,body,size);
}
static int load(struct soc_state *s) {
    if(validate(s) || soc_environment_contract(environ) || soc_release_check(&s->plan,s->release_sha,s->release_version,3) ||
       soc_broker_capabilities(1))return -EPERM;
    struct stat st;if(fstat(s->object_fd,&st) || st.st_size<64 || st.st_size>1048576)return -EINVAL;
    void *body=malloc(st.st_size);if(!body)return -ENOMEM;
    if(pread(s->object_fd,body,st.st_size,0)!=st.st_size) {free(body);return -EIO;}
    struct runtime *r=calloc(1,sizeof(*r));if(!r) {free(body);return -ENOMEM;}
    s->context=r;libbpf_set_print(NULL);
    r->object=bpf_object__open_mem(body,st.st_size,NULL);free(body);
    if(libbpf_get_error(r->object)) {r->object=NULL;return -EINVAL;}
    int tcx=s->plan.version==SOC_TCX_VERSION;
    const char *in=tcx?"tcx/ingress":"tc/ingress", *out=tcx?"tcx/egress":"tc/egress";
    unsigned programs=0,maps=0;struct bpf_program *p;struct bpf_map *m;
    bpf_object__for_each_program(p,r->object) {
        const char *section=bpf_program__section_name(p);
        if(bpf_program__type(p)!=BPF_PROG_TYPE_SCHED_CLS ||
           (strcmp(section,in) && strcmp(section,out)))return -EINVAL;
        /* Load only the explicitly approved hook; retain source object SHA. */
        if(bpf_program__set_autoload(p,!strcmp(section,s->plan.hook==1?in:out)))
            return -EINVAL;
        if(tcx && bpf_program__set_expected_attach_type(p,
            !strcmp(section,in)?BPF_TCX_INGRESS:BPF_TCX_EGRESS))return -EINVAL;
        programs++;
    }
    bpf_object__for_each_map(m,r->object) {
        const char *name=bpf_map__name(m);
        if(!strcmp(name,"events")) {
            if(bpf_map__type(m)!=BPF_MAP_TYPE_RINGBUF || bpf_map__max_entries(m)!=262144)return -EINVAL;
        } else if(!strcmp(name,"config")) {
            if(bpf_map__type(m)!=BPF_MAP_TYPE_ARRAY || bpf_map__max_entries(m)!=1 ||
               bpf_map__key_size(m)!=4 || bpf_map__value_size(m)!=sizeof(struct soc_config))return -EINVAL;
        } else if(!strcmp(name,"counters")) {
            if(bpf_map__type(m)!=BPF_MAP_TYPE_PERCPU_ARRAY || bpf_map__max_entries(m)!=2 ||
               bpf_map__key_size(m)!=4 || bpf_map__value_size(m)!=sizeof(struct soc_counters))return -EINVAL;
        } else return -EINVAL;
        maps++;
    }
    if(programs!=2 || maps!=3 || bpf_object__load(r->object))return -EINVAL;
    bpf_object__for_each_map(m,r->object) {
        struct bpf_map_info info={0};uint32_t len=sizeof(info);
        if(bpf_obj_get_info_by_fd(bpf_map__fd(m),&info,&len) || !info.id ||
           info.type!=bpf_map__type(m) || info.key_size!=bpf_map__key_size(m) ||
           info.value_size!=bpf_map__value_size(m) || info.max_entries!=bpf_map__max_entries(m))return -EINVAL;
    }
    p=bpf_object__find_program_by_name(r->object,s->plan.hook==1?"ingress":"egress");
    if(!p || (r->program=bpf_program__fd(p))<0)return -EINVAL;
    struct bpf_prog_info info={0};uint32_t len=sizeof(info);
    if(bpf_obj_get_info_by_fd(r->program,&info,&len) || !info.id || info.type!=BPF_PROG_TYPE_SCHED_CLS)
        return -EINVAL;
    s->owner=(struct soc_owner){.generation=s->generation,.program_id=info.id,
        .ifindex=s->plan.ifindex,.hook=s->plan.hook,.handle=s->handle,
        .namespace_inode=s->plan.namespace_inode};
    memcpy(s->owner.tag,info.tag,8);memcpy(s->owner.application,s->plan.application,16);
    r->config=bpf_object__find_map_fd_by_name(r->object,"config");
    int fd=bpf_object__find_map_fd_by_name(r->object,"events");
    if(r->config<0 || fd<0)return -EINVAL;
    r->ring=ring_buffer__new(fd,emit,s,NULL);
    return libbpf_get_error(r->ring) || !r->ring?-EINVAL:0;
}
static struct bpf_tc_hook hook(struct soc_state *s) {
    return (struct bpf_tc_hook){.sz=sizeof(struct bpf_tc_hook),.ifindex=s->plan.ifindex,
        .attach_point=s->plan.hook==1?BPF_TC_INGRESS:BPF_TC_EGRESS};
}
static struct bpf_tc_opts opts(struct soc_state *s) {
    struct runtime *r=s->context;
    return (struct bpf_tc_opts){.sz=sizeof(struct bpf_tc_opts),.handle=s->handle,
        .priority=SOC_PRIORITY,.prog_fd=r?r->program:0};
}
static int attach(struct soc_state *s) {
    /* Safe detach is unproved for legacy TC. Never create an uncleanable lease,
     * even if a future release opens the separate global admission gate. */
    (void)s;return -EOPNOTSUPP;
}
static int query(struct soc_state *s,uint32_t *id,uint8_t *tag) {
    if(validate(s))return -EPERM;
    struct bpf_tc_hook h=hook(s);struct bpf_tc_opts o=opts(s);o.prog_fd=0;
    if(bpf_tc_query(&h,&o))return -ENOENT;
    int fd=bpf_prog_get_fd_by_id(o.prog_id);if(fd<0)return -ENOENT;
    struct bpf_prog_info info={0};uint32_t len=sizeof(info);int rc=bpf_obj_get_info_by_fd(fd,&info,&len);
    close(fd);if(rc || info.id!=o.prog_id)return -EINVAL;
    *id=info.id;memcpy(tag,info.tag,8);return 0;
}
static int detach(struct soc_state *s) {
    /* RTM_DELTFILTER cannot condition deletion on Program ID/tag/generation.
     * No re-query closes that race. Do not call bpf_tc_detach at all. */
    (void)s;return -EOPNOTSUPP;
}
static int enable(struct soc_state *s,int enabled) {
    if(validate(s))return -EPERM;
    struct runtime *r=s->context;struct soc_config cfg={0};uint32_t key=0;
    cfg.generation=s->generation;cfg.start_ns=s->started_ns;
    cfg.deadline_ns=cfg.start_ns+(uint64_t)s->plan.duration*1000000000ULL;
    cfg.ifindex=s->plan.ifindex;cfg.enabled=enabled;
    return r?bpf_map_update_elem(r->config,&key,&cfg,BPF_ANY):-EINVAL;
}
static int release(struct soc_state *s) {
    if(!soc_native_gate() || s->attached)return -EPERM;
    struct runtime *r=s->context;if(r) {
        if(r->ring && !libbpf_get_error(r->ring))ring_buffer__free(r->ring);
        if(r->object)bpf_object__close(r->object);free(r);s->context=NULL;
    }return 0;
}
static int record(struct soc_state *s,const char *kind) {
    /* Fail closed on audit transport backpressure. Controller appends received evidence. */
    if(!soc_native_gate())return -EPERM;
    struct {uint8_t plan[32];char kind[32];struct soc_owner owner;
        uint32_t sequence,ordinal;uint8_t previous[32],digest[32];} evidence={0};
    _Static_assert(sizeof(evidence)==192,"journal ABI");
    if(strlen(kind)>=sizeof(evidence.kind) || s->audit_records>=1024)return -EOVERFLOW;
    memcpy(evidence.plan,s->plan.approval,32);strcpy(evidence.kind,kind);
    evidence.owner=s->owner;evidence.sequence=s->sequence;evidence.ordinal=s->audit_records+1;
    memcpy(evidence.previous,s->audit_previous,32);
    if(soc_sha(&evidence,sizeof(evidence)-32,evidence.digest) ||
       write(s->audit_fd,&evidence,sizeof(evidence))!=sizeof(evidence) || fsync(s->audit_fd))return -EIO;
    memcpy(s->audit_previous,evidence.digest,32);s->audit_records++;
    /* Journal commits before mutation, including after Controller EOF. IPC loss during
     * cleanup cannot turn another process's filter into ours or erase local evidence. */
    ssize_t sent=send(s->ipc_fd,&evidence,sizeof(evidence),MSG_DONTWAIT|MSG_NOSIGNAL);
    return sent==sizeof(evidence) || s->stopping?0:-ENOBUFS;
}
int soc_poll(struct soc_state *s) {
    if(validate(s) || !s->attached)return -EPERM;
    struct runtime *r=s->context;return ring_buffer__poll(r->ring,0);
}
const struct soc_ops soc_real_ops={validate,soc_snapshot_real,load,enable,query,attach,detach,release,record};

int soc_program_fd(struct soc_state *s) {
    if(validate(s) || !s->context)return -EPERM;
    return ((struct runtime *)s->context)->program;
}
