#define _GNU_SOURCE
extern char **environ;
#include "native.h"
#include "tcx.h"
#include "data.h"
#include "diagnostics.h"
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
    int program,config;uint32_t emitted;char kernel_log[65536];};
static int validate(struct soc_state *s) {
    if(!soc_native_gate() || (s->plan.version==SOC_TCX_VERSION && !soc_tcx_native_admitted()))return -EPERM;
    return soc_plan_validate(&s->plan) ||
        (s->stopping?soc_scope_environment(&s->plan):soc_peer(s->ipc_fd,&s->plan)) ||
        soc_sealed(s->object_fd,s->plan.program_sha)?-EPERM:0;
}
static int emit(void *arg,void *body,size_t size) {
    struct soc_state *s=arg;struct runtime *r=s->context;
    if(size!=sizeof(struct soc_event))return -EPROTO;
    if(r->emitted>=s->plan.events) {s->packet_budget_reached=1;return 0;}
    r->emitted++;
    if(r->emitted==s->plan.events)s->packet_budget_reached=1;
    struct soc_event *e=body;
    if(e->generation!=s->generation || e->ifindex!=s->plan.ifindex || e->hook!=s->plan.hook)
        return -EPROTO;
    /* Dedicated bounded nonblocking metadata channel; no stdout/payload persistence. */
    return soc_data_emit(s,body,size);
}
static int load_failed(struct soc_state *s,struct runtime *r,unsigned stage,unsigned api,
                       int result,int saved,unsigned source) {
    struct soc_load_diagnostic d={.stage=stage,.api=api,.result=result,
        .saved_errno=saved,.errno_source=source,.resources=SOC_FD_INVENTORY};
    size_t length=r?strnlen(r->kernel_log,sizeof(r->kernel_log)):0;
    if(r && r->object) {
        struct bpf_map *m;struct bpf_program *p;
        bpf_object__for_each_map(m,r->object)if(bpf_map__fd(m)>=0)d.map_fds++;
        bpf_object__for_each_program(p,r->object)if(bpf_program__fd(p)>=0)d.program_fds++;
    }
    if(d.map_fds)d.resources|=SOC_MAP_FD_SEEN;
    if(d.program_fds)d.resources|=SOC_PROGRAM_FD_SEEN;
    if(length>=65535)d.resources|=SOC_KERNEL_LOG_AT_BOUND;
    s->diagnostic_resources|=d.resources&~SOC_FD_INVENTORY;
    soc_diagnostic_record(s,&d,r?r->kernel_log:NULL,length);
    /* Preserve the raw result in the row even for short reads (including zero).
     * Never turn a zero/positive short read into successful loader completion. */
    return result<0?result:-EIO;
}
static int load(struct soc_state *s) {
    int rc=validate(s);
    if(rc)return load_failed(s,NULL,SOC_LOAD_PREPARE,SOC_DIAG_VALIDATE,rc,0,SOC_CONTRACT_ERROR);
    rc=soc_environment_contract(environ);
    if(rc)return load_failed(s,NULL,SOC_LOAD_PREPARE,SOC_DIAG_ENVIRONMENT,rc,0,SOC_CONTRACT_ERROR);
    rc=soc_release_check(&s->plan,s->release_sha,s->release_version,3);
    if(rc)return load_failed(s,NULL,SOC_LOAD_PREPARE,SOC_DIAG_RELEASE,rc,0,SOC_CONTRACT_ERROR);
    rc=soc_broker_capabilities(1);
    if(rc)return load_failed(s,NULL,SOC_LOAD_PREPARE,SOC_DIAG_CAPABILITIES,rc,0,SOC_CONTRACT_ERROR);
    struct stat st;errno=0;rc=fstat(s->object_fd,&st);int saved=errno;
    if(rc)return load_failed(s,NULL,SOC_LOAD_PREPARE,SOC_DIAG_FSTAT,rc,saved,SOC_SYSCALL_ERRNO);
    if(st.st_size<64 || st.st_size>1048576)
        return load_failed(s,NULL,SOC_LOAD_PREPARE,SOC_DIAG_OBJECT_SIZE,-EINVAL,0,SOC_CONTRACT_ERROR);
    errno=0;void *body=malloc(st.st_size);saved=errno;
    if(!body)return load_failed(s,NULL,SOC_LOAD_PREPARE,SOC_DIAG_ALLOCATE,-ENOMEM,saved,SOC_ALLOCATOR_ERRNO);
    errno=0;ssize_t read_bytes=pread(s->object_fd,body,st.st_size,0);saved=errno;
    if(read_bytes!=st.st_size) {free(body);return load_failed(s,NULL,SOC_LOAD_PREPARE,SOC_DIAG_PREAD,read_bytes,saved,SOC_SYSCALL_ERRNO);}
    errno=0;struct runtime *r=calloc(1,sizeof(*r));saved=errno;
    if(!r) {free(body);return load_failed(s,NULL,SOC_LOAD_PREPARE,SOC_DIAG_ALLOCATE,-ENOMEM,saved,SOC_ALLOCATOR_ERRNO);}
    s->context=r;libbpf_set_print(NULL);
    /* Request a bounded kernel log on the first API attempt; never re-invoke load
     * to obtain diagnostics. Keep text only in the private diagnostic journal. */
    struct bpf_object_open_opts options={.sz=sizeof(options),.kernel_log_buf=r->kernel_log,
        .kernel_log_size=sizeof(r->kernel_log),.kernel_log_level=1};
    errno=0;r->object=bpf_object__open_mem(body,st.st_size,&options);saved=errno;free(body);
    long error=libbpf_get_error(r->object);
    if(!r->object || error) {r->object=NULL;return load_failed(s,r,SOC_OBJECT_OPEN,SOC_DIAG_OPEN_MEM,error?error:-EINVAL,saved,SOC_LIBBPF_POINTER);}
    s->diagnostic_resources|=SOC_OBJECT_OPENED;
    int tcx=s->plan.version==SOC_TCX_VERSION;
    const char *in=tcx?"tcx/ingress":"tc/ingress", *out=tcx?"tcx/egress":"tc/egress";
    unsigned programs=0,maps=0;struct bpf_program *p;struct bpf_map *m;
    bpf_object__for_each_program(p,r->object) {
        const char *section=bpf_program__section_name(p);
        if(bpf_program__type(p)!=BPF_PROG_TYPE_SCHED_CLS || !section ||
           (strcmp(section,in) && strcmp(section,out)))
            return load_failed(s,r,SOC_OBJECT_VERIFY,SOC_DIAG_PROGRAM_SCHEMA,-EINVAL,0,SOC_CONTRACT_ERROR);
        errno=0;rc=bpf_program__set_autoload(p,!strcmp(section,s->plan.hook==1?in:out));saved=errno;
        if(rc)return load_failed(s,r,SOC_OBJECT_VERIFY,SOC_DIAG_AUTOLOAD,rc,saved,SOC_LIBBPF_RETURN);
        if(tcx) {
            errno=0;rc=bpf_program__set_expected_attach_type(p,!strcmp(section,in)?BPF_TCX_INGRESS:BPF_TCX_EGRESS);saved=errno;
            if(rc)return load_failed(s,r,SOC_OBJECT_VERIFY,SOC_DIAG_ATTACH_TYPE,rc,saved,SOC_LIBBPF_RETURN);
        }
        programs++;
    }
    bpf_object__for_each_map(m,r->object) {
        const char *name=bpf_map__name(m);int bad=0;
        if(!strcmp(name,"events"))bad=bpf_map__type(m)!=BPF_MAP_TYPE_RINGBUF || bpf_map__max_entries(m)!=262144;
        else if(!strcmp(name,"config"))bad=bpf_map__type(m)!=BPF_MAP_TYPE_ARRAY || bpf_map__max_entries(m)!=1 ||
            bpf_map__key_size(m)!=4 || bpf_map__value_size(m)!=sizeof(struct soc_config);
        else if(!strcmp(name,"counters"))bad=bpf_map__type(m)!=BPF_MAP_TYPE_PERCPU_ARRAY || bpf_map__max_entries(m)!=2 ||
            bpf_map__key_size(m)!=4 || bpf_map__value_size(m)!=sizeof(struct soc_counters);
        else bad=1;
        if(bad)return load_failed(s,r,SOC_OBJECT_VERIFY,SOC_DIAG_MAP_SCHEMA,-EINVAL,0,SOC_CONTRACT_ERROR);
        maps++;
    }
    if(programs!=2 || maps!=3)return load_failed(s,r,SOC_OBJECT_VERIFY,SOC_DIAG_MAP_SCHEMA,-EINVAL,0,SOC_CONTRACT_ERROR);
    s->diagnostic_resources|=SOC_KERNEL_LOAD_CALLED;
    errno=0;rc=bpf_object__load(r->object);saved=errno;
    if(rc)return load_failed(s,r,SOC_BPF_OBJECT_LOAD,SOC_DIAG_OBJECT_LOAD,rc,saved,SOC_LIBBPF_RETURN);
    bpf_object__for_each_map(m,r->object) {
        struct bpf_map_info info={0};uint32_t len=sizeof(info);
        errno=0;rc=bpf_obj_get_info_by_fd(bpf_map__fd(m),&info,&len);saved=errno;
        if(rc)return load_failed(s,r,SOC_MAP_INIT,SOC_DIAG_MAP_INFO,rc,saved,SOC_SYSCALL_ERRNO);
        if(!info.id || info.type!=bpf_map__type(m) || info.key_size!=bpf_map__key_size(m) ||
           info.value_size!=bpf_map__value_size(m) || info.max_entries!=bpf_map__max_entries(m))
            return load_failed(s,r,SOC_MAP_INIT,SOC_DIAG_MAP_SCHEMA,-EINVAL,0,SOC_CONTRACT_ERROR);
    }
    p=bpf_object__find_program_by_name(r->object,s->plan.hook==1?"ingress":"egress");
    errno=0;r->program=p?bpf_program__fd(p):-ENOENT;saved=errno;
    if(r->program<0)return load_failed(s,r,SOC_MAP_INIT,SOC_DIAG_PROGRAM_FD,r->program,saved,SOC_LIBBPF_RETURN);
    struct bpf_prog_info info={0};uint32_t len=sizeof(info);
    errno=0;rc=bpf_obj_get_info_by_fd(r->program,&info,&len);saved=errno;
    if(rc)return load_failed(s,r,SOC_MAP_INIT,SOC_DIAG_PROGRAM_INFO,rc,saved,SOC_SYSCALL_ERRNO);
    if(!info.id || info.type!=BPF_PROG_TYPE_SCHED_CLS)
        return load_failed(s,r,SOC_MAP_INIT,SOC_DIAG_PROGRAM_INFO,-EINVAL,0,SOC_CONTRACT_ERROR);
    s->owner=(struct soc_owner){.generation=s->generation,.program_id=info.id,
        .ifindex=s->plan.ifindex,.hook=s->plan.hook,.handle=s->handle,.namespace_inode=s->plan.namespace_inode};
    memcpy(s->owner.tag,info.tag,8);memcpy(s->owner.application,s->plan.application,16);
    errno=0;r->config=bpf_object__find_map_fd_by_name(r->object,"config");saved=errno;
    if(r->config<0)return load_failed(s,r,SOC_MAP_INIT,SOC_DIAG_CONFIG_FD,r->config,saved,SOC_LIBBPF_RETURN);
    errno=0;int fd=bpf_object__find_map_fd_by_name(r->object,"events");saved=errno;
    if(fd<0)return load_failed(s,r,SOC_RING_BUFFER_INIT,SOC_DIAG_CONFIG_FD,fd,saved,SOC_LIBBPF_RETURN);
    errno=0;r->ring=ring_buffer__new(fd,emit,s,NULL);saved=errno;error=libbpf_get_error(r->ring);
    if(!r->ring || error) {r->ring=NULL;return load_failed(s,r,SOC_RING_BUFFER_INIT,SOC_DIAG_RING_NEW,error?error:-EINVAL,saved,SOC_LIBBPF_POINTER);}
    s->diagnostic_resources|=SOC_RING_READY;return 0;
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
        if(r->object)bpf_object__close(r->object);explicit_bzero(r->kernel_log,sizeof(r->kernel_log));
        free(r);s->context=NULL;s->diagnostic_resources|=SOC_OBJECT_RELEASED;
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

int soc_final_drain_counters(struct soc_state *s) {
    if(validate(s) || s->attached || !s->context)return -EPERM;
    struct runtime *r=s->context;int status=1;
    if(!r->ring || libbpf_get_error(r->ring))return soc_data_counters(s,NULL,2,r->emitted);
    /* Link is detached and observation disabled. Drain queued metadata first. */
    for(unsigned n=0;n<16;n++) {
        int rc=ring_buffer__poll(r->ring,0);
        if(rc<0)return rc;if(!rc)break;if(n==15)return -EOVERFLOW;
    }
    int cpus=libbpf_num_possible_cpus(),fd=bpf_object__find_map_fd_by_name(r->object,"counters");
    struct soc_counters total={0};
    struct soc_counters *rows=NULL;uint32_t key=s->plan.hook-1;
    if(cpus<1 || cpus>4096 || fd<0 || !(rows=calloc(cpus,sizeof(*rows))) ||
       bpf_map_lookup_elem(fd,&key,rows))status=2;
    if(status==1)for(int cpu=0;cpu<cpus;cpu++) {
        uint64_t *to=(uint64_t *)&total,*from=(uint64_t *)&rows[cpu];
        for(unsigned i=0;i<7;i++) {
            if(UINT64_MAX-to[i]<from[i]) {status=2;break;}
            to[i]+=from[i];
        }
    }
    free(rows);return soc_data_counters(s,status==1?&total:NULL,status,r->emitted);
}
