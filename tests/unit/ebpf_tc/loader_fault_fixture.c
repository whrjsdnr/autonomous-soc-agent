/* Ordinary-UID fault injection: every kernel-facing libbpf API used here is
 * replaced, never forwards to BPF syscalls. Never installed or run as Root. */
#define _GNU_SOURCE
#include "tcx.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int scenario,load_calls,drain_calls,ring_freed;
static char *kernel_log;static const struct bpf_map *last_map;
int soc_native_gate(void) {return 1;} /* This executable's test process only. */
int soc_tcx_native_admitted(void) {return 1;}
int soc_plan_validate(const struct soc_plan *p) {(void)p;return 0;}
int soc_environment_contract(char *const e[]) {(void)e;return 0;}
int soc_peer(int f,const struct soc_plan *p) {(void)f;(void)p;return 0;}
int soc_sealed(int f,const uint8_t p[32]) {(void)f;(void)p;return 0;}
int soc_scope_environment(const struct soc_plan *p) {(void)p;return 0;}
int soc_broker_capabilities(int work) {(void)work;return 0;}
int soc_release_check(const struct soc_plan *p,const uint8_t m[32],const char v[16],int stage) {
 (void)p;(void)m;(void)v;(void)stage;errno=ENOTTY;return scenario==1?-EPERM:0;
}
struct bpf_object *bpf_object__open_mem(const void *b,size_t n,const struct bpf_object_open_opts *opts) {
 kernel_log=opts->kernel_log_buf;
 if(scenario==2) {errno=ENOEXEC;return NULL;}
 struct bpf_object *(*real_open)(const void *,size_t,const struct bpf_object_open_opts *)=dlsym(RTLD_NEXT,"bpf_object__open_mem");
 if(!real_open)_exit(101);return real_open(b,n,opts); /* ELF parse only, no load. */
}
int bpf_program__set_autoload(struct bpf_program *p,bool enabled) {
 if(scenario==3) {errno=EINVAL;return -EINVAL;}
 int (*real_set)(struct bpf_program *,bool)=dlsym(RTLD_NEXT,"bpf_program__set_autoload");
 if(!real_set)_exit(102);return real_set(p,enabled);
}
int bpf_object__load(struct bpf_object *o) {
 (void)o;load_calls++;
 if(scenario==4) {strcpy(kernel_log,"fixture-verifier-no-traffic");errno=EACCES;return -EACCES;}
 return 0; /* Deliberately do not load anything into the kernel. */
}
int bpf_map__fd(const struct bpf_map *m) {last_map=m;errno=EBADF;return load_calls?4000:-1;}
int bpf_program__fd(const struct bpf_program *p) {return load_calls && bpf_program__autoload(p)?4001:-1;}
int bpf_object__find_map_fd_by_name(const struct bpf_object *o,const char *name) {(void)o;(void)name;return 4000;}
int bpf_obj_get_info_by_fd(int fd,void *info,__u32 *length) {
 (void)fd;
 if(scenario==5) {errno=EBADF;return -1;}
 if(*length==sizeof(struct bpf_map_info)) {
  struct bpf_map_info *i=info;i->id=1;i->type=bpf_map__type(last_map);
  i->key_size=bpf_map__key_size(last_map);i->value_size=bpf_map__value_size(last_map);
  i->max_entries=bpf_map__max_entries(last_map);return 0;
 }
 struct bpf_prog_info *i=info;i->id=2;i->type=BPF_PROG_TYPE_SCHED_CLS;return 0;
}
struct ring_buffer *ring_buffer__new(int fd,ring_buffer_sample_fn cb,void *ctx,const struct ring_buffer_opts *opts) {
 (void)fd;(void)cb;(void)ctx;(void)opts;
 if(scenario==6) {errno=ENOMEM;return NULL;}return (struct ring_buffer *)0x1234;
}
void ring_buffer__free(struct ring_buffer *r) {(void)r;ring_freed++;}
int soc_snapshot_tcx(struct soc_state *s,struct soc_snapshot *out) {(void)s;(void)out;return -EAGAIN;}
int soc_final_drain_counters(struct soc_state *s) {(void)s;drain_calls++;return -EPIPE;}
int main(int argc,char **argv) {
 if(getuid()==0 || argc!=4)return 2;scenario=atoi(argv[1]);if(scenario<1 || scenario>7)return 2;
 int object=open(argv[2],O_RDONLY|O_NOFOLLOW),audit=open(argv[3],O_WRONLY|O_CREAT|O_EXCL|O_APPEND,0600);
 if(object<0 || audit<0)return 3;
 struct soc_state s={.ops=&soc_real_ops,.object_fd=object,.audit_fd=audit,.ipc_fd=-1,.data_fd=-1};
 s.plan.version=SOC_TCX_VERSION;s.plan.hook=1;memset(s.plan.approval,0xaa,32);
 int first=soc_real_ops.load(&s);s.loaded=!first;s.failed=1;
 if(scenario==7)s.tcx_snapshot_valid=1;
 struct soc_tcx link={.session=&s,.fd=-1,.program_fd=-1};
 errno=EIO;int cleaned=soc_tcx_cleanup(&link);
 printf("{\"source\":\"UNPRIVILEGED_FAULT_FIXTURE_NO_KERNEL\",\"load_return\":%d,"
        "\"cleanup_return\":%d,\"context_released\":%s,\"load_api_calls\":%d,"
        "\"drain_calls\":%d,\"ring_freed\":%d,\"cleanup_verified\":%d}\n",
        first,cleaned,s.context?"false":"true",load_calls,drain_calls,ring_freed,s.cleanup_verified);
 close(object);close(audit);return 0;
}
