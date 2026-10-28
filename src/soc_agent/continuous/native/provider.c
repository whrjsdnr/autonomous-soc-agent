/* Fixed libbpf provider, no authentication, shell, namespace entry or service installation.
 * Callable only by an already privileged, installed policy-validated service. */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "event.h"
struct runtime { struct bpf_object *object; struct bpf_link *link;
 struct ring_buffer *ring; int cfg, counters, cpus; unsigned int index; uint64_t ns; };
int continuous_close(struct runtime *r) {
 if(!r)return 0; int failed=0; uint32_t key=0; struct soc_config zero={0};
 if(r->cfg>=0 && bpf_map_update_elem(r->cfg,&key,&zero,BPF_ANY)) failed=1;
 if(r->link && bpf_link__detach(r->link)) failed=1;
 if(r->link && bpf_link__destroy(r->link)) failed=1;
 if(r->ring) ring_buffer__free(r->ring);
 if(r->object) bpf_object__close(r->object);
 free(r); return failed?-EUCLEAN:0;
}
struct runtime *continuous_open(const char *path, unsigned int index, uint64_t ns,
                                ring_buffer_sample_fn callback) {
 struct stat st; char name[IF_NAMESIZE];
 if(geteuid() || !if_indextoname(index,name) || strcmp(name,"lo") ||
    stat("/proc/self/ns/net",&st) || st.st_ino!=ns) {errno=EPERM; return NULL;}
 struct runtime *r=calloc(1,sizeof(*r)); if(!r)return NULL; r->cfg=-1; r->index=index; r->ns=ns;
 r->object=bpf_object__open_file(path,NULL);
 if(libbpf_get_error(r->object)) {r->object=NULL; goto bad;}
 if(bpf_object__load(r->object))goto bad;
 r->cfg=bpf_object__find_map_fd_by_name(r->object,"config");
 r->counters=bpf_object__find_map_fd_by_name(r->object,"counters");
 int events=bpf_object__find_map_fd_by_name(r->object,"events");
 r->cpus=libbpf_num_possible_cpus();
 if(r->cfg<0 || r->counters<0 || events<0 || r->cpus<1 || r->cpus>8192)goto bad;
 struct bpf_prog_query_opts q={.sz=sizeof(q)};
 if(bpf_prog_query_opts(index,BPF_TCX_INGRESS,&q) || q.prog_cnt || !q.revision)goto bad;
 struct bpf_tcx_opts opts={.sz=sizeof(opts),.expected_revision=q.revision};
 struct bpf_program *p=bpf_object__find_program_by_name(r->object,"ingress");
 if(!p)goto bad; r->link=bpf_program__attach_tcx(p,index,&opts);
 if(libbpf_get_error(r->link)) {r->link=NULL;goto bad;}
 r->ring=ring_buffer__new(events,callback,NULL,NULL); if(!r->ring)goto bad;
 return r;
 bad: {int cleanup=continuous_close(r); errno=cleanup?EUCLEAN:EPERM;return NULL;}
}
int continuous_renew(struct runtime *r, uint64_t generation, uint64_t now, unsigned int index) {
 uint32_t key=0; struct soc_config cfg={generation,now,now+5000000000ULL,index,1};
 return !r || !generation || index!=r->index?-EINVAL:bpf_map_update_elem(r->cfg,&key,&cfg,BPF_ANY);
}
int continuous_poll(struct runtime *r) {
 if(!r)return -EINVAL;
 struct stat st; uint32_t program=0,link=0;
 struct bpf_prog_query_opts q={.sz=sizeof(q),.prog_cnt=1,.prog_ids=&program,.link_ids=&link};
 struct bpf_link_info info={0};uint32_t size=sizeof(info);
 if(stat("/proc/self/ns/net",&st) || st.st_ino!=r->ns ||
    bpf_link_get_info_by_fd(bpf_link__fd(r->link),&info,&size) ||
    bpf_prog_query_opts(r->index,BPF_TCX_INGRESS,&q) || q.prog_cnt!=1 ||
    info.id!=link || info.prog_id!=program)return -EPERM;
 return ring_buffer__poll(r->ring,100);
}
/* Seven cumulative counters plus current minute admission state for every CPU. */
int continuous_counters(struct runtime *r, uint64_t *out, size_t bytes) {
 if(!r || bytes!=(size_t)r->cpus*9*sizeof(uint64_t))return -EINVAL;
 uint32_t key=0;return bpf_map_lookup_elem(r->counters,&key,out);
}
int continuous_cpus(struct runtime *r) {return r?r->cpus:0;}
