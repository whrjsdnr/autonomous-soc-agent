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
#include <time.h>
#include "event.h"
struct runtime { struct bpf_object *object; struct bpf_link *link;
 struct ring_buffer *ring; int cfg, counters, cpus; unsigned int index; uint64_t ns; uint64_t *initial; };
static uint64_t mono(void) { struct timespec t; if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;
 return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec; }
int continuous_close(struct runtime *r) {
 if(!r)return 0; int failed=0; uint32_t key=0; struct soc_config zero={0};
 if(r->cfg>=0 && bpf_map_update_elem(r->cfg,&key,&zero,BPF_ANY)) failed=1;
 if(r->link && bpf_link__detach(r->link)) failed=1;
 if(r->link && bpf_link__destroy(r->link)) failed=1;
 if(r->ring) ring_buffer__free(r->ring);
 if(r->object) bpf_object__close(r->object);
 free(r->initial); free(r); return failed?-EUCLEAN:0;
}
struct runtime *continuous_open(const char *path, unsigned int index, uint64_t ns,
                                ring_buffer_sample_fn callback, const uint64_t *rates, size_t rate_cpus) {
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
 r->initial=calloc((size_t)r->cpus*9+2,sizeof(uint64_t)); if(!r->initial)goto bad;
 uint32_t key=0;
 /* Carry only the existing per-minute admission state, never capture counters.
  * Fresh maps must not silently grant a second quota in the same minute. */
 if(rates) {
  if(rate_cpus!=(size_t)r->cpus)goto bad;
  uint64_t *seed=calloc((size_t)r->cpus*9,sizeof(uint64_t));if(!seed)goto bad;
  for(int cpu=0;cpu<r->cpus;cpu++) {
   if(rates[cpu*2+1]>4096) {free(seed);goto bad;}
   seed[cpu*9+7]=rates[cpu*2];seed[cpu*9+8]=rates[cpu*2+1];
  }
  int result=bpf_map_update_elem(r->counters,&key,seed,BPF_ANY);free(seed);
  if(result)goto bad;
 } else if(rate_cpus)goto bad;
 r->initial[0]=mono();
 if(bpf_map_lookup_elem(r->counters,&key,r->initial+2))goto bad;
 r->initial[1]=mono();
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

/* Actual same-owned-map PRE_ATTACH snapshot, never a fabricated zero baseline. */
int continuous_initial(struct runtime *r,uint64_t *out,size_t bytes) {
 if(!r || !r->initial || bytes!=((size_t)r->cpus*9+2)*sizeof(uint64_t))return -EINVAL;
 memcpy(out,r->initial,bytes);return 0;
}
/* Detach before final ring drain and snapshot. No later callbacks can enter this map. */
int continuous_finish(struct runtime *r,uint64_t *out,size_t bytes) {
 if(!r || !r->link || bytes!=((size_t)r->cpus*9+2)*sizeof(uint64_t))return -EINVAL;
 if(bpf_link__detach(r->link))return -EUCLEAN;
 if(bpf_link__destroy(r->link)) {r->link=NULL;return -EUCLEAN;} r->link=NULL;
 int result=ring_buffer__consume(r->ring);if(result<0)return result;
 uint32_t key=0;out[0]=mono();
 if(bpf_map_lookup_elem(r->counters,&key,out+2))return -EIO;
 out[1]=mono();return 0;
}
