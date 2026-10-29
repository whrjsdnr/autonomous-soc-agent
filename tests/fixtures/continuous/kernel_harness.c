/* Host execution of the actual Continuous ingress function with mocked helpers.
 * No BPF syscall, Kernel capture, socket, privilege or model authority. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <string.h>
#include "event.h"
static void *lookup(const void *, const void *);
static __u64 clock_ns(void);
static __u32 cpu_id(void);
static long load(const struct __sk_buff *, __u32, void *, __u32);
static void *reserve(void *, __u64, __u64);
static void submit(void *, __u64);
#define bpf_map_lookup_elem lookup
#define bpf_ktime_get_ns clock_ns
#define bpf_get_smp_processor_id cpu_id
#define bpf_skb_load_bytes load
#define bpf_ringbuf_reserve reserve
#define bpf_ringbuf_submit submit
#include "continuous.bpf.c"
static struct soc_config cfg;
static struct period_counter counts;
static struct capture_header temporary;
static struct soc_event output;
static const unsigned char *packet;
static unsigned int packet_size;
static int failure, delivered;
static void *lookup(const void *map, const void *key) {
 (void)key;
 if(map==&config)return &cfg;
 if(map==&counters)return &counts;
 if(map==&scratch)return &temporary;
 return NULL;
}
static __u64 clock_ns(void) { return 1000000000ULL; }
static __u32 cpu_id(void) { return 0; }
static long load(const struct __sk_buff *skb,__u32 offset,void *out,__u32 n) {
 (void)skb;
 if(failure==1) {memset(out,0xaa,n); return -1;}
 if(offset+n>packet_size)return -1;
 memcpy(out,packet+offset,n);return 0;
}
static void *reserve(void *map,__u64 size,__u64 flags) {
 (void)map;(void)flags;
 return failure==2 || size!=sizeof(output)?NULL:&output;
}
static void submit(void *body,__u64 flags) {(void)body;(void)flags;delivered=1;}
int run_packet(const unsigned char *body,unsigned int size,int fail,void *event,unsigned int bytes) {
 if(bytes!=sizeof(output))return -2;
 memset(&counts,0,sizeof(counts));memset(&output,0,sizeof(output));
 memset(&temporary,0xa5,sizeof(temporary));
 cfg=(struct soc_config){7,0,5000000000ULL,1,1};
 packet=body;packet_size=size;failure=fail;delivered=0;
 struct __sk_buff skb={0};skb.len=size;skb.ifindex=1;skb.gso_segs=1;
 ingress(&skb);
 for(unsigned int i=0;i<sizeof(temporary.bytes);i++)if(temporary.bytes[i])return -1;
 memcpy(event,&output,sizeof(output));return delivered;
}
void copy_counters(void *out) {memcpy(out,&counts.total,sizeof(counts.total));}
