// SPDX-License-Identifier: GPL-2.0
/* Separate Continuous policy: never changes the Phase D program or its limits. */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "parser.h"
struct { __uint(type,BPF_MAP_TYPE_RINGBUF); __uint(max_entries,262144); } events SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1);
 __type(key,__u32); __type(value,struct soc_config); } config SEC(".maps");
/* Map-backed temporary header avoids variable offsets into the BPF stack.
 * Erase immediately after parsing (including a failed copy); never retain packet bytes. */
struct capture_header { unsigned char bytes[128]; };
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,1);
 __type(key,__u32); __type(value,struct capture_header); } scratch SEC(".maps");
struct period_counter { struct soc_counters total; __u64 period, admitted; };
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,1);
 __type(key,__u32); __type(value,struct period_counter); } counters SEC(".maps");
SEC("tcx/ingress") int ingress(struct __sk_buff *skb) {
 __u32 key=0; struct soc_config *cfg=bpf_map_lookup_elem(&config,&key);
 struct period_counter *s=bpf_map_lookup_elem(&counters,&key);
 if(!s) return TCX_NEXT;
 struct soc_counters *c=&s->total;
 if(c->observed==~0ULL) return TCX_NEXT;
 __u64 sequence=__sync_add_and_fetch(&c->observed,1), now=bpf_ktime_get_ns();
 /* Root service must renew a <=10s lease; a dead daemon cannot leave capture enabled. */
 if(!cfg || !cfg->enabled || !cfg->generation || skb->ifindex!=cfg->ifindex ||
    now<cfg->start_ns || now>=cfg->deadline_ns ||
    cfg->deadline_ns-cfg->start_ns>10000000000ULL) {c->disabled++; return TCX_NEXT;}
 __u64 period=now/60000000000ULL;
 if(s->period!=period) {s->period=period; s->admitted=0;}
 /* Independent per-CPU/minute admission quota, not a cumulative diagnostic budget. */
 if(s->admitted>=4096) {c->budget++; return TCX_NEXT;}
 if(skb->vlan_present || skb->gso_segs>1) {c->unsupported++; return TCX_NEXT;}
 struct capture_header *header=bpf_map_lookup_elem(&scratch,&key);
 if(!header) {c->malformed++; return TCX_NEXT;}
 __u32 n=skb->len<128?skb->len:128;
 struct soc_event event={0};
 int parsed=bpf_skb_load_bytes(skb,0,header->bytes,n) ? SOC_MALFORMED :
            soc_parse(header->bytes,n,skb->len,&event);
 __builtin_memset(header->bytes,0,sizeof(header->bytes));
 if(parsed==SOC_UNSUPPORTED) {c->unsupported++; return TCX_NEXT;}
 if(parsed!=SOC_OK) {c->malformed++; return TCX_NEXT;}
 struct soc_event *out=bpf_ringbuf_reserve(&events,sizeof(event),0);
 if(!out) {c->ring_lost++; return TCX_NEXT;}
 event.generation=cfg->generation; event.timestamp_ns=now; event.cpu_sequence=sequence;
 event.cpu=bpf_get_smp_processor_id(); event.ifindex=skb->ifindex; event.hook=1;
 __builtin_memcpy(out,&event,sizeof(event)); bpf_ringbuf_submit(out,0);
 c->emitted++; s->admitted++; return TCX_NEXT;
}
char LICENSE[] SEC("license")="GPL";
