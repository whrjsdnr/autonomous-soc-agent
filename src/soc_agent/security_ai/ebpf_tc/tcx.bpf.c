// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "packet_parser.h"
/* Linux 6.18 TCX_NEXT preserves later TCX and Legacy TC evaluation. */
_Static_assert(TCX_NEXT == TC_ACT_UNSPEC, "TCX continuation ABI");
struct { __uint(type,BPF_MAP_TYPE_RINGBUF); __uint(max_entries,262144); } events SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1);
    __type(key,__u32); __type(value,struct soc_config); } config SEC(".maps");
/* Separate hook/CPU counters. Cumulative for map generation, reset requires new session. */
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,2);
    __type(key,__u32); __type(value,struct soc_counters); } counters SEC(".maps");
static __always_inline int observe(struct __sk_buff *skb, __u8 hook) {
    __u32 zero=0, key=hook-1;
    struct soc_config *cfg=bpf_map_lookup_elem(&config,&zero);
    struct soc_counters *c=bpf_map_lookup_elem(&counters,&key);
    if (!c) return TCX_NEXT;
    if (c->observed==~0ULL) return TCX_NEXT; /* saturation: later attestation fails */
    __u64 sequence=__sync_add_and_fetch(&c->observed,1);
    __u64 now=bpf_ktime_get_ns();
    if (!cfg || !cfg->enabled || !cfg->generation || skb->ifindex!=cfg->ifindex) {
        c->disabled++; return TCX_NEXT;
    }
    if (cfg->deadline_ns<=cfg->start_ns || cfg->deadline_ns-cfg->start_ns>300000000000ULL ||
        now<cfg->start_ns || now>=cfg->deadline_ns || sequence>4096) {
        c->budget++; return TCX_NEXT;
    }
    if (skb->vlan_present || skb->gso_segs>1) {c->unsupported++; return TCX_NEXT;}
    /* Fixed helper destinations also support non-linear skb without pulling data. */
    struct soc_event event={0};
    int status=soc_tcx_parse(skb,skb->len,&event);
    if (status==SOC_UNSUPPORTED) {c->unsupported++; return TCX_NEXT;}
    if (status!=SOC_OK) {
        c->malformed++; return TCX_NEXT;
    }
    struct soc_event *out=bpf_ringbuf_reserve(&events,sizeof(event),0);
    if (!out) {c->ring_lost++; return TCX_NEXT;}
    event.generation=cfg->generation; event.timestamp_ns=now;
    event.cpu_sequence=sequence; event.cpu=bpf_get_smp_processor_id();
    event.ifindex=skb->ifindex; event.hook=hook;
    __builtin_memcpy(out,&event,sizeof(event));
    bpf_ringbuf_submit(out,0); c->emitted++;
    return TCX_NEXT;
}
SEC("tcx/ingress") int ingress(struct __sk_buff *skb) {return observe(skb,1);}
SEC("tcx/egress") int egress(struct __sk_buff *skb) {return observe(skb,2);}
char LICENSE[] SEC("license")="GPL";
