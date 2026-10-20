#ifndef SOC_EBPF_EVENT_H
#define SOC_EBPF_EVENT_H
#include <linux/types.h>
/* Fixed native little-endian ABI v1. No payload; namespace/session are bound in config. */
struct soc_event {
    __u64 generation;
    __u64 timestamp_ns; /* bpf_ktime_get_ns: monotonic, NOT UTC/pcap event time */
    __u64 cpu_sequence; /* per-CPU attempts, includes reservation failure gaps */
    __u32 ifindex;
    __u32 cpu;
    __u32 frame_length;
    __u32 ip_length;
    __u16 source_port;
    __u16 destination_port;
    __u8 family;
    __u8 protocol;
    __u8 flags;
    __u8 hook; /* 1 ingress / 2 egress; not first-seen flow direction */
    __u8 source[16];
    __u8 destination[16];
};
struct soc_config {
    __u64 generation;
    __u64 start_ns;
    __u64 deadline_ns;
    __u32 ifindex;
    __u32 enabled; /* zero by default: observation disabled */
};
struct soc_counters {
    __u64 observed, emitted, ring_lost, unsupported, malformed, disabled, budget;
};
enum { SOC_OK, SOC_UNSUPPORTED, SOC_MALFORMED };
#endif
