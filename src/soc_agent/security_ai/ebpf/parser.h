#ifndef SOC_EBPF_PARSER_H
#define SOC_EBPF_PARSER_H
#include "event.h"
/* One parser shared by TC and the non-privileged host fixture harness.
 * TC supplies at most 128 header bytes, never persists them. */
static __inline __attribute__((always_inline)) unsigned int be16(const unsigned char *p) {
    return ((unsigned int)p[0] << 8) | p[1];
}
static __inline __attribute__((always_inline)) int
soc_parse(const unsigned char *p, unsigned int n, unsigned int wire, struct soc_event *e) {
    unsigned int off=14, proto, end, ip, transport;
    if (wire>65535) return SOC_UNSUPPORTED;
    if (n < 14 || wire < 14) return SOC_MALFORMED;
    proto=be16(p+12);
#pragma unroll
    for (int i=0; i<2; ++i) {
        if (proto==0x8100 || proto==0x88a8) {
            if (off+4>n) return SOC_MALFORMED;
            proto=be16(p+off+2); off+=4;
        }
    }
    if (proto==0x8100 || proto==0x88a8) return SOC_UNSUPPORTED;
    ip=off;
    if (proto==0x0800) {
        if (off+20>n || (p[off]>>4)!=4) return SOC_MALFORMED;
        unsigned int ihl=(p[off]&15)*4;
        if (ihl<20 || off+ihl>n) return SOC_MALFORMED;
        e->ip_length=be16(p+off+2);
        if (e->ip_length<ihl || ip+e->ip_length>wire) return SOC_MALFORMED;
        if (be16(p+off+6)&0x3fff) return SOC_UNSUPPORTED;
        e->family=4; transport=p[off+9];
        __builtin_memcpy(e->source,p+off+12,4);
        __builtin_memcpy(e->destination,p+off+16,4);
        off+=ihl;
    } else if (proto==0x86dd) {
        if (off+40>n || (p[off]>>4)!=6) return SOC_MALFORMED;
        unsigned int payload=be16(p+off+4);
        if (!payload) return SOC_UNSUPPORTED; /* no jumbograms */
        e->ip_length=40+payload;
        if (ip+e->ip_length>wire) return SOC_MALFORMED;
        e->family=6; transport=p[off+6];
        __builtin_memcpy(e->source,p+off+8,16);
        __builtin_memcpy(e->destination,p+off+24,16);
        off+=40; /* extensions/fragments are unsupported, never guessed */
    } else return SOC_UNSUPPORTED;
    end=ip+e->ip_length;
    if (transport!=6 && transport!=17) return SOC_UNSUPPORTED;
    if (off+ (transport==6 ? 20 : 8)>n || off+(transport==6 ? 20 : 8)>end)
        return SOC_MALFORMED;
    if (transport==6) {
        unsigned int h=(p[off+12]>>4)*4;
        if (h<20 || off+h>end || off+h>n || (p[off+12]&15)) return SOC_MALFORMED;
        e->flags=p[off+13];
    } else {
        unsigned int len=be16(p+off+4);
        if (len<8 || off+len!=end) return SOC_MALFORMED;
    }
    e->source_port=be16(p+off); e->destination_port=be16(p+off+2);
    e->protocol=transport; e->frame_length=wire;
    return SOC_OK;
}
#endif
