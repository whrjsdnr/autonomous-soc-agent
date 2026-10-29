#ifndef SOC_CONTINUOUS_PACKET_PARSER_H
#define SOC_CONTINUOUS_PACKET_PARSER_H
#include "event.h"
/* Same Ethernet/IP/TCP/UDP admission contract as ebpf/parser.h. Unlike the
 * memory parser, all reads use scalar skb offsets and constant-size destinations.
 * No variable stack/map pointer arithmetic, header cache or extra capabilities. */
struct soc_reader { struct __sk_buff *skb; __u32 n; int failed; };
static __inline __attribute__((always_inline)) int
soc_read(struct soc_reader *r, __u32 offset, void *out, __u32 size) {
    if(size>128 || offset>128-size || offset+size>r->n ||
       bpf_skb_load_bytes(r->skb,offset,out,size)) {r->failed=1;return -1;}
    return 0;
}
static __inline __attribute__((always_inline)) unsigned int
soc_byte(struct soc_reader *r,__u32 offset) {
    unsigned char value=0; soc_read(r,offset,&value,1);return value;
}
static __inline __attribute__((always_inline)) unsigned int
soc_word(struct soc_reader *r,__u32 offset) {
    unsigned char value[2]={0};soc_read(r,offset,value,2);
    return ((unsigned int)value[0]<<8)|value[1];
}
static __inline __attribute__((always_inline)) int
soc_parse_skb(struct soc_reader *r,unsigned int wire,struct soc_event *e) {
    unsigned int off=14,proto,end,ip,transport,n=r->n;
    if(wire>65535)return SOC_UNSUPPORTED;
    if(n<14 || wire<14)return SOC_MALFORMED;
    proto=soc_word(r,12);
#pragma unroll
    for(int i=0;i<2;++i) {
        if(proto==0x8100 || proto==0x88a8) {
            if(off+4>n)return SOC_MALFORMED;
            proto=soc_word(r,off+2);off+=4;
        }
    }
    if(proto==0x8100 || proto==0x88a8)return SOC_UNSUPPORTED;
    ip=off;
    if(proto==0x0800) {
        unsigned int version=soc_byte(r,off);
        if(off+20>n || (version>>4)!=4)return SOC_MALFORMED;
        unsigned int ihl=(version&15)*4;
        if(ihl<20 || off+ihl>n)return SOC_MALFORMED;
        e->ip_length=soc_word(r,off+2);
        if(e->ip_length<ihl || ip+e->ip_length>wire)return SOC_MALFORMED;
        if(soc_word(r,off+6)&0x3fff)return SOC_UNSUPPORTED;
        e->family=4;transport=soc_byte(r,off+9);
        soc_read(r,off+12,e->source,4);soc_read(r,off+16,e->destination,4);
        off+=ihl;
    } else if(proto==0x86dd) {
        if(off+40>n || (soc_byte(r,off)>>4)!=6)return SOC_MALFORMED;
        unsigned int payload=soc_word(r,off+4);
        if(!payload)return SOC_UNSUPPORTED;
        e->ip_length=40+payload;
        if(ip+e->ip_length>wire)return SOC_MALFORMED;
        e->family=6;transport=soc_byte(r,off+6);
        soc_read(r,off+8,e->source,16);soc_read(r,off+24,e->destination,16);
        off+=40;
    } else return SOC_UNSUPPORTED;
    end=ip+e->ip_length;
    if(transport!=6 && transport!=17)return SOC_UNSUPPORTED;
    if(off+(transport==6?20:8)>n || off+(transport==6?20:8)>end)return SOC_MALFORMED;
    if(transport==6) {
        unsigned int shape=soc_byte(r,off+12),h=(shape>>4)*4;
        if(h<20 || off+h>end || off+h>n || (shape&15))return SOC_MALFORMED;
        e->flags=soc_byte(r,off+13);
    } else {
        unsigned int len=soc_word(r,off+4);
        if(len<8 || off+len!=end)return SOC_MALFORMED;
    }
    e->source_port=soc_word(r,off);e->destination_port=soc_word(r,off+2);
    e->protocol=transport;e->frame_length=wire;
    return r->failed?SOC_MALFORMED:SOC_OK;
}
#endif
