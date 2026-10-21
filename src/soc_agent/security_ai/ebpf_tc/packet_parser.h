#ifndef SOC_TCX_PACKET_PARSER_H
#define SOC_TCX_PACKET_PARSER_H
#include "../ebpf/event.h"
/* Variable offsets refer only to skb packet data. Every helper destination and
 * read length is fixed; never construct stack_buffer + packet_offset. The host
 * harness supplies the identical read contract without invoking a BPF helper. */
#ifndef SOC_TCX_CONTEXT
#define SOC_TCX_CONTEXT struct __sk_buff
#define SOC_TCX_READ(context, offset, output, size) \
    bpf_skb_load_bytes(context, offset, output, size)
#endif
static __inline __attribute__((always_inline)) unsigned int
soc_tcx_be16(const unsigned char *p) {return ((unsigned int)p[0]<<8)|p[1];}
static __inline __attribute__((always_inline)) int
soc_tcx_parse(SOC_TCX_CONTEXT *context,unsigned int wire,struct soc_event *e) {
    unsigned int n=wire<128?wire:128,off=14,ip,end,transport,proto;
    unsigned char eth[14]={0};
    if(wire>65535)return SOC_UNSUPPORTED;
    if(n<14 || SOC_TCX_READ(context,0,eth,sizeof(eth)))return SOC_MALFORMED;
    proto=soc_tcx_be16(eth+12);
#pragma unroll
    for(int i=0;i<2;i++) {
        if(proto==0x8100 || proto==0x88a8) {
            unsigned char vlan[4]={0};
            if(off+4>n || SOC_TCX_READ(context,off,vlan,sizeof(vlan)))return SOC_MALFORMED;
            proto=soc_tcx_be16(vlan+2);off+=4;
        }
    }
    if(proto==0x8100 || proto==0x88a8)return SOC_UNSUPPORTED;
    ip=off;
    if(proto==0x0800) {
        unsigned char ipv4[20]={0};
        if(off+20>n || SOC_TCX_READ(context,off,ipv4,sizeof(ipv4)) ||
           (ipv4[0]>>4)!=4)return SOC_MALFORMED;
        unsigned int ihl=(ipv4[0]&15)*4;
        if(ihl<20 || off+ihl>n)return SOC_MALFORMED;
        e->ip_length=soc_tcx_be16(ipv4+2);
        if(e->ip_length<ihl || ip+e->ip_length>wire)return SOC_MALFORMED;
        if(soc_tcx_be16(ipv4+6)&0x3fff)return SOC_UNSUPPORTED;
        e->family=4;transport=ipv4[9];
        __builtin_memcpy(e->source,ipv4+12,4);
        __builtin_memcpy(e->destination,ipv4+16,4);
        off+=ihl;
    } else if(proto==0x86dd) {
        unsigned char ipv6[40]={0};
        if(off+40>n || SOC_TCX_READ(context,off,ipv6,sizeof(ipv6)) ||
           (ipv6[0]>>4)!=6)return SOC_MALFORMED;
        unsigned int payload=soc_tcx_be16(ipv6+4);
        if(!payload)return SOC_UNSUPPORTED;
        e->ip_length=40+payload;
        if(ip+e->ip_length>wire)return SOC_MALFORMED;
        e->family=6;transport=ipv6[6];
        __builtin_memcpy(e->source,ipv6+8,16);
        __builtin_memcpy(e->destination,ipv6+24,16);
        off+=40;
    } else return SOC_UNSUPPORTED;
    end=ip+e->ip_length;
    if(transport!=6 && transport!=17)return SOC_UNSUPPORTED;
    if(transport==6) {
        unsigned char tcp[20]={0};
        if(off+20>n || off+20>end || SOC_TCX_READ(context,off,tcp,sizeof(tcp)))return SOC_MALFORMED;
        unsigned int h=(tcp[12]>>4)*4;
        if(h<20 || off+h>end || off+h>n || (tcp[12]&15))return SOC_MALFORMED;
        e->flags=tcp[13];
        e->source_port=soc_tcx_be16(tcp);e->destination_port=soc_tcx_be16(tcp+2);
    } else {
        unsigned char udp[8]={0};
        if(off+8>n || off+8>end || SOC_TCX_READ(context,off,udp,sizeof(udp)))return SOC_MALFORMED;
        unsigned int length=soc_tcx_be16(udp+4);
        if(length<8 || off+length!=end)return SOC_MALFORMED;
        e->source_port=soc_tcx_be16(udp);e->destination_port=soc_tcx_be16(udp+2);
    }
    e->protocol=transport;e->frame_length=wire;return SOC_OK;
}
#endif
