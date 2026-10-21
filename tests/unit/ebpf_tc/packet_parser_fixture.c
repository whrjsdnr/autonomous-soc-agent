#include <stdint.h>
#include <string.h>
#include "../ebpf/parser.h"
struct packet {const unsigned char *body;unsigned int length;int fail_offset;};
static int read_packet(struct packet *p,unsigned int offset,void *out,unsigned int size) {
    if(p->fail_offset==(int)offset || offset>p->length || size>p->length-offset)return -1;
    memcpy(out,p->body+offset,size);return 0;
}
#define SOC_TCX_CONTEXT struct packet
#define SOC_TCX_READ(context, offset, output, size) read_packet(context,offset,output,size)
#include "packet_parser.h"
_Static_assert(sizeof(struct soc_event)==80,"packet ABI unchanged");
int fixture_parse(const unsigned char *body,unsigned int length,unsigned int wire,
                  int tcx,int fail_offset,struct soc_event *e) {
    memset(e,0,sizeof(*e));struct packet p={body,length,fail_offset};
    return tcx?soc_tcx_parse(&p,wire,e):soc_parse(body,length<128?length:128,wire,e);
}
