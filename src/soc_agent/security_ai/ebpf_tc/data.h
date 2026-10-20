#ifndef SOC_PACKET_DATA_H
#define SOC_PACKET_DATA_H
#include "native.h"
#include "../ebpf/event.h"
#define SOC_DATA_MAGIC 0x31445053U
#define SOC_DATA_READY 1
#define SOC_DATA_PACKET 2
#define SOC_DATA_CLOSED 3
#define SOC_DATA_RUN_END 4
/* Separate SOCK_SEQPACKET channel. LE ABI; no descriptors, paths or payload. */
struct soc_data_row {
    uint32_t magic,version,kind,source;
    uint64_t sequence,loss;
    uint8_t application[16],approval[32],program[32];
    struct soc_event event;
};
_Static_assert(__BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__,"little endian data ABI");
_Static_assert(sizeof(struct soc_event)==80,"packet ABI");
_Static_assert(sizeof(struct soc_data_row)==192,"data envelope ABI");
int soc_data_open(struct soc_state *,unsigned,const uint8_t[32]);
int soc_data_emit(struct soc_state *,const void *,size_t);
int soc_data_end(struct soc_state *,unsigned);
int soc_data_close(struct soc_state *);
#endif
