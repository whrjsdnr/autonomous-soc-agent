#ifndef SOC_OS_HANDOFF_H
#define SOC_OS_HANDOFF_H
#include "native.h"
#define SOC_HANDOFF_MAGIC 0x4a324253U
/* No passwords, bearer secrets, paths or privileged descriptors in replies. */
struct soc_handoff_reply {
    uint32_t magic,phase,source,pid,uid,gid;
    uint64_t ticks;
    uint8_t envelope_sha[32],broker_sha[32];
};
_Static_assert(sizeof(struct soc_handoff_reply)==96,"OS handoff reply ABI");
int soc_handoff_connect(uid_t,gid_t,const uint8_t[16]);
int soc_handoff_receive(int,uid_t,gid_t,const uint8_t[16],const uint8_t[32],const uint8_t[32],struct soc_release_envelope *,int *,int *);
int soc_handoff_reply(int,const struct soc_release_envelope *,unsigned,unsigned);
int soc_os_auth_admitted(void);
#endif
