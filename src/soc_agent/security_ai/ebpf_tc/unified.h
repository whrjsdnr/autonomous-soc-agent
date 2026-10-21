#ifndef SOC_UNIFIED_SESSION_H
#define SOC_UNIFIED_SESSION_H
#include "native.h"
#define SOC_UNIFIED_PROOF_FD 8
/* Root-created, sealed, in-memory authority. Never a persisted password token. */
struct soc_unified_proof {
    char magic[8];uint32_t version,pid;
    uint64_t ticks,issued_ns;
    struct soc_release_envelope envelope;
    uint8_t image_sha[32],previous_manifest[32],command_sha[32],approval[32];
};
_Static_assert(sizeof(struct soc_unified_proof)==512,"unified authority ABI");
int soc_os_password_policy_only(unsigned,unsigned);
int soc_unified_proof_read(struct soc_unified_proof *,unsigned,unsigned,
                          const uint8_t[16],const uint8_t[32],const uint8_t[32],const uint8_t[32]);
#endif
