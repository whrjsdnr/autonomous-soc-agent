#ifndef SOC_TCX_H
#define SOC_TCX_H
#include "native.h"
struct soc_tcx_identity {
    uint64_t generation,namespace_inode,broker_ticks;
    uint32_t link_id,program_id,ifindex,attach_type,broker_pid,pinned;
    uint8_t program_tag[8],application[16],program_sha[32];
};
enum soc_tcx_phase {SOC_LINK_NOT_ATTACHED,SOC_LINK_ATTACH_PENDING,SOC_LINK_ACTIVE,
    SOC_LINK_DETACH_PENDING,SOC_LINK_DETACHED,SOC_LINK_ORPHANED,SOC_LINK_UNVERIFIED};
struct soc_tcx;
struct soc_tcx_ops {
    int (*validate)(struct soc_tcx *);
    int (*create)(struct soc_tcx *);
    int (*info)(struct soc_tcx *,struct soc_tcx_identity *);
    int (*detach)(struct soc_tcx *);
    int (*close)(struct soc_tcx *);
    int (*record)(struct soc_tcx *,const char *);
};
struct soc_tcx {
    struct soc_tcx_identity owner;const struct soc_tcx_ops *ops;
    struct soc_state *session;void *context;
    int fd,program_fd,phase,attempted;
};
int soc_tcx_native_admitted(void);
int soc_tcx_attach(struct soc_tcx *);
int soc_tcx_detach(struct soc_tcx *);
extern const struct soc_tcx_ops soc_tcx_real_ops;
int soc_tcx_fixture(int);
int soc_tcx_dispatch(struct soc_tcx *,const struct soc_request *);
int soc_tcx_cleanup(struct soc_tcx *);
int soc_program_fd(struct soc_state *);
int soc_tcx_journal(struct soc_tcx *,const char *);
#endif
