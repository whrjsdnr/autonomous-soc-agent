#ifndef SOC_NATIVE_TC_H
#define SOC_NATIVE_TC_H
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#define SOC_VERSION 1
#define SOC_TCX_VERSION 2 /* Same bounded wire shape, distinct approval identity. */
#define SOC_LIMIT_FILTERS 128
#define SOC_INSTALL "/usr/libexec/soc-agent-ebpf/"
#define SOC_POLICY "/etc/pam.d/soc-agent-ebpf"
#define SOC_PRIORITY 49152
/* Fixed little-endian ABI, no path/string/shell fields. */
struct soc_plan {
    uint32_t version, uid, gid, controller_pid;
    uint64_t controller_ticks, namespace_inode;
    uint32_t ifindex, hook, duration, events, queue, rss_mib, cpu_seconds, reserved;
    uint8_t application[16], program_sha[32], loader_sha[32], bootstrap_sha[32], broker_sha[32], bundle_sha[32], approval[32];
};
_Static_assert(sizeof(struct soc_plan)==272,"plan ABI");
/* Versioned, session-bound release approval; never persisted as authentication. */
struct soc_release_envelope {
    struct soc_plan plan;
    uint8_t manifest_sha[32];
    char release_version[16];
    uint8_t approval[32];
};
_Static_assert(sizeof(struct soc_release_envelope)==352,"release approval ABI");
#define SOC_ENTRY_PROOF_FD 31
#define SOC_ENTRY_MAGIC 0x3130304945434f53ULL
struct soc_entry_proof {
    uint64_t magic;uint32_t uid,gid,pid,reserved;
    struct soc_release_envelope envelope;
};
_Static_assert(sizeof(struct soc_entry_proof)==376,"static entry proof ABI");
int soc_entry_identity(const struct soc_entry_proof *,const struct soc_release_envelope *,uid_t,gid_t,pid_t);
int soc_entry_proof_check(const struct soc_release_envelope *);
struct soc_trust_record {char path[256];uint8_t sha[32];uint64_t size;uint32_t mode,reserved;};
struct soc_trust_header {
    char magic[8];uint32_t schema,count,native_release,dynamic_closure;
    uint8_t manifest_sha[32],artifacts[160];char release_version[16];
};
_Static_assert(sizeof(struct soc_trust_header)==232,"trust header ABI");
_Static_assert(sizeof(struct soc_trust_record)==304,"trust record ABI");
int soc_envelope_validate(const struct soc_release_envelope *);
int soc_trust_parse(const void *,size_t,const struct soc_plan *,const uint8_t[32],const char[16]);
int soc_release_check(const struct soc_plan *,const uint8_t[32],const char[16],int);
int soc_capability_contract(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
int soc_capabilities(void);
int soc_broker_capability_contract(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,int);
int soc_broker_capabilities(int);
int soc_broker_privileges(void);
int soc_work_privileges(int);
int soc_process_identity(uid_t,uid_t,uid_t,gid_t,gid_t,gid_t,int);
char *const *soc_clean_environment(void);
int soc_environment_contract(char *const env[]);
int soc_mapped_dependencies(const void *,size_t);
struct soc_state;
int soc_release_record(struct soc_state *);
struct soc_manifest {uint8_t bootstrap[32], broker[32], loader[32], program[32], bundle[32];};
struct soc_filter {uint32_t parent, handle, priority, chain, program_id;char kind[16];};
struct soc_snapshot {uint32_t clsact, count;struct soc_filter filters[SOC_LIMIT_FILTERS];};
struct soc_owner {uint64_t generation;uint32_t program_id, ifindex, hook, handle;
    uint8_t tag[8], application[16];uint64_t namespace_inode;};
struct soc_state;
struct soc_ops {
    int (*validate)(struct soc_state *);
    int (*snapshot)(struct soc_state *,struct soc_snapshot *);
    int (*load)(struct soc_state *);
    int (*enable)(struct soc_state *,int);
    int (*query)(struct soc_state *,uint32_t *,uint8_t *);
    int (*attach)(struct soc_state *);
    int (*detach)(struct soc_state *);
    int (*release)(struct soc_state *);
    int (*record)(struct soc_state *,const char *);
};
struct soc_state {
    uint8_t release_sha[32];char release_version[16];
    struct soc_plan plan;struct soc_owner owner;const struct soc_ops *ops;
    struct soc_snapshot before;void *context;
    uint64_t started_ns, generation;uint32_t handle, attempts, sequence;
    int data_fd;uint32_t data_source;uint64_t data_sequence,data_loss,data_ended_generation;uint8_t data_approval[32];
    int object_fd, ipc_fd, audit_fd, stopping, loaded, attached, failed, cleanup_verified;
    uint8_t audit_previous[32];uint32_t audit_records;
};
struct soc_request {uint32_t operation,sequence;uint64_t generation;uint32_t handle,reason;
    uint8_t approval[32];struct soc_owner owner;};
_Static_assert(sizeof(struct soc_request)==112,"request ABI");
int soc_request_validate(const struct soc_plan *,const struct soc_request *,uint32_t,int);
int soc_receive_request(int,const struct soc_plan *,uint32_t,struct soc_request *);
int soc_rate_allow(uint64_t[32],uint32_t *,uint64_t);
int soc_native_gate(void);
int soc_plan_validate(const struct soc_plan *);
int soc_prepare(struct soc_state *);
int soc_attach(struct soc_state *);
int soc_detach(struct soc_state *);
int soc_cleanup(struct soc_state *);
int soc_sha(const void *,size_t,uint8_t[32]);
int soc_fd_sha(int,uint8_t[32]);
int soc_sealed(int,const uint8_t[32]);
int soc_trusted(const char *,const uint8_t[32]);
int soc_environment(const struct soc_plan *);
int soc_scope_environment(const struct soc_plan *);
int soc_peer(int,const struct soc_plan *);
uint64_t soc_now(void);
struct soc_auth_facts {uint32_t uid,gid,real_uid,effective_uid,tty_owner,
    tty_present,foreground,policy_exact,challenge_count,authentication_status,cached_only;};
int soc_auth_contract(const struct soc_auth_facts *);
int soc_password(const struct soc_release_envelope *);
int soc_account_identity(uid_t,gid_t,uid_t,gid_t,int);
int soc_reduce(uid_t,gid_t);
int soc_snapshot_real(struct soc_state *,struct soc_snapshot *);
extern const struct soc_ops soc_real_ops;
#endif
