#ifndef SOC_LOADER_DIAGNOSTICS_H
#define SOC_LOADER_DIAGNOSTICS_H
#include "native.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
/* Internal journal extension only. Packet, control, plan and BPF ABIs unchanged. */
enum soc_load_stage {SOC_LOAD_PREPARE=1,SOC_OBJECT_OPEN,SOC_OBJECT_VERIFY,
    SOC_BPF_OBJECT_LOAD,SOC_MAP_INIT,SOC_RING_BUFFER_INIT,SOC_TCX_ATTACH,SOC_LOAD_CLEANUP};
enum soc_load_api {SOC_DIAG_VALIDATE=1,SOC_DIAG_ENVIRONMENT,SOC_DIAG_RELEASE,
    SOC_DIAG_CAPABILITIES,SOC_DIAG_FSTAT,SOC_DIAG_OBJECT_SIZE,SOC_DIAG_PREAD,
    SOC_DIAG_ALLOCATE,SOC_DIAG_OPEN_MEM,SOC_DIAG_PROGRAM_SCHEMA,SOC_DIAG_AUTOLOAD,
    SOC_DIAG_ATTACH_TYPE,SOC_DIAG_MAP_SCHEMA,SOC_DIAG_OBJECT_LOAD,SOC_DIAG_MAP_INFO,
    SOC_DIAG_PROGRAM_FD,SOC_DIAG_PROGRAM_INFO,SOC_DIAG_CONFIG_FD,SOC_DIAG_RING_NEW,
    SOC_DIAG_SNAPSHOT,SOC_DIAG_DRAIN,SOC_DIAG_OBJECT_RELEASE,SOC_DIAG_LINK_ATTACH,
    SOC_DIAG_ENABLE,SOC_DIAG_CAPTURE_FAILED,SOC_DIAG_LINK_DETACH,SOC_DIAG_LOAD_RECORD,SOC_DIAG_VERIFIED_RECORD};
enum soc_errno_source {SOC_CONTRACT_ERROR=0,SOC_SYSCALL_ERRNO,SOC_LIBBPF_RETURN,
    SOC_LIBBPF_POINTER,SOC_ALLOCATOR_ERRNO};
enum soc_resource_bits {SOC_OBJECT_OPENED=1,SOC_MAP_FD_SEEN=2,SOC_PROGRAM_FD_SEEN=4,
    SOC_RING_READY=8,SOC_KERNEL_LOAD_CALLED=16,SOC_OBJECT_RELEASED=32,SOC_LINK_FD_SEEN=64,
    SOC_KERNEL_LOG_AT_BOUND=128,SOC_FD_INVENTORY=256};
struct soc_load_diagnostic {
    uint32_t version,stage,api,errno_source;
    int32_t result,saved_errno;
    uint32_t resources,kernel_log_bytes;
    uint8_t kernel_log_sha[32];
    uint32_t map_fds,program_fds,link_fd,reserved;
};
_Static_assert(sizeof(struct soc_load_diagnostic)==80,"loader diagnostic ABI");
static inline void soc_diagnostic_record(struct soc_state *s,
    struct soc_load_diagnostic *detail,const char *log,size_t length) {
    int *recorded=detail->stage==SOC_LOAD_CLEANUP?&s->diagnostic_cleanup:&s->diagnostic_failed;
    if(*recorded)return;*recorded=1; /* First failure in each plane is immutable. */
    detail->version=1;detail->resources|=s->diagnostic_resources&~SOC_FD_INVENTORY;
    if(length>65536)length=65536;
    detail->kernel_log_bytes=length;
    if(length && soc_sha(log,length,detail->kernel_log_sha)) {s->failed=1;return;}
    struct {uint8_t plan[32];char kind[32];struct soc_load_diagnostic detail;
        uint32_t sequence,ordinal;uint8_t previous[32],sha[32];} row={0};
    _Static_assert(sizeof(row)==216,"loader diagnostic journal ABI");
    if(s->audit_fd<0 || s->audit_records>=1024) {s->failed=1;return;}
    memcpy(row.plan,s->plan.approval,32);strcpy(row.kind,"LOADER_DIAGNOSTIC");row.detail=*detail;
    row.sequence=s->sequence;row.ordinal=s->audit_records+1;memcpy(row.previous,s->audit_previous,32);
    if(soc_sha(&row,sizeof(row)-32,row.sha) ||
       write(s->audit_fd,&row,sizeof(row))!=sizeof(row) || fsync(s->audit_fd)) {s->failed=1;return;}
    memcpy(s->audit_previous,row.sha,32);s->audit_records++;
    /* Journal only: do not inject this row or verifier text into control/data IPC. */
    /* A digest alone cannot explain a verifier rejection. Retain bounded kernel
     * diagnostics in the same private append-only journal, never packet payload.
     * Each chunk shares the existing hash chain and has canonical zero padding. */
    for(size_t offset=0;offset<length;offset+=72) {
        struct {uint32_t offset,length;uint8_t bytes[72];} chunk={0};
        size_t count=length-offset;if(count>72)count=72;
        chunk.offset=offset;chunk.length=count;memcpy(chunk.bytes,log+offset,count);
        if(s->audit_records>=1024) {s->failed=1;return;}
        memset(&row,0,sizeof(row));memcpy(row.plan,s->plan.approval,32);
        strcpy(row.kind,"LOADER_VERIFIER_LOG");memcpy(&row.detail,&chunk,sizeof(chunk));
        row.sequence=s->sequence;row.ordinal=s->audit_records+1;
        memcpy(row.previous,s->audit_previous,32);
        if(soc_sha(&row,sizeof(row)-32,row.sha) ||
           write(s->audit_fd,&row,sizeof(row))!=sizeof(row) || fsync(s->audit_fd)) {s->failed=1;return;}
        memcpy(s->audit_previous,row.sha,32);s->audit_records++;
    }
}
#endif
