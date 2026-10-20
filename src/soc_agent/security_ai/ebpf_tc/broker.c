#define _GNU_SOURCE
#include "native.h"
#include "tcx.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern int soc_poll(struct soc_state *);
/* The six operations reuse the B-1 allowlist. No path/command or arbitrary flags. */
static volatile sig_atomic_t stopped;
static void stop_signal(int n) {(void)n;stopped=1;}
static int broker(int ipc,int plan,int object,int audit) {
    if(!soc_native_gate())return -EPERM;
    struct soc_state s={.ops=&soc_real_ops,.object_fd=object,.ipc_fd=ipc,.audit_fd=audit};uint8_t md[32];
    struct soc_release_envelope envelope;struct stat authority,code,audit_info;
    if(fstat(plan,&authority) || fstat(object,&code) || authority.st_uid || code.st_uid ||
       authority.st_size!=sizeof(envelope) || fstat(audit,&audit_info) ||
       audit_info.st_uid!=getuid() || !S_ISREG(audit_info.st_mode) ||
       audit_info.st_size || audit_info.st_nlink!=1 ||
       (audit_info.st_mode&0777)!=0600 || !(fcntl(audit,F_GETFL)&O_APPEND) || prctl(PR_SET_DUMPABLE,0))return -EPERM;
    if(pread(plan,&envelope,sizeof(envelope),0)!=sizeof(envelope) || soc_fd_sha(plan,md) ||
       soc_sealed(plan,md) || soc_envelope_validate(&envelope))return -EPERM;
    s.plan=envelope.plan;
    if(soc_release_check(&s.plan,envelope.manifest_sha,envelope.release_version,2) || !getuid() || geteuid()!=getuid() ||
       getuid()!=s.plan.uid || getgid()!=s.plan.gid || soc_capabilities() || soc_peer(ipc,&s.plan) ||
       soc_sealed(object,s.plan.program_sha))return -EPERM;
    memcpy(s.release_sha,envelope.manifest_sha,32);
    memcpy(s.release_version,envelope.release_version,16);
    struct soc_tcx link={.session=&s,.ops=&soc_tcx_real_ops,.fd=-1,.program_fd=-1};
    int tcx=s.plan.version==SOC_TCX_VERSION;
    int socket_bytes=32768,passcred=1;
    if(setsockopt(ipc,SOL_SOCKET,SO_PASSCRED,&passcred,sizeof(passcred)) ||
       setsockopt(ipc,SOL_SOCKET,SO_SNDBUF,&socket_bytes,sizeof(socket_bytes)) ||
       setsockopt(ipc,SOL_SOCKET,SO_RCVBUF,&socket_bytes,sizeof(socket_bytes)))return -EPERM;
    struct rlimit cpu={19,20},memory={268435456,268435456},files={32,32},core={0,0};
    if(setrlimit(RLIMIT_CPU,&cpu) || setrlimit(RLIMIT_AS,&memory) ||
       setrlimit(RLIMIT_NOFILE,&files) || setrlimit(RLIMIT_CORE,&core))return -EPERM;
    signal(SIGINT,stop_signal);signal(SIGTERM,stop_signal);signal(SIGXCPU,stop_signal);
    signal(SIGPIPE,SIG_IGN);
    uint64_t born=soc_now(),heartbeat=born;uint64_t previous_generations[16]={0};
    uint32_t previous_handles[16]={0},rate_cursor=0;uint64_t rate_slots[32]={0};int result=0;
    if(soc_release_record(&s) || s.ops->record(&s,"AUTHENTICATION_VERIFIED") || s.ops->record(&s,"BROKER_READY"))return -EIO;
    for(unsigned commands=0;!stopped && commands<2048;) {
        uint64_t now=soc_now();
        if(now<heartbeat || now-born>=3600000000000ULL || now-heartbeat>=15000000000ULL ||
           soc_peer(ipc,&s.plan)) {result=-ETIMEDOUT;break;}
        if(s.attached && now-s.started_ns>=300000000000ULL && (tcx?soc_tcx_cleanup(&link):soc_cleanup(&s))) {result=-EUCLEAN;break;}
        struct pollfd wait={ipc,POLLIN,0};int ready=poll(&wait,1,100);
        if(ready<0) {if(errno==EINTR)continue;result=-EIO;break;}
        if(s.attached && soc_poll(&s)<0) {result=-ENOBUFS;break;}
        if(!ready)continue;
        struct soc_request q={0};
        if(soc_receive_request(ipc,&s.plan,s.sequence,&q)) {result=-EPROTO;break;}
        if(soc_rate_allow(rate_slots,&rate_cursor,now)) {result=-EAGAIN;break;}
        s.sequence=q.sequence;commands++;heartbeat=now;
        int rc=0;
        if(soc_capabilities() || soc_release_check(&s.plan,s.release_sha,s.release_version,2)) {
            result=-EPERM;break; /* owned-FD cleanup below is still attempted */
        }
        if(tcx) {
            if(q.operation==2 && link.phase==SOC_LINK_DETACHED && !s.failed) {
                /* New explicit run, never automatic retry. Broker ingress history still applies. */
                link=(struct soc_tcx){.session=&s,.ops=&soc_tcx_real_ops,.fd=-1,.program_fd=-1};
            }
            if(q.operation==2) {
                for(uint32_t i=0;i<s.attempts;i++)if(previous_generations[i]==q.generation ||
                    previous_handles[i]==q.handle)rc=-EPERM;
                if(!rc && s.attempts<16) {
                    previous_generations[s.attempts]=q.generation;
                    previous_handles[s.attempts]=q.handle;
                }
            }
            if(!rc)rc=soc_tcx_dispatch(&link,&q);
            if(q.operation==6)stopped=1;
        }
        else if(q.operation==1) {if(s.loaded || s.attached)rc=-EPERM;}
        else if(q.operation==2) {
            if(!q.generation || !q.handle || s.attempts>=16) {result=-EINVAL;break;}
            for(uint32_t i=0;i<s.attempts;i++)if(previous_generations[i]==q.generation ||
                previous_handles[i]==q.handle)rc=-EPERM;
            if(rc) {result=rc;break;}
            previous_generations[s.attempts]=q.generation;previous_handles[s.attempts]=q.handle;
            s.generation=q.generation;s.handle=q.handle;s.started_ns=now;
            rc=soc_prepare(&s);if(!rc)rc=soc_attach(&s);
        } else if(q.operation==4) {
            rc=memcmp(&s.owner,&q.owner,sizeof(q.owner))?-EPERM:soc_detach(&s);
        } else if(q.operation==5) {rc=q.reason>=1 && q.reason<=7?(tcx?soc_tcx_cleanup(&link):soc_cleanup(&s)):-EINVAL;}
        else if(q.operation==6) {rc=(tcx?soc_tcx_cleanup(&link):soc_cleanup(&s));stopped=1;}
        struct {uint32_t sequence,state;int32_t error;uint32_t reserved;struct soc_owner owner;} reply={
            q.sequence,s.attached?4:3,rc,0,s.owner};
        if(send(ipc,&reply,sizeof(reply),MSG_DONTWAIT|MSG_NOSIGNAL)!=sizeof(reply))rc=-ENOBUFS;
        if(rc) {result=rc;break;}
    }
    if((tcx?soc_tcx_cleanup(&link):soc_cleanup(&s)))result=-EUCLEAN;
    if(s.ops->record(&s,result?"CLEANUP_UNVERIFIED":"BROKER_EXITED"))result=-EIO;
    close(object);close(plan);close(ipc);close(audit);return result;
}
int main(int argc,char **argv) {
    if(argc==2 && !strcmp(argv[1],"--inspect") && getuid()==geteuid() && getuid()) {
        puts("{\"stage\":\"B2A\",\"native_gate\":false,\"kernel_load\":false,\"tc_attach\":false}");return 0;
    }
    if(!soc_native_gate()) {fputs("EBPF_B2A_NATIVE_EXECUTION_BLOCKED\n",stderr);return 2;}
    if(argc!=5)return 2;
    int fd[4];for(int i=0;i<4;i++) {char *end;long n=strtol(argv[i+1],&end,10);
        if(*end || n<3 || n>31)return 2;fd[i]=n;}
    for(int i=0;i<4;i++)for(int j=i+1;j<4;j++)if(fd[i]==fd[j])return 2;
    return broker(fd[0],fd[1],fd[2],fd[3])?2:0;
}
