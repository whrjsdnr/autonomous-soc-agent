#define _GNU_SOURCE
#include "data.h"
#include "handoff.h"
#include "diagnostics.h"
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
/* SOCK_SEQPACKET is atomic: never send a suffix after a short result.
 * One readiness wait and one resumed send, <=50ms per record and <=2s
 * cumulative per Broker session. No extra queue or Collector restart. */
#define DATA_WAIT_NS 50000000ULL
#define DATA_TOTAL_WAIT_NS 2000000000ULL
static int data_record(struct soc_state *s,const char *kind,const void *detail) {
    struct {uint8_t plan[32];char kind[32];uint8_t detail[80];
        uint32_t sequence,ordinal;uint8_t previous[32],sha[32];} row={0};
    _Static_assert(sizeof(row)==216,"data journal ABI");
    if(s->audit_fd<0 || s->audit_records>=1024 || strlen(kind)>=32)return -EIO;
    memcpy(row.detail,detail,80);memcpy(row.plan,s->plan.approval,32);strcpy(row.kind,kind);
    row.sequence=s->sequence;row.ordinal=s->audit_records+1;
    memcpy(row.previous,s->audit_previous,32);
    if(soc_sha(&row,sizeof(row)-32,row.sha) ||
       write(s->audit_fd,&row,sizeof(row))!=sizeof(row) || fsync(s->audit_fd))return -EIO;
    memcpy(s->audit_previous,row.sha,32);s->audit_records++;return 0;
}
static int socket_sample(struct soc_state *s,unsigned kind,unsigned phase) {
    int queued=0,capacity=0;socklen_t size=sizeof(capacity);
    errno=0;int queried=ioctl(s->data_fd,SIOCOUTQ,&queued),queue_errno=errno;
    errno=0;int buffered=getsockopt(s->data_fd,SOL_SOCKET,SO_SNDBUF,&capacity,&size),buffer_errno=errno;
    int64_t detail[10]={1,kind,phase,(int64_t)s->data_sequence,queried,queue_errno,
        queried? -1:queued,buffered? -buffer_errno:capacity,(int64_t)soc_now(),(int64_t)s->data_wait_ns};
    return data_record(s,"DATA_SOCKET_SAMPLE",detail);
}
static int data_status(struct soc_state *s,unsigned kind,unsigned status,ssize_t result,int saved) {
    struct detail {uint32_t version,kind,status,stopping;
        uint64_t sequence,send_calls,wait_ns,last_sent,packets_sent;
        int64_t result;uint32_t saved_errno,requested,waits,retries;} detail={
        .version=1,.kind=kind,.status=status,.stopping=!!s->stopping,
        .sequence=s->data_sequence,.send_calls=s->data_send_calls,.wait_ns=s->data_wait_ns,
        .last_sent=s->data_last_sent,.packets_sent=s->data_packets_sent,.result=result,
        .saved_errno=saved,.requested=sizeof(struct soc_data_row),
        .waits=s->data_waits,.retries=s->data_retries};
    _Static_assert(sizeof(detail)==80,"data status ABI");
    return data_record(s,"DATA_SEND_STATUS",&detail);
}
static int row(struct soc_state *s,unsigned kind,const struct soc_event *event) {
    if(s->data_fd<0 || !s->data_source || s->data_sequence>=65568)return -EPERM;
    struct soc_data_row r={.magic=SOC_DATA_MAGIC,.version=1,.kind=kind,
        .source=s->data_source,.sequence=s->data_sequence,.loss=s->data_loss};
    if(kind!=SOC_DATA_READY)r.sequence=++s->data_sequence;
    memcpy(r.application,s->plan.application,16);memcpy(r.approval,s->data_approval,32);
    memcpy(r.program,s->plan.program_sha,32);if(event)r.event=*event;
    errno=0;s->data_send_calls++;
    ssize_t sent=send(s->data_fd,&r,sizeof(r),MSG_DONTWAIT|MSG_NOSIGNAL);int saved=errno;
    if(sent<0 && (saved==EAGAIN || saved==EWOULDBLOCK)) {
        if(!s->data_pressure_recorded) {
            s->data_pressure_recorded=1;
            if(socket_sample(s,kind,1) || data_status(s,kind,1,sent,saved))return -EIO;
        }
        uint64_t now=soc_now(),remaining=s->data_wait_ns<DATA_TOTAL_WAIT_NS?
            DATA_TOTAL_WAIT_NS-s->data_wait_ns:0;
        if(remaining>DATA_WAIT_NS)remaining=DATA_WAIT_NS;
        if(!s->stopping && s->started_ns) {
            uint64_t end=s->started_ns+(uint64_t)s->plan.duration*1000000000ULL;
            if(now>=end)remaining=0;else if(remaining>end-now)remaining=end-now;
        }
        /* Forty waits cap scheduled waiting at 2s even if a socket repeatedly
         * becomes writable immediately. Actual elapsed time is also bounded. */
        if(remaining>=1000000ULL && s->data_waits<40) {
            struct pollfd p={.fd=s->data_fd,.events=POLLOUT};
            int milliseconds=(int)(remaining/1000000ULL);s->data_waits++;
            int ready=poll(&p,1,milliseconds);
            uint64_t after=soc_now();
            s->data_wait_ns+=after>=now?after-now:remaining;
            if(ready>0 && (p.revents&POLLOUT) && !(p.revents&(POLLERR|POLLHUP|POLLNVAL))) {
                errno=0;s->data_send_calls++;s->data_retries++;
                sent=send(s->data_fd,&r,sizeof(r),MSG_DONTWAIT|MSG_NOSIGNAL);saved=errno;
            } else if(ready<0) {
                int poll_errno=errno;
                if(data_status(s,kind,4,ready,poll_errno))return -EIO;
            }
        }
    }
    if(sent!=(ssize_t)sizeof(r)) {
        s->data_loss++;
        if(socket_sample(s,kind,2) || data_status(s,kind,2,sent,saved))return -EIO;
        struct soc_load_diagnostic d={.stage=s->stopping?SOC_LOAD_CLEANUP:SOC_DATA_PLANE,
            .api=SOC_DIAG_SEND_DATA,.result=sent,.saved_errno=saved,.errno_source=SOC_SYSCALL_ERRNO};
        soc_diagnostic_record(s,&d,NULL,0);
        return sent<0 && saved?-saved:-EIO;
    }
    s->data_last_sent=r.sequence;if(kind==SOC_DATA_PACKET)s->data_packets_sent++;
    return 0;
}
int soc_data_open(struct soc_state *s,unsigned source,const uint8_t approval[32]) {
    memcpy(s->data_approval,approval,32);
    if(source!=1 && source!=2)return -EPERM;
    s->data_fd=soc_handoff_connect_data(s->plan.uid,s->plan.gid,s->plan.application);
    if(s->data_fd<0 || soc_peer(s->data_fd,&s->plan))return -EPERM;
    int bytes=32768;if(setsockopt(s->data_fd,SOL_SOCKET,SO_SNDBUF,&bytes,sizeof(bytes)))return -EPERM;
    s->data_source=source;return row(s,SOC_DATA_READY,NULL);
}
int soc_data_emit(struct soc_state *s,const void *body,size_t size) {
    const struct soc_event *e=body;
    if(size!=sizeof(*e) || e->generation!=s->generation ||
       e->ifindex!=s->plan.ifindex || e->hook!=s->plan.hook)return -EPROTO;
    return row(s,SOC_DATA_PACKET,e);
}
int soc_data_end(struct soc_state *s,unsigned reason) {
    if(!s->generation || s->data_ended_generation==s->generation)return 0;
    s->data_ended_generation=s->generation;
    /* End of observation does not establish flow completeness. */
    struct soc_event e={.generation=s->generation,.frame_length=reason};
    return row(s,SOC_DATA_RUN_END,&e);
}
int soc_data_close(struct soc_state *s) {
    if(s->data_fd<0)return 0;
    int rc=row(s,SOC_DATA_CLOSED,NULL);
    if(socket_sample(s,SOC_DATA_CLOSED,3) && !rc)rc=-EIO;
    if(data_status(s,SOC_DATA_CLOSED,3,rc,0) && !rc)rc=-EIO;
    if(close(s->data_fd))rc=-EIO;s->data_fd=-1;return rc;
}

int soc_data_counters(struct soc_state *s,const struct soc_counters *c,unsigned status,unsigned delivered) {
    struct {uint64_t generation,timestamp;struct soc_counters totals;uint32_t status,delivered;} payload={
        .generation=s->generation,.timestamp=soc_now(),.status=status,.delivered=delivered};
    _Static_assert(sizeof(payload)==80,"counter payload ABI");
    if(c)payload.totals=*c;struct soc_event bytes;memcpy(&bytes,&payload,sizeof(bytes));
    if(data_record(s,s->data_source==1?"DATA_COUNTER_STATUS":"FIXTURE_COUNTER_STATUS",&payload))return -EIO;
    return row(s,SOC_DATA_COUNTER,&bytes);
}

int soc_data_counter_query(struct soc_state *s,int drain,int cpus,int fd,int lookup,int saved,int sent,uint64_t elapsed,unsigned flags) {
    /* Signed results retain not-attempted (-ECANCELED), syscall errno and
     * transmission failure separately. This row never depends on the socket. */
    struct {
        int64_t version,drain,cpus,fd,lookup,saved,sent,elapsed;
        uint64_t generation;
        int64_t source;
    } detail={1,drain,cpus,fd,lookup,saved,sent,(int64_t)elapsed,
        s->generation,(int64_t)(s->data_source|flags)};
    _Static_assert(sizeof(detail)==80,"counter query ABI");
    return data_record(s,"DATA_COUNTER_QUERY",&detail);
}

int soc_data_accounting(struct soc_state *s,const struct soc_delivery_accounting *detail) {
    /* Journal first: terminal evidence survives a blocked/closed packet channel. */
    if(data_record(s,"DATA_DELIVERY_ACCOUNTING",detail))return -EIO;
    struct soc_event bytes;memcpy(&bytes,detail,sizeof(bytes));
    return row(s,SOC_DATA_ACCOUNTING,&bytes);
}

int soc_data_cpu_window(struct soc_state *s,const struct soc_cpu_window *detail) {
    if(data_record(s,"DATA_CPU_WINDOW",detail))return -EIO;
    struct soc_event bytes;memcpy(&bytes,detail,sizeof(bytes));
    return row(s,SOC_DATA_CPU_WINDOW,&bytes);
}

int soc_data_clock_sample(struct soc_state *s,const uint64_t detail[10]) {
    if(data_record(s,"DATA_CLOCK_SAMPLE",detail))return -EIO;
    struct soc_event bytes;memcpy(&bytes,detail,sizeof(bytes));
    return row(s,SOC_DATA_CLOCK_SAMPLE,&bytes);
}
