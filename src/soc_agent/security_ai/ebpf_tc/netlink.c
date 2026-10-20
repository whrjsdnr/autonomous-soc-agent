#define _GNU_SOURCE
#include "native.h"
#include <errno.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
static int dump(struct soc_state *s,struct soc_snapshot *out,int type,uint32_t parent) {
    if(!soc_native_gate())return -EPERM;
    int fd=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC,NETLINK_ROUTE);if(fd<0)return -errno;
    struct timeval timeout={0,250000};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    struct sockaddr_nl local={.nl_family=AF_NETLINK};
    if(bind(fd,(struct sockaddr *)&local,sizeof(local))) {close(fd);return -EIO;}
    struct {struct nlmsghdr n;struct tcmsg t;} req={0};
    req.n.nlmsg_len=sizeof(req);req.n.nlmsg_type=type;
    req.n.nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP;req.n.nlmsg_seq=1;
    req.t.tcm_family=AF_UNSPEC;req.t.tcm_ifindex=s->plan.ifindex;req.t.tcm_parent=parent;
    struct sockaddr_nl kernel={.nl_family=AF_NETLINK};
    if(sendto(fd,&req,sizeof(req),0,(struct sockaddr *)&kernel,sizeof(kernel))!=sizeof(req)) {
        close(fd);return -EIO;
    }
    unsigned char buffer[65536];int rc=-EOVERFLOW;
    uint64_t deadline=soc_now()+250000000ULL;
    for(unsigned batch=0;batch<32;batch++) {
        uint64_t now=soc_now();if(now>=deadline) {rc=-ETIMEDOUT;break;}
        uint64_t remaining=deadline-now;
        timeout=(struct timeval){.tv_sec=0,.tv_usec=(remaining+999)/1000};
        if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))) {rc=-EIO;break;}
        struct sockaddr_nl source={0};struct iovec iov={buffer,sizeof(buffer)};
        struct msghdr msg={.msg_name=&source,.msg_namelen=sizeof(source),.msg_iov=&iov,.msg_iovlen=1};
        ssize_t got=recvmsg(fd,&msg,0);
        if(got<=0 || msg.msg_flags&MSG_TRUNC || source.nl_pid) {rc=-EIO;break;}
        int left=got;
        for(struct nlmsghdr *n=(struct nlmsghdr *)buffer;NLMSG_OK(n,left);n=NLMSG_NEXT(n,left)) {
            if(n->nlmsg_seq!=1 || n->nlmsg_flags&NLM_F_DUMP_INTR) {rc=-EIO;goto done;}
            if(n->nlmsg_type==NLMSG_DONE) {rc=0;goto done;}
            if(n->nlmsg_type==NLMSG_ERROR || n->nlmsg_len<NLMSG_LENGTH(sizeof(struct tcmsg))) {
                rc=-EIO;goto done;
            }
            struct tcmsg *t=NLMSG_DATA(n);if(t->tcm_ifindex!=(int)s->plan.ifindex)continue;
            int len=n->nlmsg_len-NLMSG_LENGTH(sizeof(*t));
            struct soc_filter f={0};f.parent=t->tcm_parent;f.handle=t->tcm_handle;
            f.priority=t->tcm_info>>16;
            for(struct rtattr *a=TCA_RTA(t);RTA_OK(a,len);a=RTA_NEXT(a,len)) {
                if(a->rta_type==TCA_KIND) {
                    size_t z=RTA_PAYLOAD(a);if(!z || z>sizeof(f.kind) ||
                       ((char *)RTA_DATA(a))[z-1]) {rc=-EINVAL;goto done;}
                    memcpy(f.kind,RTA_DATA(a),z);
                } else if(a->rta_type==TCA_CHAIN && RTA_PAYLOAD(a)==4)memcpy(&f.chain,RTA_DATA(a),4);
                else if(a->rta_type==TCA_OPTIONS) {
                    int z=RTA_PAYLOAD(a);
                    for(struct rtattr *b=RTA_DATA(a);RTA_OK(b,z);b=RTA_NEXT(b,z))
                        if(b->rta_type==TCA_BPF_ID && RTA_PAYLOAD(b)==4)memcpy(&f.program_id,RTA_DATA(b),4);
                }
            }
            if(type==RTM_GETQDISC) {
                if(!strcmp(f.kind,"clsact"))out->clsact++;
            } else {
                if(out->count>=SOC_LIMIT_FILTERS)goto done;
                out->filters[out->count++]=f;
            }
        }
        if(left) {rc=-EINVAL;break;}
    }
done:close(fd);return rc;
}
int soc_snapshot_real(struct soc_state *s,struct soc_snapshot *out) {
    memset(out,0,sizeof(*out));
    if(dump(s,out,RTM_GETQDISC,0) || out->clsact!=1 ||
       dump(s,out,RTM_GETTFILTER,0xfffffff2) || dump(s,out,RTM_GETTFILTER,0xfffffff3))return -EUCLEAN;
    return 0;
}

int soc_snapshot_tcx(struct soc_state *s,struct soc_snapshot *out) {
    memset(out,0,sizeof(*out));
    /* TCX needs no clsact qdisc. Read existing state; never create/delete one. */
    return dump(s,out,RTM_GETQDISC,0) || dump(s,out,RTM_GETTFILTER,0xfffffff2) ||
           dump(s,out,RTM_GETTFILTER,0xfffffff3)?-EUCLEAN:0;
}
