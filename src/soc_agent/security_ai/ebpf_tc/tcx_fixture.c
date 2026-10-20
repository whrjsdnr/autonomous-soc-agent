/* Closed fake resource table, not OS FDs. Models references and object identity. */
#include "tcx.h"
#include <linux/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
struct fake_link {int scenario,refs,active,foreign_active,deletes,closed;
    struct soc_tcx_identity kernel;char trace[1024];};
static struct fake_link *f(struct soc_tcx *l) {return l->context;}
static int validate(struct soc_tcx *l) {return f(l)->scenario==10?-EPERM:0;}
static int create(struct soc_tcx *l) {
    struct fake_link *k=f(l);k->kernel=l->owner;k->kernel.link_id=501;
    k->refs=1;k->active=1;l->fd=71;
    if(k->scenario==1)return -EIO;
    return 0;
}
static int info(struct soc_tcx *l,struct soc_tcx_identity *out) {
    struct fake_link *k=f(l);if(k->scenario==2)return -EIO;
    *out=k->kernel;if(!k->active)out->ifindex=0;
    if(k->scenario==3)out->program_id++;
    if(k->scenario==4)out->attach_type=BPF_TCX_EGRESS;
    return 0;
}
static int detach(struct soc_tcx *l) {
    struct fake_link *k=f(l);if(k->scenario==7)return -EIO;
    k->deletes++;k->active=0;return 0; /* Only held object, never foreign_active. */
}
static int close_link(struct soc_tcx *l) {
    struct fake_link *k=f(l);k->closed++;k->refs--;if(k->scenario==8)return -EIO;return 0;
}
static int record(struct soc_tcx *l,const char *kind) {
    struct fake_link *k=f(l);
    if(strlen(k->trace)+strlen(kind)+2<sizeof(k->trace)) {strcat(k->trace,kind);strcat(k->trace,";");}
    if(k->scenario==9 && !strcmp(kind,"TCX_DETACHED"))return -EIO;
    /* Another manager replaces a positional filter after our last info check. */
    if(k->scenario==6 && !strcmp(kind,"TCX_DETACH_REQUESTED"))k->foreign_active=2;
    return 0;
}
static const struct soc_tcx_ops ops={validate,create,info,detach,close_link,record};
int soc_tcx_fixture(int scenario) {
    if(scenario<0 || scenario>20)return 2;
    struct fake_link k={.scenario=scenario,.foreign_active=1};
    struct soc_tcx l={.ops=&ops,.context=&k,.fd=-1,.program_fd=-1};
    l.owner=(struct soc_tcx_identity){.generation=1,.namespace_inode=44,.broker_ticks=77,
        .program_id=101,.ifindex=1,.attach_type=BPF_TCX_INGRESS,.broker_pid=9};
    memset(l.owner.application,1,16);memset(l.owner.program_sha,2,32);memset(l.owner.program_tag,3,8);
    if(scenario==5)l.owner.pinned=1;
    int attached=soc_tcx_attach(&l),replay=soc_tcx_attach(&l);
    if(scenario==11) {k.refs++;} /* Copied FD: close alone is insufficient. */
    if(scenario==13)k.refs++; /* External FD duplicated before the crash. */
    if(scenario==12 || scenario==13) { /* Process crash: its own reference closes. */
        k.refs--;l.fd=-1;if(!k.refs)k.active=0;l.phase=k.active?SOC_LINK_ORPHANED:SOC_LINK_UNVERIFIED;
    }
    if(scenario==14) {k.kernel.ifindex=0;k.active=0;} /* Interface removed. */
    if(scenario==15)l.owner.generation++; /* Forged/stale journal lease. */
    if(scenario==16)l.owner.application[0]++;
    if(scenario==17)k.kernel.program_id=999;
    if(scenario==18)k.kernel.link_id=777;
    if(scenario==19)k.refs++; /* A privileged external pin retains a reference. */
    if(scenario==20)l.owner.program_sha[0]++;
    int detached=soc_tcx_detach(&l);
    char sha[65]={0},tag[17]={0},app[33]={0};
    for(int i=0;i<32;i++)snprintf(sha+2*i,3,"%02x",l.owner.program_sha[i]);
    for(int i=0;i<8;i++)snprintf(tag+2*i,3,"%02x",l.owner.program_tag[i]);
    for(int i=0;i<16;i++)snprintf(app+2*i,3,"%02x",l.owner.application[i]);
    printf("{\"source\":\"TCX_FAKE_RESOURCE_TABLE_NOT_KERNEL\",\"native\":false,"
        "\"replay\":%d,\"link_id\":%u,\"attach\":%d,\"detach\":%d,\"phase\":%d,\"active\":%d,\"references\":%d,"
        "\"foreign\":%d,\"deletes\":%d,\"closed\":%d,\"trace\":\"%s\","
        "\"owner\":{\"origin\":\"C_FAKE_NOT_KERNEL\",\"link_id\":%u,\"program_id\":%u,"
        "\"attach_type\":%u,\"ifindex\":%u,\"namespace_inode\":%llu,\"generation\":%llu,"
        "\"broker_pid\":%u,\"broker_ticks\":%llu,\"pinned\":%u,\"program_sha\":\"%s\","
        "\"program_tag\":\"%s\",\"application\":\"%s\"}}\n",
        replay,l.owner.link_id,attached,detached,l.phase,k.active,k.refs,k.foreign_active,k.deletes,k.closed,k.trace,l.owner.link_id,l.owner.program_id,l.owner.attach_type,l.owner.ifindex,
        (unsigned long long)l.owner.namespace_inode,(unsigned long long)l.owner.generation,
        l.owner.broker_pid,(unsigned long long)l.owner.broker_ticks,l.owner.pinned,sha,tag,app);
    return 0;
}
