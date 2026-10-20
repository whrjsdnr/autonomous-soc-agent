/* Execute production transaction core against a closed fake syscall table only. */
#include "native.h"
#include "tcx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
struct fake {int scenario,loads,attaches,detaches,releases,records,enabled;
    struct soc_snapshot current;char trace[2048];};
static struct fake *f(struct soc_state *s) {return s->context;}
static int valid(struct soc_state *s) {return f(s)->scenario==1?-EPERM:0;}
static int snap(struct soc_state *s,struct soc_snapshot *out) {*out=f(s)->current;return 0;}
static int load(struct soc_state *s) {
    f(s)->loads++;if(f(s)->scenario==3)return -EINVAL;
    s->owner=(struct soc_owner){.generation=s->generation,.program_id=101,.ifindex=s->plan.ifindex,
        .hook=s->plan.hook,.handle=s->handle,.namespace_inode=s->plan.namespace_inode};
    memcpy(s->owner.application,s->plan.application,16);memset(s->owner.tag,0xab,8);return 0;
}
static int enable(struct soc_state *s,int value) {f(s)->enabled=value;return 0;}
static int query(struct soc_state *s,uint32_t *id,uint8_t *tag) {
    if(f(s)->scenario==5 || f(s)->scenario==11)return -ENOENT;
    *id=f(s)->scenario==6?999:s->owner.program_id;
    memcpy(tag,s->owner.tag,8);if(f(s)->scenario==7)tag[0]++;return 0;
}
static int attach(struct soc_state *s) {
    f(s)->attaches++;struct soc_filter *v=&f(s)->current.filters[f(s)->current.count++];
    memset(v,0,sizeof(*v));*v=(struct soc_filter){.parent=0xfffffff2,.handle=s->handle,
        .priority=SOC_PRIORITY,.program_id=s->owner.program_id};strcpy(v->kind,"bpf");
    return f(s)->scenario==4?-EIO:0;
}
static int detach(struct soc_state *s) {
    if(f(s)->scenario==15) return soc_real_ops.detach(s);
    f(s)->detaches++;
    if(f(s)->scenario==8)return -EIO;
    f(s)->current.count--;
    if(f(s)->scenario==12)f(s)->current.filters[0].program_id=777;
    return 0;
}
static int release(struct soc_state *s) {f(s)->releases++;return 0;}
static int record(struct soc_state *s,const char *kind) {
    f(s)->records++;
    if(f(s)->scenario==15 && !strcmp(kind,"DETACH_REQUESTED")) {
        /* External replacement AFTER the core's final ownership query/snapshot. */
        f(s)->current.filters[1].program_id=999;
    }
    if(strlen(f(s)->trace)+strlen(kind)+2<sizeof(f(s)->trace)) {strcat(f(s)->trace,kind);strcat(f(s)->trace,";");}
    if((f(s)->scenario==9 && !strcmp(kind,"ATTACH_VERIFIED")) ||
       (f(s)->scenario==10 && !strcmp(kind,"DETACH_VERIFIED")))return -EIO;
    return 0;
}
static const struct soc_ops fake_ops={valid,snap,load,enable,query,attach,detach,release,record};
int main(int argc,char **argv) {
    if(argc==3 && !strcmp(argv[1],"--tcx") && getuid() && getuid()==geteuid()) {
        char *end;long n=strtol(argv[2],&end,10);return *end || n<0 || n>20?2:soc_tcx_fixture(n);
    }
    if(argc!=2 || !getuid() || getuid()!=geteuid())return 2;
    char *end;long scenario=strtol(argv[1],&end,10);if(*end || scenario<0 || scenario>20)return 2;
    struct fake fake={.scenario=scenario,.current={.clsact=1,.count=1}};
    fake.current.filters[0]=(struct soc_filter){.parent=0xfffffff2,.priority=1,.handle=1,.program_id=77};
    strcpy(fake.current.filters[0].kind,"foreign");
    struct soc_state s={.ops=&fake_ops,.context=&fake,.generation=11,.handle=4321};
    s.plan=(struct soc_plan){.version=1,.uid=1000,.gid=1000,.controller_pid=1234,
        .controller_ticks=5678,.namespace_inode=999,.ifindex=1,.hook=1,.duration=300,
        .events=4096,.queue=32,.rss_mib=256,.cpu_seconds=20};
    memset(s.plan.application,1,16);memset(s.plan.program_sha,2,32);
    memset(s.plan.loader_sha,3,32);memset(s.plan.bundle_sha,4,32);
    memset(s.plan.bootstrap_sha,5,32);memset(s.plan.broker_sha,6,32);
    soc_sha(&s.plan,sizeof(s.plan),s.plan.approval);
    if(scenario==2) {fake.current.filters[0].priority=SOC_PRIORITY;fake.current.filters[0].handle=4321;}
    if(scenario==13)s.plan.approval[0]++;
    if(scenario==14)fake.current.clsact=0;
    int prepared=soc_prepare(&s),attached=prepared?-999:soc_attach(&s);
    if(scenario==16)s.owner.generation++;
    if(scenario==17)s.owner.namespace_inode++;
    if(scenario==18)s.owner.ifindex++;
    if(scenario==19)s.owner.application[0]++;
    if(scenario==20)s.owner.hook=2;
    int cleaned=soc_cleanup(&s);
    printf("{\"source\":\"C_TRANSACTION_CORE_FAKE_OPS_ONLY\",\"native_gate\":%s,"
        "\"scenario\":%ld,\"prepare\":%d,\"attach\":%d,\"cleanup\":%d,"
        "\"loads\":%d,\"attaches\":%d,\"detaches\":%d,\"releases\":%d,"
        "\"cleanup_verified\":%s,\"failed\":%s,\"foreign_program\":%u,\"remaining\":%u,"
        "\"replacement_program\":%u,\"trace\":\"%s\"}\n",soc_native_gate()?"true":"false",scenario,prepared,attached,cleaned,
        fake.loads,fake.attaches,fake.detaches,fake.releases,s.cleanup_verified?"true":"false",
        s.failed?"true":"false",fake.current.filters[0].program_id,fake.current.count,fake.current.filters[1].program_id,fake.trace);
    return 0;
}
