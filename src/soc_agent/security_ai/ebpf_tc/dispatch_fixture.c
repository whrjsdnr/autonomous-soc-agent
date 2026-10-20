/* Ordinary-UID fixture: no OS BPF descriptors and no privileged provider calls. */
#define _GNU_SOURCE
#include "tcx.h"
#include <linux/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static struct {int scenario,active,created,removed,foreign;struct soc_tcx_identity owner;} fake;
static int valid(struct soc_state *s) {(void)s;return 0;}
static int load(struct soc_state *s) {
    if(fake.scenario==1)return -EIO;
    s->owner=(struct soc_owner){.generation=s->generation,.program_id=101,
        .ifindex=s->plan.ifindex,.hook=s->plan.hook,.handle=s->handle,
        .namespace_inode=s->plan.namespace_inode};
    memcpy(s->owner.application,s->plan.application,16);memset(s->owner.tag,3,8);return 0;
}
static int enable(struct soc_state *s,int value) {(void)s;(void)value;return fake.scenario==2?-EIO:0;}
static int record(struct soc_state *s,const char *kind) {(void)s;(void)kind;return 0;}
static int check(struct soc_tcx *l) {(void)l;return fake.scenario==3?-EPERM:0;}
static int create(struct soc_tcx *l) {
    fake.created++;fake.active=1;l->fd=71;fake.owner=l->owner;fake.owner.link_id=501;
    return fake.scenario==4?-EIO:0;
}
static int info(struct soc_tcx *l,struct soc_tcx_identity *out) {
    (void)l;*out=fake.owner;if(!fake.active)out->ifindex=0;
    if(fake.scenario==5)out->program_id++;
    return 0;
}
static int detach(struct soc_tcx *l) {
    (void)l;if(fake.scenario==6)return -EIO;
    fake.active=0;fake.removed++;return 0;
}
static int close_link(struct soc_tcx *l) {(void)l;return 0;}
static int journal(struct soc_tcx *l,const char *kind) {return soc_tcx_journal(l,kind);}
static const struct soc_ops ops={.validate=valid,.load=load,.enable=enable,.release=valid,.record=record};
static const struct soc_tcx_ops links={check,create,info,detach,close_link,journal};
int main(int argc,char **argv) {
    if(getuid()==0 || argc!=2)return 2;
    char *end;long n=strtol(argv[1],&end,10);if(*end || n<0 || n>9)return 2;
    fake.scenario=n;fake.foreign=1;
    char path[]="/tmp/soc-tcx-journal-XXXXXX";int fd=mkstemp(path);if(fd<0)return 2;unlink(path);
    struct soc_state s={.ops=&ops,.audit_fd=fd,.ipc_fd=-1,.stopping=1};
    s.plan=(struct soc_plan){.version=SOC_TCX_VERSION,.uid=1000,.gid=1000,.controller_pid=10,
        .controller_ticks=11,.namespace_inode=44,.ifindex=1,.hook=1,.duration=300,
        .events=4096,.queue=32,.rss_mib=256,.cpu_seconds=20};
    memset(s.plan.application,1,16);memset(s.plan.program_sha,2,32);
    memset(s.plan.loader_sha,3,32);memset(s.plan.bootstrap_sha,4,32);
    memset(s.plan.broker_sha,5,32);memset(s.plan.bundle_sha,6,32);
    soc_sha(&s.plan,sizeof(s.plan),s.plan.approval);
    struct soc_tcx l={.session=&s,.ops=&links,.fd=-1,.program_fd=-1};
    struct soc_request q={.operation=2,.sequence=1,.generation=1,.handle=2};
    memcpy(q.approval,s.plan.approval,32);
    if(n==7)q.approval[0]++;
    if(n==8)s.plan.version=1; /* An old plan never selects the TCX dispatcher. */
    /* Local fixture journal has no listener: stopping only suppresses IPC delivery. */
    int first;
    /* Dispatcher resets stopping. A local connected socket drains journal notifications. */
    int sockets[2];extern int socketpair(int,int,int,int[2]);
    if(socketpair(1,5,0,sockets))return 2;s.ipc_fd=sockets[0];
    first=soc_tcx_dispatch(&l,&q);
    q.operation=4;q.sequence=2;q.generation=0;q.handle=0;q.owner=s.owner;
    if(n==9)q.owner.program_id++;
    int stopped=soc_tcx_dispatch(&l,&q);
    /* Crash/stop cleanup uses the held link even if the request was rejected. */
    int cleaned=soc_tcx_cleanup(&l);
    unsigned char body[4096];ssize_t size=pread(fd,body,sizeof(body),0);if(size<0)return 2;
    printf("{\"source\":\"TCX_DISPATCH_FIXTURE_NOT_KERNEL\",\"native\":false,\"attach\":%d,"
        "\"stop\":%d,\"cleanup\":%d,\"active\":%d,\"created\":%d,\"removed\":%d,"
        "\"foreign\":%d,\"phase\":%d,\"approval\":\"",first,stopped,cleaned,
        fake.active,fake.created,fake.removed,fake.foreign,l.phase);
    for(int i=0;i<32;i++)printf("%02x",s.plan.approval[i]);
    printf("\",\"journal\":\"");for(ssize_t i=0;i<size;i++)printf("%02x",body[i]);puts("\"}");
    close(fd);close(sockets[0]);close(sockets[1]);return 0;
}
