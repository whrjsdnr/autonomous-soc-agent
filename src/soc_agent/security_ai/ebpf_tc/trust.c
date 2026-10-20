#define _GNU_SOURCE
#include "native.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <openssl/evp.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/* No caller-selected root, UID, policy, environment or execution path. */
static int nonzero(const uint8_t *p,size_t n) {for(size_t i=0;i<n;i++)if(p[i])return 1;return 0;}
static int version(const char v[16]) {
    if(!memchr(v,0,16))return 0;
    int groups=0,digits=0;
    for(int i=0;i<16;i++) {
        if(v[i]>='0' && v[i]<='9') {if(++digits>4)return 0;}
        else if(v[i]=='.') {if(!digits || ++groups>2)return 0;digits=0;}
        else if(!v[i]) {if(groups!=2 || !digits)return 0;
            for(int j=i;j<16;j++)if(v[j])return 0;return 1;}
        else return 0;
    }return 0;
}
int soc_envelope_validate(const struct soc_release_envelope *e) {
    if(!e || soc_plan_validate(&e->plan) || e->plan.version!=SOC_TCX_VERSION ||
       !nonzero(e->manifest_sha,32) || !version(e->release_version))return -EPERM;
    struct soc_release_envelope copy=*e;uint8_t hash[32];memset(copy.approval,0,32);
    return soc_sha(&copy,sizeof(copy),hash) || memcmp(hash,e->approval,32)?-EPERM:0;
}
static int allowed_path(const char p[256]) {
    const char *end=memchr(p,0,256);if(!end || p[0]!='/' || strstr(p,"//") ||
        strstr(p,"/../") || strstr(p,"/./") || end==p || end[-1]=='/')return 0;
    for(const char *c=end;c<p+256;c++)if(*c)return 0;
    if(!strcmp(p,"/etc/nsswitch.conf") || !strcmp(p,"/etc/ld.so.cache") ||
       !strcmp(p,"/etc/pam.d/soc-agent-ebpf"))return 1;
    return !strncmp(p,"/usr/lib/",9) || !strncmp(p,"/usr/lib64/",11);
}
int soc_trust_parse(const void *body,size_t size,const struct soc_plan *p,
                    const uint8_t expected[32],const char v[16]) {
    if(!body || !p || !expected || !v || size<sizeof(struct soc_trust_header))return -EPERM;
    struct soc_trust_header h;memcpy(&h,body,sizeof(h));
    if(memcmp(h.magic,"SOCRC001",8) || h.schema!=1 || h.count<3 || h.count>72 ||
       size!=sizeof(h)+h.count*sizeof(struct soc_trust_record) || h.native_release ||
       h.dynamic_closure || !version(h.release_version) || memcmp(v,h.release_version,16) ||
       !nonzero(expected,32) || memcmp(h.manifest_sha,expected,32))return -EPERM;
    uint8_t hashes[160];memcpy(hashes,p->bootstrap_sha,32);memcpy(hashes+32,p->broker_sha,32);
    memcpy(hashes+64,p->loader_sha,32);memcpy(hashes+96,p->program_sha,32);
    memcpy(hashes+128,p->bundle_sha,32);if(memcmp(h.artifacts,hashes,160))return -EPERM;
    uint64_t total=0;char previous[256]={0};unsigned mandatory=0;
    for(uint32_t i=0;i<h.count;i++) {
        struct soc_trust_record r;memcpy(&r,(const char *)body+sizeof(h)+i*sizeof(r),sizeof(r));
        if(!allowed_path(r.path) || (i && strcmp(previous,r.path)>=0) || !r.size ||
           r.size>16777216 || !nonzero(r.sha,32) || r.reserved ||
           r.mode&~0777U || r.mode&022 || (total+=r.size)>67108864)return -EPERM;
        if(!strcmp(r.path,"/etc/nsswitch.conf"))mandatory|=1;
        if(!strcmp(r.path,"/etc/ld.so.cache"))mandatory|=2;
        if(!strcmp(r.path,"/etc/pam.d/soc-agent-ebpf"))mandatory|=4;
        memcpy(previous,r.path,256);
    }return mandatory==7?0:-EPERM;
}
static int hash_fd(int fd,const uint8_t expected[32],uint64_t size,unsigned mode) {
    struct stat a,b;if(fstat(fd,&a) || !S_ISREG(a.st_mode) || a.st_uid || a.st_gid ||
        a.st_nlink!=1 || (a.st_mode&07777)!=mode || a.st_size!=(off_t)size ||
        !size || size>16777216)return -EPERM;
    EVP_MD_CTX *ctx=EVP_MD_CTX_new();if(!ctx)return -ENOMEM;
    int ok=EVP_DigestInit_ex(ctx,EVP_sha256(),NULL);uint8_t buffer[8192],hash[32];
    for(uint64_t offset=0;ok && offset<size;) {
        size_t count=size-offset<sizeof(buffer)?size-offset:sizeof(buffer);
        ssize_t n=pread(fd,buffer,count,offset);if(n!=(ssize_t)count) {ok=0;break;}
        ok=EVP_DigestUpdate(ctx,buffer,count);offset+=count;
    }
    unsigned length=0;ok=ok && EVP_DigestFinal_ex(ctx,hash,&length);EVP_MD_CTX_free(ctx);
    return !ok || length!=32 || memcmp(hash,expected,32) || fstat(fd,&b) ||
        a.st_dev!=b.st_dev || a.st_ino!=b.st_ino || a.st_size!=b.st_size ||
        a.st_mode!=b.st_mode || a.st_nlink!=b.st_nlink ||
        a.st_mtim.tv_sec!=b.st_mtim.tv_sec || a.st_mtim.tv_nsec!=b.st_mtim.tv_nsec ||
        a.st_ctim.tv_sec!=b.st_ctim.tv_sec || a.st_ctim.tv_nsec!=b.st_ctim.tv_nsec?-EPERM:0;
}
int soc_release_check(const struct soc_plan *p,const uint8_t expected[32],const char v[16],int stage) {
    if(!p || stage<1 || stage>3)return -EPERM;
    int fd=soc_trusted(SOC_INSTALL "release.trust",NULL);struct stat st;
    if(fd<0)return -EPERM;
    unsigned char body[232+72*304];
    int rc=fstat(fd,&st) || st.st_gid || (st.st_mode&07777)!=0444 ||
        st.st_size<232 || st.st_size>(off_t)sizeof(body)?-EPERM:0;
    if(!rc && pread(fd,body,st.st_size,0)!=st.st_size)rc=-EIO;close(fd);
    if(rc || soc_trust_parse(body,st.st_size,p,expected,v))return -EPERM;
    /* release.trust is the bounded execution schema compiled from strict release.json.
     * Both must be in the same root-owned quiescent installation. Neither opens the gate. */
    fd=soc_trusted(SOC_INSTALL "release.json",expected);
    if(fd<0)return -EPERM;
    rc=fstat(fd,&st) || st.st_gid || (st.st_mode&07777)!=0444 || st.st_size>65536;
    close(fd);if(rc)return -EPERM;
    struct soc_trust_header h;memcpy(&h,body,sizeof(h));
    for(uint32_t i=0;i<h.count;i++) {
        struct soc_trust_record r;memcpy(&r,body+sizeof(h)+i*sizeof(r),sizeof(r));
        fd=soc_trusted(r.path,NULL);if(fd<0)return -EPERM;
        rc=hash_fd(fd,r.sha,r.size,r.mode);close(fd);if(rc)return rc;
    }
    /* Refuse preload configuration rather than attempting an incomplete parser. */
    struct stat preload;if(!lstat("/etc/ld.so.preload",&preload) || errno!=ENOENT)return -EPERM;
    const char *names[]={"bootstrap","broker","libnative-tc.so","tc.bpf.o"};
    unsigned modes[]={04755,0555,0444,0444};
    for(int i=0;i<4;i++) {
        char path[256];snprintf(path,sizeof(path),"%s%s",SOC_INSTALL,names[i]);
        fd=soc_trusted(path,h.artifacts+32*i);if(fd<0)return -EPERM;
        rc=fstat(fd,&st) || st.st_gid || (st.st_mode&07777)!=modes[i];
        if(!rc && i==(stage==1?0:1)) {
            int self=open("/proc/self/exe",O_RDONLY|O_CLOEXEC);struct stat actual;
            rc=self<0 || fstat(self,&actual) || actual.st_dev!=st.st_dev || actual.st_ino!=st.st_ino;
            if(self>=0)close(self);
        }
        close(fd);if(rc)return -EPERM;
    }return 0;
}
int soc_capability_contract(uint64_t effective,uint64_t permitted,uint64_t inheritable,
                           uint64_t ambient,uint64_t bounding) {
    uint64_t expected=(1ULL<<CAP_BPF)|(1ULL<<CAP_NET_ADMIN);
    return effective==expected && permitted==expected && inheritable==expected &&
        ambient==expected && bounding==expected?0:-EPERM;
}
int soc_capabilities(void) {
    struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct d[2]={{0}};
    if(syscall(SYS_capget,&h,d) || !getuid() || getuid()!=geteuid() ||
       prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1)return -EPERM;
    uint64_t ambient=0,bounding=0;
    for(int i=0;i<=CAP_LAST_CAP;i++) {
        int a=prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_IS_SET,i,0,0),b=prctl(PR_CAPBSET_READ,i,0,0,0);
        if(a<0 || b<0)return -EPERM;
        if(a)ambient|=1ULL<<i;if(b)bounding|=1ULL<<i;
    }
    return soc_capability_contract(d[0].effective|((uint64_t)d[1].effective<<32),
        d[0].permitted|((uint64_t)d[1].permitted<<32),
        d[0].inheritable|((uint64_t)d[1].inheritable<<32),ambient,bounding);
}

int soc_release_record(struct soc_state *s) {
    struct {uint8_t plan[32];char kind[32];uint8_t manifest[32];char version[16];
        uint8_t scope[32];uint32_t sequence,ordinal;uint8_t previous[32],sha[32];} row={0};
    _Static_assert(sizeof(row)==216,"release journal ABI");
    if(!s || !nonzero(s->release_sha,32) || !version(s->release_version) ||
       s->audit_records>=1024)return -EPERM;
    memcpy(row.plan,s->plan.approval,32);memcpy(row.kind,"RC_RELEASE_VERIFIED",19);
    memcpy(row.manifest,s->release_sha,32);memcpy(row.version,s->release_version,16);
    if(soc_sha(&s->plan,sizeof(s->plan),row.scope))return -EIO;
    row.sequence=s->sequence;row.ordinal=s->audit_records+1;memcpy(row.previous,s->audit_previous,32);
    if(soc_sha(&row,sizeof(row)-32,row.sha) ||
       write(s->audit_fd,&row,sizeof(row))!=sizeof(row) || fsync(s->audit_fd))return -EIO;
    memcpy(s->audit_previous,row.sha,32);s->audit_records++;return 0;
}
