#define _GNU_SOURCE
#include "native.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <link.h>
#include <limits.h>
#include <sys/sysmacros.h>
#include <sys/auxv.h>
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
    if(!strcmp(p,SOC_INSTALL "entry"))return 1;
    if(!strcmp(p,"/etc/nsswitch.conf") || !strcmp(p,"/etc/ld.so.cache"))return 1;
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
           (strcmp(r.path,SOC_INSTALL "entry")?r.mode&~0777U:r.mode!=0555) || r.mode&022 || (total+=r.size)>67108864)return -EPERM;
        if(!strcmp(r.path,SOC_INSTALL "entry"))mandatory|=8;
        if(!strcmp(r.path,"/etc/nsswitch.conf"))mandatory|=1;
        if(!strcmp(r.path,"/etc/ld.so.cache"))mandatory|=2;
        memcpy(previous,r.path,256);
    }return mandatory==11?0:-EPERM;
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
/* Compare a mapped file-backed segment with the held verified inode. This is
 * post-map evidence, not proof that pre-main constructors were safe. */
static int mapped_inode(const struct dl_phdr_info *info,const struct stat *st) {
    uintptr_t address=0;int found=0;
    for(ElfW(Half) i=0;i<info->dlpi_phnum;i++)if(info->dlpi_phdr[i].p_type==PT_LOAD &&
        info->dlpi_phdr[i].p_filesz) {address=info->dlpi_addr+info->dlpi_phdr[i].p_vaddr;found=1;break;}
    if(!found)return -EPERM;
    FILE *maps=fopen("/proc/self/maps","re");if(!maps)return -EPERM;
    char line[512];int result=-EPERM;unsigned lines=0;
    while(fgets(line,sizeof(line),maps)) {
        if(++lines>2048 || !strchr(line,'\n'))break;
        unsigned long lo,hi,offset,inode;unsigned dev_major,dev_minor;char perms[5];
        if(sscanf(line,"%lx-%lx %4s %lx %x:%x %lu",&lo,&hi,perms,&offset,
            &dev_major,&dev_minor,&inode)!=7)break;
        if(address>=lo && address<hi) {
            result=inode==(unsigned long)st->st_ino && dev_major==major(st->st_dev) &&
                dev_minor==minor(st->st_dev)?0:-EPERM;break;
        }
    }fclose(maps);return result;
}
static int trusted_mapping_name(const char *name) {
    if(strncmp(name,"/lib/",5) && strncmp(name,"/lib64/",7) &&
       strncmp(name,"/usr/lib/",9) && strncmp(name,"/usr/lib64/",11))return -EPERM;
    if(strlen(name)>=256 || strstr(name,"//") || strstr(name,"/../") || strstr(name,"/./"))return -EPERM;
    char path[256];strcpy(path,name);
    /* Permit root-owned distribution aliases such as /lib -> usr/lib, while
     * rejecting user-owned/mutable named parents before canonical FD checks. */
    for(char *c=path+1;;c++)if(*c=='/' || !*c) {
        char saved=*c;*c=0;struct stat named,resolved;
        int rc=lstat(path,&named) || named.st_uid || named.st_gid ||
            stat(path,&resolved) || resolved.st_uid || resolved.st_gid || (resolved.st_mode&022);
        *c=saved;if(rc)return -EPERM;if(!saved)break;
    }return 0;
}
struct mapping_check {const unsigned char *body;uint32_t count,seen;};
static int mapping_callback(struct dl_phdr_info *info,size_t size,void *context) {
    (void)size;struct mapping_check *check=context;
    if(++check->seen>128)return 1;
    const char *name=info->dlpi_name;
    /* Main executable has its own root-owned inode check. vDSO is kernel-provided,
     * explicitly outside disk dependency attestation, never a zero-drop claim. */
    if(!name || !*name || !strcmp(name,"linux-vdso.so.1"))return 0;
    if(trusted_mapping_name(name))return 1;
    char canonical[PATH_MAX];if(!realpath(name,canonical) || strlen(canonical)>=256)return 1;
    for(uint32_t i=0;i<check->count;i++) {
        struct soc_trust_record r;
        memcpy(&r,check->body+sizeof(struct soc_trust_header)+i*sizeof(r),sizeof(r));
        if(strcmp(r.path,canonical))continue;
        int fd=soc_trusted(canonical,NULL);if(fd<0)return 1;
        struct stat st;int rc=fstat(fd,&st) || hash_fd(fd,r.sha,r.size,r.mode) || mapped_inode(info,&st);
        close(fd);return rc?1:0;
    }return 1;
}
/* Process-wide snapshot includes dlmopen/LD_AUDIT namespaces. It is not a
 * history of executed code: a constructor may already have run/unmapped. */
static int executable_maps(const struct mapping_check *check) {
    struct stat main_file;if(stat("/proc/self/exe",&main_file))return -EPERM;
    FILE *maps=fopen("/proc/self/maps","re");if(!maps)return -EPERM;
    char line[1024];unsigned lines=0;int result=0;
    while(fgets(line,sizeof(line),maps)) {
        unsigned long lo,hi,offset,inode;unsigned ma,mi;char perms[5];int used=0;
        if(++lines>2048 || !strchr(line,'\n') ||
           sscanf(line,"%lx-%lx %4s %lx %x:%x %lu %n",&lo,&hi,perms,&offset,
                  &ma,&mi,&inode,&used)!=7 || !used || lo>=hi) {result=-EPERM;break;}
        if(!strchr(perms,'x'))continue;
        char *name=line+used;name[strcspn(name,"\n")]=0;
        if(!strcmp(name,"[vdso]") && lo==getauxval(AT_SYSINFO_EHDR))continue;
#if defined(__x86_64__)
        if(!strcmp(name,"[vsyscall]") && lo==0xffffffffff600000UL &&
           hi==0xffffffffff601000UL)continue;
#endif
        if(!inode || name[0]!='/' || strstr(name," (deleted)") || strstr(name,"/memfd:")) {
            result=-EPERM;break;
        }
        /* Self is independently root-owned, SHA/inode verified at each release entry. */
        if(inode==(unsigned long)main_file.st_ino && ma==major(main_file.st_dev) &&
           mi==minor(main_file.st_dev))continue;
        if(trusted_mapping_name(name)) {result=-EPERM;break;}
        char canonical[PATH_MAX];if(!realpath(name,canonical)) {result=-EPERM;break;}
        int matched=0;
        for(uint32_t i=0;i<check->count;i++) {
            struct soc_trust_record record;
            memcpy(&record,check->body+sizeof(struct soc_trust_header)+i*sizeof(record),sizeof(record));
            if(strcmp(record.path,canonical))continue;
            int fd=soc_trusted(canonical,NULL);struct stat st;
            if(fd<0) {result=-EPERM;break;}
            int bad=fstat(fd,&st) || inode!=(unsigned long)st.st_ino || ma!=major(st.st_dev) ||
                mi!=minor(st.st_dev) || hash_fd(fd,record.sha,record.size,record.mode);
            close(fd);if(bad)result=-EPERM;else matched=1;break;
        }
        if(result || !matched) {result=-EPERM;break;}
    }
    if(ferror(maps))result=-EPERM;fclose(maps);return result;
}
/* This array is passed to a NEW exec, never an inherited environment edited in
 * place. Pre-main trust at the setuid entry still requires kernel AT_SECURE. */
char *const *soc_clean_environment(void) {
    static char *const clean[]={"PATH=/usr/bin:/bin","LANG=C",NULL};return clean;
}
int soc_environment_contract(char *const env[]) {
    if(!env)return -EPERM;
    unsigned seen=0;
    for(unsigned i=0;i<3;i++) {
        if(!env[i])return seen==3?0:-EPERM;
        unsigned flag=!strcmp(env[i],"PATH=/usr/bin:/bin")?1:!strcmp(env[i],"LANG=C")?2:0;
        if(!flag || (seen&flag))return -EPERM;seen|=flag;
    }return -EPERM;
}
int soc_mapped_dependencies(const void *body,size_t size) {
    if(!body || size<sizeof(struct soc_trust_header))return -EPERM;
    struct soc_trust_header h;memcpy(&h,body,sizeof(h));
    if(memcmp(h.magic,"SOCRC001",8) || h.schema!=1 || !h.count || h.count>72 ||
       h.native_release || h.dynamic_closure ||
       size!=sizeof(h)+h.count*sizeof(struct soc_trust_record))return -EPERM;
    for(uint32_t i=0;i<h.count;i++) {
        struct soc_trust_record r;memcpy(&r,(const char *)body+sizeof(h)+i*sizeof(r),sizeof(r));
        if(!allowed_path(r.path) || !r.size || r.size>16777216 || (strcmp(r.path,SOC_INSTALL "entry")?r.mode&~0777U:r.mode!=0555) ||
           r.mode&022 || r.reserved || !nonzero(r.sha,32))return -EPERM;
    }
    struct mapping_check check={body,h.count,0};
    return dl_iterate_phdr(mapping_callback,&check)?-EPERM:executable_maps(&check);
}
int soc_account_identity(uid_t uid,gid_t gid,uid_t found_uid,gid_t found_gid,int found) {
    return uid && gid && found==1 && uid==found_uid && gid==found_gid?0:-EPERM;
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
    size_t descriptor_size=st.st_size;
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
    unsigned modes[]={0555,0555,0444,0444};
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
    }return soc_mapped_dependencies(body,descriptor_size);
}
int soc_capability_contract(uint64_t effective,uint64_t permitted,uint64_t inheritable,
                           uint64_t ambient,uint64_t bounding) {
    uint64_t expected=(1ULL<<CAP_BPF)|(1ULL<<CAP_NET_ADMIN);
    return effective==expected && permitted==expected && inheritable==expected &&
        ambient==expected && bounding==expected?0:-EPERM;
}
int soc_process_identity(uid_t r,uid_t e,uid_t saved,gid_t gr,gid_t ge,gid_t gs,int groups) {
    return r && gr && r==e && e==saved && gr==ge && ge==gs && groups==0?0:-EPERM;
}
int soc_capabilities(void) {
    struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct d[2]={{0}};
    uid_t r,e,saved;gid_t gr,ge,gs;
    if(getresuid(&r,&e,&saved) || getresgid(&gr,&ge,&gs) ||
       soc_process_identity(r,e,saved,gr,ge,gs,getgroups(0,NULL)))return -EPERM;
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

/* Execution transfer needs ambient rights only until the fixed Broker exec.
 * The Broker then clears I/A and keeps E=0 except for explicit Load/Attach. */
int soc_broker_capability_contract(uint64_t e,uint64_t p,uint64_t i,uint64_t a,uint64_t b,int work) {
    uint64_t mask=(1ULL<<CAP_BPF)|(1ULL<<CAP_NET_ADMIN);
    return (work==0 || work==1) && e==(work?mask:0) && p==mask && !i && !a && b==mask?0:-EPERM;
}
int soc_broker_capabilities(int work) {
    struct __user_cap_header_struct h={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct d[2]={{0}};uid_t r,e,s;gid_t gr,ge,gs;
    if(getresuid(&r,&e,&s) || getresgid(&gr,&ge,&gs) ||
       soc_process_identity(r,e,s,gr,ge,gs,getgroups(0,NULL)) ||
       prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1 || syscall(SYS_capget,&h,d))return -EPERM;
    uint64_t ambient=0,bounding=0;
    for(int cap=0;cap<=CAP_LAST_CAP;cap++) {
        int a=prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_IS_SET,cap,0,0),b=prctl(PR_CAPBSET_READ,cap,0,0,0);
        if(a<0 || b<0)return -EPERM;
        if(a)ambient|=1ULL<<cap;if(b)bounding|=1ULL<<cap;
    }
    return soc_broker_capability_contract(d[0].effective|((uint64_t)d[1].effective<<32),
        d[0].permitted|((uint64_t)d[1].permitted<<32),
        d[0].inheritable|((uint64_t)d[1].inheritable<<32),ambient,bounding,work);
}
