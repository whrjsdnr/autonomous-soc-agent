#define _GNU_SOURCE
/* x86-64 syscall-only entry. No libc, ELF interpreter, DSO, NSS or PAM here.
 * Never installed/executed privileged during qualification. Native gate is CLOSED.
 * The fixture build is a separate, ordinary-UID executable with a fixed harmless
 * compile-time target; it cannot create an entry proof or run as root. */
#include "native.h"
#include <asm/unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/memfd.h>
static long call(long nr,long a,long b,long c,long d,long e,long f) {
    register long r10 __asm__("r10")=d,r8 __asm__("r8")=e,r9 __asm__("r9")=f;
    long out;__asm__ volatile("syscall":"=a"(out):"a"(nr),"D"(a),"S"(b),"d"(c),
        "r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");return out;
}
#ifndef SOC_ENTRY_FIXTURE_TARGET
static int equal(const char *a,const char *b) {while(*a && *a==*b){a++;b++;}return *a==*b;}
#endif
__attribute__((noreturn)) static void finish(int code) {call(__NR_exit_group,code,0,0,0,0,0);for(;;){}}
#ifndef SOC_ENTRY_FIXTURE_TARGET
static void message(const char *s,unsigned n) {call(__NR_write,2,(long)s,n,0,0,0);}
#endif
static long clean_exec(int fd,char *const argv[]) {
    /* Exec preserves blocked signals and ignored dispositions. Reset them before
     * PAM's dynamic image starts so a polluted parent cannot disable its alarm. */
    struct {unsigned long handler,flags,restorer,mask;} action={0};
    for(int signal=1;signal<=64;signal++) {
        if(signal==9 || signal==19)continue; /* SIGKILL / SIGSTOP */
        if(call(__NR_rt_sigaction,signal,(long)&action,0,8,0,0))return -1;
    }
    unsigned long mask=0;
    if(call(__NR_rt_sigprocmask,2,(long)&mask,0,8,0,0) || /* SIG_SETMASK */
       call(__NR_chdir,(long)"/",0,0,0,0,0))return -1;
    call(__NR_alarm,0,0,0,0,0,0);call(__NR_umask,077,0,0,0,0,0);
    char *const env[]={"PATH=/usr/bin:/bin","LANG=C",0};
    return call(__NR_execveat,fd,(long)"",(long)argv,(long)env,AT_EMPTY_PATH,0);
}
#ifndef SOC_ENTRY_FIXTURE_TARGET
static const volatile int native_entry_qualified=0;
static int trusted(int parent,const char *name,int directory,unsigned mode) {
    long fd=call(__NR_openat,parent,(long)name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|
        (directory?O_DIRECTORY:O_NONBLOCK),0,0,0);struct stat st;
    if(fd<0)return -1;
    if(call(__NR_fstat,fd,(long)&st,0,0,0,0) || st.st_uid || st.st_gid ||
       (st.st_mode&022) || (directory?!S_ISDIR(st.st_mode):
        (!S_ISREG(st.st_mode) || st.st_nlink!=1 || (st.st_mode&07777)!=mode ||
         st.st_size<1 || st.st_size>1048576))) {
        call(__NR_close,fd,0,0,0,0,0);return -1;
    }return fd;
}
static int native_entry(unsigned long *stack) {
    /* Separate compile-time gate; no environment, argv or manifest opens it. */
    if(!native_entry_qualified)return -1;
    unsigned uid=call(__NR_getuid,0,0,0,0,0,0),gid=call(__NR_getgid,0,0,0,0,0,0);
    if(!uid || !gid || call(__NR_getegid,0,0,0,0,0,0)!=gid ||
       call(__NR_geteuid,0,0,0,0,0,0)!=0 || stack[0]!=1)return -1;
    unsigned long *aux=stack+stack[0]+2;unsigned i=0;
    while(*aux && i++<4096)aux++;
    if(*aux)return -1;aux++;int secure=0;
    for(i=0;aux[0] && i<64;i++,aux+=2)if(aux[0]==23)secure=aux[1]==1; /* AT_SECURE */
    if(i==64 || !secure)return -1;
    int root=trusted(AT_FDCWD,"/",1,0);if(root<0)return -1;
    const char *parts[]={"usr","libexec","soc-agent-ebpf"};
    for(i=0;i<3;i++) {int next=trusted(root,parts[i],1,0);call(__NR_close,root,0,0,0,0,0);
        if(next<0)return -1;root=next;}
    int self=trusted(root,"entry",0,04755),helper=trusted(root,"bootstrap",0,0555);
    call(__NR_close,root,0,0,0,0,0);if(self<0 || helper<0)return -1;
    int running=call(__NR_openat,AT_FDCWD,(long)"/proc/self/exe",O_RDONLY|O_CLOEXEC,0,0,0);
    struct stat a,b;if(running<0 || call(__NR_fstat,self,(long)&a,0,0,0,0) ||
       call(__NR_fstat,running,(long)&b,0,0,0,0) || a.st_dev!=b.st_dev || a.st_ino!=b.st_ino)return -1;
    call(__NR_close,self,0,0,0,0,0);call(__NR_close,running,0,0,0,0,0);
    /* Proof is NOT authentication. Only this entry creates it, before fresh PAM.
     * Root ownership, seals, PID and exact envelope bind it to this one exec. */
    struct soc_entry_proof proof={.magic=SOC_ENTRY_MAGIC,.uid=uid,.gid=gid,
        .pid=call(__NR_getpid,0,0,0,0,0,0)};
    if(call(__NR_pread64,4,(long)&proof.envelope,sizeof(proof.envelope),0,0,0)!=sizeof(proof.envelope))return -1;
    int fd=call(__NR_memfd_create,(long)"soc-entry-not-auth",MFD_ALLOW_SEALING,0,0,0,0);
    if(fd<0 || call(__NR_write,fd,(long)&proof,sizeof(proof),0,0,0)!=sizeof(proof) ||
       call(__NR_fcntl,fd,F_ADD_SEALS,15,0,0,0)<0)return -1;
    int executable=call(__NR_fcntl,helper,F_DUPFD_CLOEXEC,64,0,0,0);
    if(executable!=64 || call(__NR_dup2,fd,SOC_ENTRY_PROOF_FD,0,0,0,0)<0)return -1;
    /* Fixed input FDs 3/4/6 only. No arbitrary paths or caller-selected commands. */
    call(__NR_close,5,0,0,0,0,0);
    if(call(__NR_close_range,7,30,0,0,0,0) || call(__NR_close_range,32,63,0,0,0,0) ||
       call(__NR_close_range,65,~0U,0,0,0,0))return -1;
    char *const args[]={"bootstrap","3","4","6",0};
    return clean_exec(64,args);
}
#endif
__attribute__((noreturn)) void soc_entry_start(unsigned long *stack) {
#ifdef SOC_ENTRY_FIXTURE_TARGET
    /* Ordinary-UID static exec fixture, never an installed/native entry. */
    long uid=call(__NR_getuid,0,0,0,0,0,0);
    if(!uid || uid!=call(__NR_geteuid,0,0,0,0,0,0) || stack[0]!=1)finish(2);
    int fd=call(__NR_openat,AT_FDCWD,(long)SOC_ENTRY_FIXTURE_TARGET,O_RDONLY|O_NOFOLLOW,0,0,0);
    char *const args[]={"entry-child-fixture",0};
    if(fd>=0)clean_exec(fd,args);finish(2);
#else
    char **argv=(char **)(stack+1);
    if(stack[0]==2 && equal(argv[1],"--inspect") && call(__NR_getuid,0,0,0,0,0,0)>0 &&
       call(__NR_getuid,0,0,0,0,0,0)==call(__NR_geteuid,0,0,0,0,0,0)) {
        static const char text[]="{\"entry\":\"STATIC_SYSCALL_ONLY\",\"native_gate\":false}\n";
        call(__NR_write,1,(long)text,sizeof(text)-1,0,0,0);finish(0);
    }
    native_entry(stack);
    static const char denied[]="EBPF_B2I_NATIVE_ENTRY_BLOCKED\n";message(denied,sizeof(denied)-1);finish(2);
#endif
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nand $-16,%rsp\ncall soc_entry_start\nud2\n");
