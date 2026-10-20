#define _GNU_SOURCE
/* x86-64 syscall-only entry. No libc, ELF interpreter, DSO, NSS or PAM here.
 * No custom setuid installation or privilege-raising implementation remains.
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
#ifdef SOC_ENTRY_FIXTURE_TARGET
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
    /* Custom SUID/PAM entry removed. OS-authenticated handoff is not yet
     * qualified. No runtime flag, manifest or root invocation enables an exec. */
    static const char denied[]="EBPF_B2I_NATIVE_ENTRY_BLOCKED\n";message(denied,sizeof(denied)-1);finish(2);
#endif
}
__asm__(".global _start\n_start:\nmov %rsp,%rdi\nand $-16,%rsp\ncall soc_entry_start\nud2\n");
