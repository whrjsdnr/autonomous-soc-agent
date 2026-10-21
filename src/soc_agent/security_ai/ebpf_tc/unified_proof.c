/* Same authenticated process: isolated SHA-pinned installation image -> Bootstrap.
 * Ordinary Controller assertions cannot create a Root-owned sealed authority FD.
 */
#define _GNU_SOURCE
#include "unified.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static int own_ticks(uint64_t *ticks) {
    char line[4096];int fd=open("/proc/self/stat",O_RDONLY|O_CLOEXEC);
    if(fd<0)return -EPERM;ssize_t n=read(fd,line,sizeof(line)-1);close(fd);
    if(n<=0)return -EPERM;line[n]=0;char *end=strrchr(line,')'),*save=NULL;
    if(!end)return -EPERM;char *word=strtok_r(end+2," ",&save);
    for(int i=0;word;i++,word=strtok_r(NULL," ",&save))if(i==19){*ticks=strtoull(word,NULL,10);return 0;}
    return -EPERM;
}
static int sudo_python_parent(const uint8_t expected[32]) {
    int trusted=soc_trusted("/usr/bin/sudo",NULL);struct stat a,b;char path[64];
    snprintf(path,sizeof(path),"/proc/%u/exe",getppid());
    int bad=trusted<0 || fstat(trusted,&a) || stat(path,&b) ||
        a.st_dev!=b.st_dev || a.st_ino!=b.st_ino;
    if(trusted>=0)close(trusted);if(bad)return -EPERM;
    snprintf(path,sizeof(path),"/proc/%u/cmdline",getppid());
    int fd=open(path,O_RDONLY|O_CLOEXEC);char arguments[16384];
    if(fd<0)return -EPERM;ssize_t n=read(fd,arguments,sizeof(arguments));close(fd);
    if(n<1 || n>=(ssize_t)sizeof(arguments) || arguments[n-1])return -EPERM;
    const char *fixed[]={"-k","-u","root","--","/usr/bin/python3","-I","-S","-c"};
    size_t offset=strnlen(arguments,n)+1;
    for(unsigned i=0;i<sizeof(fixed)/sizeof(*fixed);i++) {
        if(offset>=(size_t)n || strcmp(arguments+offset,fixed[i]))return -EPERM;
        offset+=strlen(arguments+offset)+1;
    }
    if(offset>=(size_t)n || offset+strlen(arguments+offset)+1!=(size_t)n)return -EPERM;
    uint8_t hash[32];return soc_sha(arguments+offset,strlen(arguments+offset),hash) ||
        memcmp(hash,expected,32)?-EPERM:0;
}
int soc_unified_proof_read(struct soc_unified_proof *proof,unsigned uid,unsigned gid,
    const uint8_t app[16],const uint8_t approval[32],const uint8_t manifest[32],const uint8_t purpose[32]) {
    int fd=SOC_UNIFIED_PROOF_FD,seals=fcntl(fd,F_GET_SEALS);struct stat st;uint64_t ticks=0;
    if(getuid() || geteuid() || getgid() || getegid() ||
       fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_uid || st.st_gid ||
       st.st_nlink || st.st_size!=sizeof(*proof) || seals<0 || (seals&15)!=15 ||
       pread(fd,proof,sizeof(*proof),0)!=sizeof(*proof))return -EPERM;
    uint64_t now=soc_now();uint8_t zero[32]={0};
    if(memcmp(proof->magic,"SOCUNP01",8) || proof->version!=1 || proof->pid!=(uint32_t)getpid() ||
       own_ticks(&ticks) || ticks!=proof->ticks || !proof->issued_ns || proof->issued_ns>now ||
       now-proof->issued_ns>15000000000ULL || !memcmp(proof->image_sha,zero,32) ||
       soc_envelope_validate(&proof->envelope) ||
       proof->envelope.plan.uid!=uid || proof->envelope.plan.gid!=gid ||
       memcmp(proof->envelope.plan.application,app,16) ||
       memcmp(proof->envelope.approval,approval,32) ||
       memcmp(proof->envelope.manifest_sha,manifest,32))return -EPERM;
    const char label[]="SOC_UNIFIED_SESSION_V1";
    uint8_t body[sizeof(label)+sizeof(proof->envelope)+64],hash[32];
    memcpy(body,label,sizeof(label));memcpy(body+sizeof(label),&proof->envelope,sizeof(proof->envelope));
    memcpy(body+sizeof(label)+sizeof(proof->envelope),proof->image_sha,32);
    memcpy(body+sizeof(label)+sizeof(proof->envelope)+32,proof->previous_manifest,32);
    if(soc_sha(body,sizeof(body),hash) || memcmp(hash,purpose,32) ||
       memcmp(hash,proof->approval,32) || sudo_python_parent(proof->command_sha) ||
       soc_os_password_policy_only(uid,gid))return -EPERM;
    return close(fd)?-EPERM:0;
}
