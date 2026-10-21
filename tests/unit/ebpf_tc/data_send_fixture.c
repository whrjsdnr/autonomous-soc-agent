#include "native.h"
#include "data.h"
#include <openssl/sha.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/time.h>
static int partial;
ssize_t __real_send(int,const void *,size_t,int);
ssize_t __wrap_send(int fd,const void *body,size_t size,int flags) {
 if(partial) {partial=0;return 17;} /* fault injection only, never partial retry */
 return __real_send(fd,body,size,flags);
}
int soc_sha(const void *b,size_t n,uint8_t out[32]) {return SHA256(b,n,out)?0:-1;}
uint64_t soc_now(void) {struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;}
int soc_handoff_connect_data(uid_t u,gid_t g,const uint8_t s[16]) {(void)u;(void)g;(void)s;return -1;}
int soc_peer(int f,const struct soc_plan *p) {(void)f;(void)p;return 0;}
int main(int argc,char **argv) {
 if(getuid()==0 || (argc!=2 && argc!=3))return 2;
 int pair[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET,0,pair))return 3;
 const char *mode=argc==3?argv[2]:"closed";pid_t child=0;
 if(!strcmp(mode,"closed")) {close(pair[1]);pair[1]=-1;}
 if(!strcmp(mode,"partial"))partial=1;
 if(!strcmp(mode,"slow") || !strcmp(mode,"blocked")) {
  int bytes=4096;setsockopt(pair[0],SOL_SOCKET,SO_SNDBUF,&bytes,sizeof(bytes));
  char junk[192]={0};int full=0;
  for(int i=0;i<128;i++)if(send(pair[0],junk,sizeof(junk),MSG_DONTWAIT)<0) {full=errno==EAGAIN;break;}
  if(!full)return 5;
  if(!strcmp(mode,"slow")) {
   child=fork();if(child<0)return 6;
   if(!child) {
    close(pair[0]);usleep(20000);struct timeval timeout={0,200000};
    setsockopt(pair[1],SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));int closed=0;
    for(int i=0;i<256;i++) {struct soc_data_row row={0};
     if(recv(pair[1],&row,sizeof(row),0)!=(ssize_t)sizeof(row))break;
     if(row.magic==SOC_DATA_MAGIC && row.kind==SOC_DATA_CLOSED) {closed=1;break;}
    }close(pair[1]);_exit(closed?0:7);
   }
  }
 }
 int audit=open(argv[1],O_WRONLY|O_CREAT|O_EXCL|O_APPEND,0600);if(audit<0)return 4;
 struct soc_state s={.audit_fd=audit,.data_fd=pair[0],.data_source=2,.generation=7};
 s.plan.ifindex=1;s.plan.hook=1;memset(s.plan.approval,0xaa,32);
 struct soc_event e={.generation=7,.ifindex=1,.hook=1};
 int rc=soc_data_emit(&s,&e,sizeof(e));printf("%d\n",rc);
 struct soc_counters counters={.observed=1,.emitted=1};
 s.stopping=1;soc_data_counters(&s,&counters,1,rc?0:1);soc_data_close(&s);
 if(pair[1]>=0)close(pair[1]);close(audit);
 if(child) {int status=0;waitpid(child,&status,0);if(!WIFEXITED(status) || WEXITSTATUS(status))return 8;}
 return 0;
}
