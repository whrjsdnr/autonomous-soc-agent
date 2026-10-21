#include "native.h"
#include "data.h"
#include <openssl/sha.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
int soc_sha(const void *b,size_t n,uint8_t out[32]) {return SHA256(b,n,out)?0:-1;}
uint64_t soc_now(void) {return 1;}
int soc_handoff_connect_data(uid_t u,gid_t g,const uint8_t s[16]) {(void)u;(void)g;(void)s;return -1;}
int soc_peer(int f,const struct soc_plan *p) {(void)f;(void)p;return 0;}
int main(int argc,char **argv) {
 if(getuid()==0 || argc!=2)return 2;
 int pair[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET,0,pair))return 3;
 close(pair[1]);int audit=open(argv[1],O_WRONLY|O_CREAT|O_EXCL|O_APPEND,0600);if(audit<0)return 4;
 struct soc_state s={.audit_fd=audit,.data_fd=pair[0],.data_source=1,.generation=7};
 s.plan.ifindex=1;s.plan.hook=1;memset(s.plan.approval,0xaa,32);
 struct soc_event e={.generation=7,.ifindex=1,.hook=1};
 int rc=soc_data_emit(&s,&e,sizeof(e));printf("%d\n",rc);
 close(pair[0]);close(audit);return 0;
}
