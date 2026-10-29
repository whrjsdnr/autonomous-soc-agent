/* Privilege and libbpf boundaries mocked; execute the actual C error/cleanup path only. */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
static uid_t fixture_uid(void) {return 0;}
static char *fixture_if(unsigned int index,char *name) {
 if(index!=1)return NULL;strcpy(name,"lo");return name;
}
static int fixture_stat(const char *path,struct stat *out) {
 (void)path;memset(out,0,sizeof(*out));out->st_ino=4026532232ULL;return 0;
}
static struct bpf_object *fixture_open(const char *path,const struct bpf_object_open_opts *opts) {
 (void)path;(void)opts;errno=EACCES;return NULL;
}
static long fixture_error(const void *pointer) {(void)pointer;return -EACCES;}
#define geteuid fixture_uid
#define if_indextoname fixture_if
#define stat(path,out) fixture_stat(path,out)
#define bpf_object__open_file fixture_open
#define libbpf_get_error fixture_error
#include "provider.c"
int open_failure_errno(void) {
 errno=0;struct runtime *runtime=continuous_open("/fixture/not-loaded",1,4026532232ULL,NULL,NULL,0);
 if(runtime) {continuous_close(runtime);return 0;}
 return errno;
}
