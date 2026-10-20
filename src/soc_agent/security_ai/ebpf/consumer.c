/* Read-only inherited-ring-FD consumer; no loader, attachment, pinning or privileges.
 * Future reviewed supervisor must own/map-bind the FD, stop producer and attest counters.
 * This executable alone cannot attest hook/program identity. Native CLI does not call it. */
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include "event.h"
static unsigned int count;
static int emit(void *ctx, void *data, size_t size) {
    (void)ctx;
    if (size!=sizeof(struct soc_event) || count>=4096) return -EOVERFLOW;
    if (fwrite(data,1,size,stdout)!=size || fflush(stdout)) return -EIO;
    ++count; return 0;
}
int main(int argc, char **argv) {
    if (argc!=2 || geteuid()==0) return 2;
    char *end=0; errno=0; long fd=strtol(argv[1],&end,10);
    if (errno || *end || end==argv[1] || fd<3 || fd>1048576) return 2;
    struct bpf_map_info info={0}; __u32 len=sizeof(info);
    if (bpf_obj_get_info_by_fd(fd,&info,&len) || info.type!=BPF_MAP_TYPE_RINGBUF ||
        info.max_entries!=262144) return 3;
    int flags=fcntl(STDOUT_FILENO,F_GETFL);
    if (flags<0 || fcntl(STDOUT_FILENO,F_SETFL,flags|O_NONBLOCK)<0) return 3;
    setvbuf(stdout,NULL,_IONBF,0);
    struct ring_buffer *r=ring_buffer__new(fd,emit,0,0);
    if (!r) return 4;
    struct timespec start,now; clock_gettime(CLOCK_MONOTONIC,&start);
    int result=0;
    while (count<4096) {
        clock_gettime(CLOCK_MONOTONIC,&now);
        if (now.tv_sec-start.tv_sec>=300) break;
        int rc=ring_buffer__poll(r,100);
        if (rc<0) { result=5; break; }
    }
    ring_buffer__free(r);
    /* Output EOF is not a CLOSED/counter attestation. Supervisor drain still required. */
    return result;
}
