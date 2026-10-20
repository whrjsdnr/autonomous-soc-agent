/* Phase A read-only ELF inspection. No BPF load, map creation or TC mutation API. */
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
static int inspect(const char *path, const char *expected) {
    if (strlen(expected)!=64) return 2;
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    struct stat st;
    if (fd<0 || fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size<64 || st.st_size>1048576) {
        if (fd>=0) close(fd);
        return 3;
    }
    size_t length=st.st_size, have=0;
    unsigned char *body=malloc(length);
    if (!body) {close(fd);return 3;}
    while (have<length) {
        ssize_t n=read(fd,body+have,length-have);
        if (n<=0) {free(body);close(fd);return 3;}
        have+=n;
    }
    close(fd);
    unsigned char md[32];unsigned int size=0;char hex[65];
    if (!EVP_Digest(body,length,md,&size,EVP_sha256(),NULL) || size!=32) {free(body);return 4;}
    for (int i=0;i<32;i++) snprintf(hex+2*i,3,"%02x",md[i]);
    if (strcmp(hex,expected)) {free(body);return 4;}
    if (memcmp(body,"\177ELF\002\001",6) || body[18]!=247 || body[19]!=0) {free(body);return 4;}
    libbpf_set_print(NULL); /* Never relay arbitrary ELF/libbpf diagnostics. */
    struct bpf_object *obj=bpf_object__open_mem(body,length,NULL);
    if (libbpf_get_error(obj)) {free(body);return 5;}
    unsigned int programs=0,maps=0;
    struct bpf_program *p;
    bpf_object__for_each_program(p,obj) {
        const char *section=bpf_program__section_name(p);
        if (bpf_program__type(p)!=BPF_PROG_TYPE_SCHED_CLS ||
            (strcmp(section,"tc/ingress") && strcmp(section,"tc/egress"))) goto invalid;
        ++programs;
    }
    struct bpf_map *m;
    bpf_object__for_each_map(m,obj) {
        const char *name=bpf_map__name(m);
        if (!strcmp(name,"events")) {
            if (bpf_map__type(m)!=BPF_MAP_TYPE_RINGBUF || bpf_map__max_entries(m)!=262144) goto invalid;
        } else if (!strcmp(name,"config")) {
            if (bpf_map__type(m)!=BPF_MAP_TYPE_ARRAY || bpf_map__max_entries(m)!=1 ||
                bpf_map__key_size(m)!=4 || bpf_map__value_size(m)!=32) goto invalid;
        } else if (!strcmp(name,"counters")) {
            if (bpf_map__type(m)!=BPF_MAP_TYPE_PERCPU_ARRAY || bpf_map__max_entries(m)!=2 ||
                bpf_map__key_size(m)!=4 || bpf_map__value_size(m)!=56) goto invalid;
        } else goto invalid;
        ++maps;
    }
    if (maps!=3 || programs!=2) goto invalid;
    bpf_object__close(obj);free(body);
    puts("{\"status\":\"LOADER_PREPARATION_VERIFIED\",\"scope\":\"ELF_INSPECTION_ONLY\","
         "\"programs\":2,\"maps\":3,\"kernel_load\":false,\"tc_attach\":false,"
         "\"map_identity\":\"ELF_DECLARATIONS_NOT_KERNEL_IDS\"}");
    return 0;
invalid:
    bpf_object__close(obj);free(body);return 5;
}
int main(int argc,char **argv) {
    /* Native flags never enter inspection; phase A cannot be enabled by an approval string. */
    if (argc!=4 || strcmp(argv[1],"--inspect")) {
        fputs("EBPF_PHASE_A_NATIVE_EXECUTION_DISABLED\n",stderr);return 2;
    }
    if (geteuid()==0 || getuid()!=geteuid()) return 2;
    struct rlimit cpu={5,5},memory={134217728,134217728},files={32,32};
    if (setrlimit(RLIMIT_CPU,&cpu) || setrlimit(RLIMIT_AS,&memory) ||
        setrlimit(RLIMIT_NOFILE,&files)) return 3;
    return inspect(argv[2],argv[3]);
}
