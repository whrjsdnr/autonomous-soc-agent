/* Header and dynamic-symbol compatibility only: no BPF syscall or capability probe. */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdio.h>
int main(void) {
    /* Taking addresses forces link-time resolution; none of these functions is called. */
    const void * volatile api[]={bpf_program__attach_tcx,bpf_link__destroy,bpf_link__pin,
        bpf_link__unpin,bpf_link_create,bpf_link_update,bpf_link_detach,bpf_link_get_info_by_fd};
    for(unsigned n=0;n<sizeof(api)/sizeof(api[0]);n++)if(!api[n])return 2;
    printf("{\"scope\":\"HEADER_SYMBOL_ONLY_NOT_KERNEL\",\"libbpf\":\"%s\","
        "\"tcx_ingress\":%d,\"tcx_egress\":%d,\"tc_act_ok\":%d,\"tcx_pass\":%d,"
        "\"tcx_next\":%d,\"kernel_support\":\"UNKNOWN\"}\n",
        libbpf_version_string(),BPF_TCX_INGRESS,BPF_TCX_EGRESS,TC_ACT_OK,TCX_PASS,TCX_NEXT);
    return 0;
}
