#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>


SEC("lsm/socket_connect")
int restrict_connect(__u64* ctx){
    struct sockaddr* address = (struct sockaddr*)ctx[1];
    if(address->sa_family != 2){
        return 0;
    }
    struct sockaddr_in* addr = (struct sockaddr_in*)address;
    __u32 dest = addr->sin_addr.s_addr;
    char str[16] = "";
    __u32 ip_addr_h = bpf_ntohl(dest);
	BPF_SNPRINTF(str, sizeof(str), "%d.%d.%d.%d",
		(ip_addr_h >> 24) & 0xff, (ip_addr_h >> 16) & 0xff,
		(ip_addr_h >> 8) & 0xff, ip_addr_h & 0xff);

    bpf_printk("found connect: %s", str);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
