#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_v4_connect(struct pt_regs *ctx){

    struct sock* sk = (struct sock*)PT_REGS_PARM1(ctx);
    struct sockaddr* uaddr=(struct sockaddr*)PT_REGS_PARM2(ctx);
    if(!sk || !uaddr){
        bpf_printk("not sk or not uaddr");
        return 0;
    }
    struct sockaddr_in* usin = (struct sockaddr_in*)uaddr;
    __u32 dest = 0;
    int ret = bpf_probe_read_kernel(&dest, sizeof(dest), &usin->sin_addr.s_addr);
    char str[16] = "";
    __u32 ip_addr_h = bpf_ntohl(dest);
	BPF_SNPRINTF(str, sizeof(str), "%d.%d.%d.%d",
		(ip_addr_h >> 24) & 0xff, (ip_addr_h >> 16) & 0xff,
		(ip_addr_h >> 8) & 0xff, ip_addr_h & 0xff);

    bpf_printk("found connect: %s", str);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
