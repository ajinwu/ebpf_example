#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 

SEC("tc")
int tc_ingress(struct __sk_buff* ctx){
    void* data_end = (void*)(__u64)ctx->data_end;
    void* data = (void*)(__u64)ctx->data;
    struct ethhdr* l2;
    struct iphdr* l3 ;

    if(ctx->protocol != bpf_htons(ETH_P_IP)){
        return TC_ACT_OK;
    }

    l2 = (struct ethhdr*)data;
    if((void*)(l2 + 1) > data_end){
        return TC_ACT_OK;
    }
    l3 = (struct iphdr*)(l2+1);
    if((void*)(l3 + 1) > data_end){
        return TC_ACT_OK;
    }

    __u32 dest = l3->saddr;
    char str[16] = "";
    __u32 ip_addr_h = bpf_ntohl(dest);
	BPF_SNPRINTF(str, sizeof(str), "%d.%d.%d.%d",
		(ip_addr_h >> 24) & 0xff, (ip_addr_h >> 16) & 0xff,
		(ip_addr_h >> 8) & 0xff, ip_addr_h & 0xff);
    bpf_printk("ip: %s ttl: %d", str, l3->ttl);

}

char __license[] SEC("license") = "GPL";
