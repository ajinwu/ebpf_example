#include <bpf/bpf_endian.h>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// net:net_dev_xmit：设备层发送 skb 的 tracepoint。
// net:netif_receive_skb：设备层接收 skb 的 tracepoint。

#define ETH_P_8021Q	0x8100
#define ETH_P_IP	0x0800

struct tp_netif_receive_skb_args {
    u64 unused;
    void* skdaddr;
    u32 len;
};

struct tp_net_dev_xmit_args {
    u64 unused;
    void* skdaddr;
    u32 len;
    int rc;
};

struct net_tuple{
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct net_tuple);
    __type(value,__u64);
    __uint(max_entries, 8192);
}timestamps SEC(".maps");


static __always_inline int handle_skb2(struct sk_buff* skb){
    long  ret;
    unsigned char *head;
    ret = bpf_probe_read_kernel(&head, sizeof(unsigned char*), &skb->head);
    if(ret < 0){
        return BPF_OK;
    }
    u16 network_header;
    struct iphdr ip_hdr;
    ret = bpf_probe_read_kernel(&network_header,sizeof(network_header),&skb->network_header);
    if(ret < 0){
        return BPF_OK;
    }
    ret = bpf_probe_read_kernel(&ip_hdr, sizeof(ip_hdr),(struct iphdr*)(head+network_header));
    if(ret < 0){
        return BPF_OK;
    }

    struct udphdr udp_hdr;
    u16 transport_header;
    ret = bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);
    if(ret < 0){
        return BPF_OK;
    }
    ret = bpf_probe_read_kernel(&udp_hdr, sizeof(udp_hdr),(struct udphdr*)(head+transport_header));
    if(ret < 0){
        return BPF_OK;
    }
    struct net_tuple tuple = {};
    switch(ip_hdr.protocol){
        case IPPROTO_TCP:
            tuple.sport = udp_hdr.source;
            tuple.dport = udp_hdr.dest;
        case IPPROTO_UDP:
            tuple.sport = udp_hdr.source;
            tuple.dport = udp_hdr.dest;
        case IPPROTO_ICMP:
            tuple.sport = 0;
            tuple.dport = 0;
    }
    __u64* ts = (__u64*)bpf_map_lookup_elem(&timestamps, &tuple);
    if(ts){
        __u64 delta = bpf_ktime_get_ns() - *ts;
        bpf_map_delete_elem(&timestamps, &tuple);
        bpf_printk("delta time: %llu", delta);
    }
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&timestamps, &tuple, &now, BPF_NOEXIST);
    return BPF_OK;
}

SEC("tp/net/netif_receive_skb")
int handle_netif_receive_skb(struct tp_netif_receive_skb_args* ctx){
    struct sk_buff* skb = ctx->skdaddr;
    handle_skb2(skb);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
