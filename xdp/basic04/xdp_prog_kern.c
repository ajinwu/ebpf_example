#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct datarec{
    __u32 rx_packets;
    __u32 rx_bytes;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct datarec);
    __uint(max_entries, 5);
}stats_map SEC(".maps");

static inline __u32 xdp_stats_action(struct xdp_md* ctx,__u32 action){
    if(action >=5){
        return XDP_ABORTED;
    }
    void* data_end = (void *)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct datarec* ret = bpf_map_lookup_elem(&stats_map, &action);
    if(!ret){
        return action;
    }
    
    __u64 bytes = data_end - data;
    ret->rx_packets++;
    ret->rx_bytes += bytes;


    return action;
}  

SEC("xdp")
int xdp_pass_func(struct xdp_md* ctx){
    return xdp_stats_action(ctx, XDP_PASS);
}

SEC("xdp")
int xdp_drop_func(struct xdp_md* ctx){
    return xdp_stats_action(ctx, XDP_DROP);
}

SEC("xdp")
int xdp_aborted_func(struct xdp_md* ctx){
    return xdp_stats_action(ctx, XDP_ABORTED);
}


char _license[] SEC("license") = "GPL";
