#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
} xdprxqueue SEC(".maps");

SEC("xdp")
int xdpccc(struct xdp_md* ctx){
    int index = ctx->rx_queue_index;
    __u32 *pkt_count = bpf_map_lookup_elem(&xdprxqueue, &index);
    if(pkt_count){
        int value = *pkt_count + 1;
        bpf_map_update_elem(&xdprxqueue,&index, &value,0);
    }else {
        int value = 1;
        bpf_map_update_elem(&xdprxqueue,&index, &value,0);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
