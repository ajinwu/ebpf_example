// #include <bpf/bpf.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct datarec);
    __uint(max_entries, 1024);
}xdp_stats_map SEC(".maps");

struct datarec {
	__u64 rx_packets;
};

#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

SEC("xdp")
int xdp_stats1_func(struct xdp_md* ctx){
    struct datarec* rec;
    __u32 key = XDP_PASS;
    rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if(!rec){
        return XDP_ABORTED;
    }
    __sync_fetch_and_add(&rec->rx_packets, 1);
    // lock_xadd(&rec->rx_packets, 1);
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
