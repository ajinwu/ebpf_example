#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct xdp_exception_ctx{
    __u64 __pad;
    __s32 prog_id;
    __u32 act;
    __s32 ifindex;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __s32);
    __type(value,__u64);
    __uint(max_entries, 10);

}xdp_stats_map SEC(".maps");


SEC("tracepoint/xdp/xdp_exception")
int trace_xdp_execption(struct xdp_exception_ctx* ctx){
    __s32 key = ctx->ifindex;
    if (ctx->act != XDP_ABORTED)
		return 0;
    __u64* valp = bpf_map_lookup_elem(&xdp_stats_map, &key);
    if(!valp){
        __u64 one = 1;
        return bpf_map_update_elem(&xdp_stats_map, &key, &one, 0)?1:0;
    }
    (*valp)++;
    return 0;
}

char _license[] SEC("license") = "GPL";
