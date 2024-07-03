#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define SAMPLE_SIZE 1024ul
#define MAX_CPUS 128

#ifdef __packed
#define __packed __attribute__((packed))
#endif

#define min(x, y) ((x) < (y)?(x):(y))

struct S {
    __u16 cookie;
    __u16 pkt_len;
} __packed;

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, __u32);
    __uint(max_entries, MAX_CPUS);
}my_map SEC(".maps");

SEC("xdp")
int xdp_sample_prog(struct xdp_md* ctx){
    void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	if (data < data_end) {
        __u64 flags = BPF_F_CURRENT_CPU;
		__u16 sample_size = (__u16)(data_end - data);

        struct S metadata;
        metadata.cookie = 0xdead;
        metadata.pkt_len = min(sample_size, SAMPLE_SIZE);

        flags |= (__u64)sample_size << 32;
        int ret = bpf_perf_event_output(ctx, &my_map, flags, &metadata, sizeof(metadata));
        if (ret){
			bpf_printk("perf_event_output failed: %d\n", ret);
        }
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
