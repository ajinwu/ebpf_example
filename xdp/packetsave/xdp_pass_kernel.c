#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
#ifdef __packed
#define __packed __attribute__((packed))
#endif

#define SAMPLE_SIZE 1024ul
#define min(x, y) ((x) < (y)?(x):(y))
#define MAX_CPUS 128

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, uint32_t);
    __uint(max_entries, MAX_CPUS);
}my_map SEC(".maps") ;

struct Metadata {
    uint16_t cookie;
    uint16_t pkt_len;
} __packed;

SEC("xdp")
int xdp_func(struct xdp_md* ctx){
    
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    if(data < data_end){
        struct Metadata metadata;
        metadata.cookie = 0xdead;
        uint64_t flags = BPF_F_CURRENT_CPU;
        uint16_t samplesize = (uint16_t)(data_end - data);
        metadata.pkt_len = min(samplesize,SAMPLE_SIZE);
        flags |= (uint64_t)samplesize << 32;
        uint16_t ret = bpf_perf_event_output(ctx, &my_map,flags, &metadata, sizeof(metadata));
        if(!ret){
            bpf_printk("perf_event_output failed: %d\n", ret);
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
