#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define MAX_DIR_LEN 256

struct data_t {
    int value;
    char message[64];
};
const static char ff[MAX_DIR_LEN] = "/root/test.txt";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8);
    __type(key, char[MAX_DIR_LEN]);
    __type(value, char[MAX_DIR_LEN]);
}mm_map SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_openat")
int bpf_prog(struct trace_event_raw_sys_enter* ctx) {
    // char filename[MAX_DIR_LEN];
    // __builtin_memset(filename, 0, sizeof(filename)); 
    char filename[MAX_DIR_LEN] = {0}; 
    char *filename_ptr = (char *)ctx->args[1];
    int filename_len = bpf_probe_read_user_str(filename, sizeof(filename), filename_ptr);

    if ( bpf_strncmp(filename, 256, ff) == 0) {
        char* nfilename = bpf_map_lookup_elem(&mm_map, filename);
        char* vfilename = bpf_map_lookup_elem(&mm_map, ff);
        bpf_printk("oldfilename:%s  vfilename:%s", nfilename, vfilename);
        if(vfilename){
        bpf_probe_write_user((char *)ctx->args[1], vfilename, sizeof(vfilename));
        }
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
