#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define FILENAME_MAX_LEN 256

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_buff_addrs SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, unsigned int);
} map_fds SEC(".maps");

SEC("tp/syscalls/sys_enter_openat")
int sys_enter_openat(struct trace_event_raw_sys_enter* ctx){

    char* filename_ptr = (char*)ctx->args[1];
    char filename[FILENAME_MAX_LEN];
    int ret = bpf_probe_read_str(filename, sizeof(filename), filename_ptr);
    if (ret <=0){
        return 0;
    }
    const char* testfilename = "112233.txt";
    for(int i = 0;i < sizeof(testfilename); i++){
        if(testfilename[i] != filename[i]){
            return 0;
        }
    }
    size_t pid_tgid = bpf_get_current_pid_tgid();
    char common[TASK_COMM_LEN];
    ret = bpf_get_current_comm(&common, sizeof(common));
    if(ret){
        return 0;
    }
    bpf_printk("common: %s  filename: %s", common, filename);
    unsigned int zero = 0;
    // 这里是要看看是不是已经打开了该文件，在exit里面检查
    bpf_map_update_elem(&map_fds, &pid_tgid, &zero, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int sys_exit_openat(struct trace_event_raw_sys_exit* ctx){
    size_t pid_tgid = bpf_get_current_pid_tgid();
    unsigned int *check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if(check == 0){
        return 0;
    }
    unsigned int fd = (unsigned int)ctx->ret;
    // 这里是退出，把文件fd放进去
    bpf_map_update_elem(&map_fds, &pid_tgid, &fd, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter* ctx){
    size_t pid_tgid = bpf_get_current_pid_tgid();

    unsigned int* pfd = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if(pfd == 0){
        return 0;
    }
    unsigned int map_fd = *pfd;
    unsigned int fd = (unsigned int)ctx->args[0];
    if(map_fd != fd){
        return 0;
    }
    long unsigned int buff_addr = ctx->args[1];

    bpf_map_update_elem(&map_buff_addrs, &pid_tgid, &buff_addr, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit* ctx){
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int* buff_addr  = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if(buff_addr  == 0){
        return 0;
    }
    bpf_printk("exit get data");

    long int read_size = ctx->ret;
    bpf_printk("read size: %d", read_size);
    if(read_size <= 0){
        return 0;
    }
    bpf_printk("modify data:");

    char payload[] = "ee"; // 正确初始化字符数组
    int payload_size = sizeof(payload) - 1; 
    if (read_size < payload_size) {
        bpf_printk("read size is smaller than payload size");
        return 0;
    }

    int ret = bpf_probe_write_user((void*)*buff_addr, payload, payload_size);
    bpf_printk("write return: %d", ret);
    return 0;
}

SEC("tp/syscalls/sys_exit_close")
int sys_exit_close(){
    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
