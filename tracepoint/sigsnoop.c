#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#define TASK_COMM_LEN 16
#define MAX_ENTRIES 10240
struct event {
    unsigned int pid;
    unsigned int tpid;
    int sig;
    int ret;
    char comm[TASK_COMM_LEN]
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct event);
    __uint(max_entries, MAX_ENTRIES);
} sigmaps SEC(".maps");

int probe_entry(int tpid, int sig){
    struct event event = {};

    __u32 tid;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    tid = (__u32)pid_tgid;
    event.pid = pid_tgid >> 32;

    event.tpid = tpid;
    event.sig = sig;
    bpf_printk("pid====: %d", pid_tgid >> 32);
    bpf_get_current_comm(event.comm, sizeof(event.comm));
    bpf_map_update_elem(&sigmaps, &tid,&event,BPF_ANY);
    return 0;

}

int probe_exit(void* ctx, int ret){
    pid_t pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)pid_tgid;
    struct event* eventp;
    eventp = bpf_map_lookup_elem(&sigmaps, &tid);
    if(!eventp){
        return 0;
    }
    eventp->ret = ret;
    bpf_printk("PID %d (%s) sent signal %d ",
           eventp->pid, eventp->comm, eventp->sig);
    bpf_printk("to PID %d, ret = %d",
            eventp->tpid, ret);
    bpf_map_delete_elem(&sigmaps, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill_entry(struct trace_event_raw_sys_enter* ctx){
    pid_t tpid = ctx->args[0];
    int sig = ctx->args[1];
    return probe_entry(tpid, sig);
}

SEC("tracepoint/syscalls/sys_exit_kill")
int kill_exit(struct trace_event_raw_sys_exit* ctx){

    return probe_exit(ctx, ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
