#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

struct event {
    int pid;
    int ppid;
    unsigned exit_code;
    unsigned long long duration_ns;
    char comm[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256*1024);
}ringbuf SEC(".maps");

// struct trace_event_raw_sched_process_template {
// 	struct trace_entry ent;
// 	char comm[16];
// 	pid_t pid;
// 	int prio;
// 	char __data[0];
// };

SEC("tp/sched/sched_process_exit")
int prog2(struct trace_event_raw_sched_process_template* ctx){
    struct event* e;
    e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    if(!e){
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    u64 pid = id >> 32;
    struct task_struct* task;
    task = (struct task_struct* )bpf_get_current_task();
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task,real_parent, tgid);
    e->exit_code = BPF_CORE_READ(task, exit_code);
    u64 starttime = BPF_CORE_READ(task, start_time);
    e->duration_ns = bpf_ktime_get_ns() - starttime;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    bpf_ringbuf_submit(e, 0);
    return 0;

}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
