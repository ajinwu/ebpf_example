#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>



struct event {
  pid_t pid;
  pid_t ppid;
  uid_t uid;
  char comm[16];
  char args[128];
};

#define BASE_EVENT_SIZE (size_t)(&((struct event*)0)->args)
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
}events SEC(".maps");

// struct trace_event_raw_sys_enter {
// 	struct trace_entry ent;
// 	long int id;
// 	long unsigned int args[6];
// 	char __data[0];
// };

SEC("tracepoint/syscalls/sys_enter_execve")
int prog1(struct trace_event_raw_sys_enter *ctx) { 
    struct event e;
    pid_t pid, tgid;
    uid_t uid = (u32)bpf_get_current_uid_gid();
    u64 id = bpf_get_current_pid_tgid();
    pid = (pid_t)id;
    tgid = id >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm)); 

    struct task_struct *task;
    task = (struct task_struct*)bpf_get_current_task();

    e.pid = pid;
    e.ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);;
    e.uid = uid;

    bpf_probe_read_user(e.args, 128, (const char*)ctx->args[0]);
    bpf_perf_event_output(ctx, &events,BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
