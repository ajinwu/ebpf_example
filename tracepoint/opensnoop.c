#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tracepoint/syscalls/sys_enter_openat")
int handtp(struct trace_event_raw_sys_enter* ctx){
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("Process ID: %d enter sys openat\n", pid);
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
