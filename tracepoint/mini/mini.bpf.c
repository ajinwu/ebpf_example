#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>


SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct syscall_trace_enter* ctx)
{
	u64 id;
	pid_t pid, tgid;
	struct task_struct *task;


	uid_t uid = (u32)bpf_get_current_uid_gid();
	int i;


	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	tgid = id >> 32;

	task = (struct task_struct*)bpf_get_current_task();
	pid_t ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
    bpf_printk("hello\n");
    char comm[16];
    bpf_get_current_comm(&comm,sizeof(comm));
    bpf_printk("comm: %s", comm);
	return 0;
}


char LICENSE[] SEC("license") = "GPL";
