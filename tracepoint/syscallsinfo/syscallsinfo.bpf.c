#include <bpf/bpf_core_read.h>
#include <vmlinux.h>

#include "syscallsinfo.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 存储任务id
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, 10);
  __uint(value_size, 4);
  __uint(max_entries, 256 * 1024);
} pid_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} info_buff SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter_handler(struct trace_event_raw_sys_enter *ctx) {
  void *value = bpf_map_lookup_elem(&pid_map, "child_pid");
  if (value) {
    long syscallid = ctx->id;
    pid_t tgid = *(int *)value;
    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    if (pid == tgid && syscallid < MAX_SYSCALL_NR && syscallid > 0) {
      bpf_printk("pid enter: %d", tgid);

      struct inner_syscall_info *info =
          bpf_ringbuf_reserve(&info_buff, sizeof(struct inner_syscall_info), 0);
      if (!info) {
        bpf_printk("bpf_ringbuf_reserve failed");
        return 0;
      }
      bpf_probe_read_kernel_str(info->name, sizeof(syscalls[syscallid].name),
                              syscalls[syscallid].name);
#pragma unroll
      for (int i = 0; i < MAX_ARGS; i++) {
        info->args[i] = (void *)BPF_CORE_READ(ctx, args[i]);
      }
      info->num_args = syscalls[syscallid].num_args;
      info->syscall_nr = syscallid;
      info->mode = SYS_ENTER;
      bpf_ringbuf_submit(info, 0);
    }
    return 0;
  }
  return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit_handler(struct trace_event_raw_sys_exit *ctx) {
  void *value = bpf_map_lookup_elem(&pid_map, "child_pid");
  if (value) {
    long syscallid = ctx->id;
    pid_t tgid = *(int *)value;

    pid_t pid = bpf_get_current_pid_tgid() & 0xffffffff;
    if (pid == tgid && syscallid < MAX_SYSCALL_NR && syscallid > 0) {
    bpf_printk("pid exit: %d", tgid);

        struct inner_syscall_info* info = bpf_ringbuf_reserve(&info_buff,sizeof(struct inner_syscall_info),0);
        if (!info) {
        bpf_printk("bpf_ringbuf_reserve failed");
        return 0;
      }
      info->mode = SYS_EXIT;
      info->retval = ctx->ret;
      bpf_ringbuf_submit(info, 0);
    }
  }
  return 0;
}
char LICENSE[] SEC("license") = "GPL";
