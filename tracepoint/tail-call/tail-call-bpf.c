#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>


struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 3);
}prog_array SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter_handler(struct bpf_raw_tracepoint_args* ctx){
    int opcode = ctx->args[1];
    switch (opcode) {
        // case 59:
        // bpf_printk("opcode: sys_enter");
        // case 1:
        // bpf_printk("opcode: sys_write");
        // bpf_tail_call(ctx,&prog_array,1);
        // default:
        // bpf_printk("opcode: sys_enter_tail_call");
        // bpf_tail_call(ctx, &prog_array,2);
        case 59:
         bpf_tail_call(ctx,&prog_array, 1);
         default:
         bpf_tail_call(ctx, &prog_array, 2);
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter_tail1_handler(struct trace_event_raw_sys_enter* ctx){
    bpf_printk("tail-call1");
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter_tail2_handler(struct trace_event_raw_sys_enter* ctx){
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
