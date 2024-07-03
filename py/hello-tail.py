from bcc import BPF
import ctypes

program = r"""
BPF_PROG_ARRAY(syscall, 300);

int hello(struct bpf_raw_tracepoint_args* ctx){
    int opcode = ctx->args[1];
    syscall.call(ctx, opcode);
    bpf_trace_printk("Another syscall: %d", opcode);
    return 0;
}

int hello_exec(void* ctx){
    bpf_trace_printk("Executing a program");
    return 0;
}

int hello_timer(struct  bpf_raw_tracepoint_args* ctx){
    int opcode = ctx->args[1];
    switch(opcode){
        case 222:
            bpf_trace_printk("create a timer");
            break;
        case 223:
            bpf_trace_printk("delete a timer");
            break;
        case 224:
            bpf_trace_printk("other a timer");
            break;
    }
    return 0;
}

int ignore_opcode(void* ctx){
    return 0;
}

"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn = b.load_func("hello_exec", BPF.RAW_TRACEPOINT)
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

prog_array = b.get_table("syscall")
prog_array[ctypes.c_int(59)] = ctypes.c_int(exec_fn.fd)

prog_array[ctypes.c_int(21)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(22)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(25)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(29)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(56)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(57)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(63)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(64)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(66)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(72)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(73)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(79)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(98)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(101)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(115)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(131)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(134)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(135)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(139)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(172)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(233)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(280)] = ctypes.c_int(ignore_fn.fd)
prog_array[ctypes.c_int(291)] = ctypes.c_int(ignore_fn.fd)

b.trace_print()
