from bcc import BPF
from bcc.utils import printb

# program = r"""
# int kprobe_sys_clone(void* ctx){
#     bpf_trace_printk("Hello, World!\\n"); 
    
#     return 0;
# }
# """
# b = BPF(text=program)
# b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="kprobe_sys_clone")
# b.trace_print()




# program = r"""
# int hello(void* ctx){
#     bpf_trace_printk("syscall sync\n"); 
    
#     return 0;
# }
# """
# b = BPF(text=program)
# b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="hello")
# b.trace_print()


# define BPF program
prog = """
int kprobe_sys_clone(void* ctx){
    bpf_trace_printk("Hello, World!\\n"); 
    
    return 0;
}
"""
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="kprobe_sys_clone")
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
