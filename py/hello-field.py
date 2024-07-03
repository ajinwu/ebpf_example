from bcc import BPF
from bcc.utils import printb

# define BPF program
prog = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello, World!\n");
    return 0;
}
"""

b = BPF(text=prog)
event = b.get_syscall_fnname("clone")
b.attach_kprobe(event=event, fn_name="hello")

while True:
    try:
        task, pid, cpu, flags, ts, msg = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
