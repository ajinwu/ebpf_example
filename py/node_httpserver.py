from bcc import BPF,USDT
import sys

# pid = sys.argv[1]
pid = 3515665

program = r"""
#include<uapi/linux/ptrace.h>
int do_trace(struct pt_regs* ctx){
    uint64 addr;
    char path[128] = {};
    bpf_usdt_readarg(6, ctx, &addr);
    bpf_probe_read_user(&path, sizeof(path),(void*)addr);
    return 0;
}
"""

u = USDT(pid = int(pid))
u.enable_probe(probe="http__server__request", fn_name="do_trace")

b = BPF(text=program, usdt_contexts=[u])
b.trace_print()

