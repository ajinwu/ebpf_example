from bcc import BPF
program = r"""
#include <uapi/linux/ptrace.h>

struct Test{
    int a;    
};

int change_param(struct pt_regs* ctx){
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    struct Test* parm = (struct Test*)PT_REGS_PARM1(ctx);
    int cc = (int)PT_REGS_PARM2(ctx);
    bpf_trace_printk("%d: %d cc: %d", pid, parm->a, cc);
    int a=22;
    u64 success = bpf_probe_write_user(&(parm->a), &a, sizeof(a));
    u64 success2 = bpf_probe_write_user(&cc, &a, sizeof(cc));
    if(success2 != 0){
        bpf_trace_printk("modify cc error: %d", success2);
    }
    bpf_trace_printk("%d   %d ", parm->a, cc);
    return 0;
}

"""
bpf = BPF(text=program)

bpf.attach_uprobe(name="/root/ebpfexamples/uprobe/example/a.out", sym_re=".*say.*", fn_name="change_param")

bpf.trace_print()
