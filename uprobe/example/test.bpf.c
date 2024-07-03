#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct Test{
    int a;    
};


SEC("uprobe//root/ebpfexamples/uprobe/py/a.out:_Z12saySomethingP4Testi")
int saySomething(struct pt_regs* ctx){
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    void *parm_addr = (void *)PT_REGS_PARM1(ctx);
    struct Test parm = {};
    if(bpf_probe_read_user(&parm, sizeof(struct Test), parm_addr)!=0){
        return 0;
    }

    int cc = (int)PT_REGS_PARM2(ctx);
    bpf_printk("pid %d: a: %d  cc: %d", pid, parm.a, cc);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
