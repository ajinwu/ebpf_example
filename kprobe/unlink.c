#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


// SEC("kprobe/do_unlinkat")
// int BPF_KPROBE(do_unlinkat, int dfd, struct filename* name){
//     pid_t pid;
//     const char *filename;

//     pid = bpf_get_current_pid_tgid() >> 32;
//     filename = BPF_CORE_READ(name, name);
//     bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
//     return 0;
// }

SEC("kprobe/do_unlinkat")
int handletp(struct pt_regs* ctx){
   
    struct filename* name = (struct filename*)((ctx->si));
    const char* filename;
    pid_t pid;
    pid = bpf_get_current_pid_tgid() >> 32;
    filename = BPF_CORE_READ(name, name);
    bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
    return 0;
}


SEC("kretprobe/do_unlinkat")
int handletp2(struct pt_regs* ctx){
   
    long ret;
    pid_t pid;
    if (bpf_probe_read_kernel(&ret, sizeof(ret), (void *)&ctx->ax)){
        return 0;
    }
    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("KretPROBE ENTRY pid = %d, ret = %s\n", pid, ret);
    return 0;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";
