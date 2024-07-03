from bcc import BPF
from time import sleep

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
struct key_t {
   u32 pre_pid;
   u32 cur_pid;  
};

BPF_HASH(stats, struct key_t, u64, 1024);

int count_sched(struct pt_regs *ctx, struct task_struct *prev){
    struct key_t key = {};
    u64 zero=0, *val;
    key.cur_pid = bpf_get_current_pid_tgid();
    key.pre_pid = prev->pid;
    
    val = stats.lookup_or_try_init(&key, &zero);
    if(val){
        (*val)++;
    }
    return 0;
}

"""

b = BPF(text=program)
# b.attach_kprobe(event=b.get_syscall_fnname("finish_task_switch"), fn_name="count_sched")
b.attach_kprobe(event_re=r'^finish_task_switch$|^finish_task_switch.isra.d$',
                fn_name="count_sched")
for i in range(0, 100): 
    sleep(0.01)

for k,v in b["stats"].items():
    print("task_switch[%5d->%5d]=%u" % (k.pre_pid, k.cur_pid, v.value))
