from bcc import BPF
from bcc.utils import printb

program = """
#include <uapi/linux/ptrace.h>
BPF_HASH(counter);
int do_trace(void* ctx){
    u64 ts, *tsp, delta, key = 0;
    tsp = counter.lookup(&key);
    if(tsp != NULL){
        delta = bpf_ktime_get_ns() - *tsp;
        if(delta < 1000000000){
            bpf_trace_printk("%d\\n", delta / 1000000);
        }
        counter.delete(&key);
    }
    ts = bpf_ktime_get_ns();
    counter.update(&key, &ts);
    return 0;
}

"""

b = BPF(text=program)
event = b.get_syscall_fnname("sync")
b.attach_kprobe(event=event, fn_name="do_trace")

start = 0
while True:
    try:
        task, pid, cpu, flags, ts, msg = b.trace_fields()
        ts = ts - start
        printb(b"At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, msg))
    except ValueError:
        continue
    except KeyboardInterrupt:
        exit()
    
