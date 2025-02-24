from bcc import BPF

program = """
#include <linux/sched.h>
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int hello(struct pt_regs* ctx){
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

"""
b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
        start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.9f %-16s %-6d %s" % (time_s, event.comm, event.pid,
        "Hello, perf_output!"))

b["events"].open_perf_buffer(print_event)
while 1:
    b.perf_buffer_poll()
