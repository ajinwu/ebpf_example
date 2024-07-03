import ctypes
from bcc import BPF

program = r"""
struct user_msg_t {
    char message[12];
};

struct data_t {
    u32 uid;
    u32 pid;
    char command[16];
    char message[12];    
};

BPF_HASH(config, u32, struct user_msg_t);

BPF_PERF_OUTPUT(output);

int hello(void* ctx){
    struct data_t data = {};
    struct user_msg_t *p;
    char message[12] = "hello world";
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() &0xffffffff;
    bpf_get_current_comm(&data.command, sizeof(data.command));
    p = config.lookup(&data.uid);
    if(p!=0){
        bpf_probe_read_kernel(&data.message, sizeof(data.message), p->message);
    }else{
        bpf_probe_read_kernel(&data.message,sizeof(data.message), message);
    }
    output.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event=b.get_syscall_fnname("execve"),fn_name="hello")

def print_event(cpu, data, size):
    event= b["output"].event(data)
    print(event.uid, event.pid, event.command, event.message)

b["output"].open_perf_buffer(print_event)
b["config"][ctypes.c_int(0)] = ctypes.create_string_buffer(b"hello root")
b["config"][ctypes.c_int(1000)] = ctypes.create_string_buffer(b"hello user")

while 1:
    b.perf_buffer_poll()
