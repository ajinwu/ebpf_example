// #include <linux/bpf.h>
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN  16
#define MAX_FILENAME_LEN 256

#define MAX_ARGS 21
#define MAX_STRING_SIZE 1024


struct filenameargs {
    int user_uid;
    int login_uid;
    int process_id;
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS][MAX_STRING_SIZE];
    int count;
};


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct filenameargs);
} large_string_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
}dataf_map SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct trace_event_raw_sys_enter* ctx){
    u32 key = 0;
    struct filenameargs* data = bpf_map_lookup_elem(&large_string_map, &key);
    if (!data){
        bpf_printk("can not init string");
        return 0;
    }
    data->count = 0;
    // loginuid
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    bpf_probe_read_kernel(&data->login_uid, sizeof(unsigned int), &task->loginuid.val);
    
    // uid
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    data->user_uid = uid;

    // process id
    data->process_id = (bpf_get_current_pid_tgid()  >> 32) & 0xFFFFFFFF;


    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(data->filename, sizeof(data->filename), filename);


    const char **argv = (const char **)ctx->args[1];
    u16 arglen = 0;
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]))
            break;
        if (argp == NULL)
            break;
        
        if (bpf_probe_read_user_str(data->args[i], sizeof(data->args[i]), argp) > 0) {
            data->count++;
        } else {
            break;
        }
    }
    bpf_perf_event_output(ctx, &dataf_map, BPF_F_CURRENT_CPU, data, sizeof(*data));
    return 0;
}

struct sched_process_exec_args
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int data_loc_filename;
    pid_t pid;
    pid_t old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int sched_process_exec(struct sched_process_exec_args *ctx){
    // evt_type=execve user=root user_uid=0 user_loginuid=1000 process=find proc_exepath=/usr/bin/find parent=bash command=find -name /root/.ssh/id_rsa terminal=34818
    //loginuid
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    u32  loginuid; 
    bpf_probe_read_kernel(&loginuid, sizeof(unsigned int), &task->loginuid.val);
    // uid
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    // absfilename
    unsigned short __offset = ctx->data_loc_filename & 0xFFFF;
    char *filename = (char *)ctx + __offset;
    char filename1[MAX_FILENAME_LEN];
    bpf_probe_read_str(filename1, sizeof(filename1), filename);

    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 tgid = (pid_tgid  >> 32) & 0xFFFFFFFF;

    // bpf_printk("loginuid:%d uid:%d abs_path: %s processid: %d", loginuid, (u32)uid, filename1, tgid);

    return 0;
}
char LICENSE[] SEC("license") = "GPL";
