#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#include "execsnoop.skel.h"
#include "execsnoop.skel.h"

static volatile sig_atomic_t exiting=0;
struct event {
  pid_t pid;
  pid_t ppid;
  uid_t uid;
  char comm[16];
  char args[128];
};


static void handler_event(void *ctx, int cpu, void *data, __u32 data_sz){
    const struct event* e = data;
//     struct event {
//   pid_t pid;
//   pid_t ppid;
//   uid_t uid;
//   char comm[16];
// };
    printf("%-16s %32s %-6d %-6d %3d \n", e->comm, e->args, e->pid, e->ppid, e->uid);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt){
    fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}
static void sig_int(int signo)
{
	exiting = 1;
}

int main(){
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    struct execsnoop_bpf *obj;
    obj = execsnoop_bpf__open_opts(&open_opts);
    int err = execsnoop_bpf__load(obj);
    if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}
    err = execsnoop_bpf__attach(obj);
    if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}
    struct perf_buffer *pb = NULL;
    pb = perf_buffer__new(bpf_map__fd(obj->maps.events), 64, handler_event, handle_lost_events, NULL, NULL);
    if(!pb){
        err = -errno;
		fprintf(stderr, "failed to open ring buffer: %d\n", err);
		goto cleanup;
    }
    if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		err = 0;
    }
    


cleanup:
    execsnoop_bpf__destroy(obj);
    
    
}
