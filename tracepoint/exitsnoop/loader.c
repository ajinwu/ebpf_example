#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_common.h>
#include <stdio.h>
#include <time.h>
#include "exitsnoop.skel.h"
#include <signal.h>

static volatile sig_atomic_t exiting=0;

struct event {
    int pid;
    int ppid;
    unsigned exit_code;
    unsigned long long duration_ns;
    char comm[128];
};

static int handle_event(void *ctx, void *data, size_t len){
    const struct event* e = data;
    printf("%-16s %-7d %-7d %u %10.3f\n", e->comm, e->pid, e->ppid, e->exit_code, (double)e->duration_ns / 1000000000.0);
	return 0;
}

static void sig_int(int signo)
{
	exiting = 1;
}


int main(){

    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    struct exitsnoop_bpf* obj = exitsnoop_bpf__open_and_load();
    int err = exitsnoop_bpf__attach(obj);
    if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

    struct ring_buffer* rb=NULL;
    rb = ring_buffer__new(bpf_map__fd(obj->maps.ringbuf), handle_event, NULL, NULL);
    if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
    if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
        err = 0;
    }


    cleanup:
    exitsnoop_bpf__destroy(obj);
}
