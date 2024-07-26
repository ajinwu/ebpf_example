// #include <vmlinux.h>
#include "lsm-connect.skel.h"
#include <bpf/libbpf.h>
#include <bpf/libbpf_common.h>
#include <unistd.h>
#include <signal.h>

static volatile sig_atomic_t exiting=0;

static void sig_int(int signo)
{
	exiting = 1;
}

int main(){
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    struct lsm_connect_bpf* obj = lsm_connect_bpf__open_and_load();
    int err = lsm_connect_bpf__attach(obj);
    if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}
    while (!exiting) {
        sleep(1);
    }

    cleanup:
    lsm_connect_bpf__destroy(obj);
}
