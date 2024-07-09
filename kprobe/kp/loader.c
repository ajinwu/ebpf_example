#include "kp1.skel.h"
#include <unistd.h>
#include <signal.h>

static volatile sig_atomic_t exiting=0;

static void sig_int(int signo)
{
	exiting = 1;
}

int main(){
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    struct kp1* obj = kp1__open_and_load();
    int err = kp1__attach(obj);
    if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}
    while (!exiting) {
        sleep(1);
    }

    cleanup:
        kp1__destroy(obj);
}
