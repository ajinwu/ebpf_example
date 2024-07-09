#include "fentry.skel.h"
#include <unistd.h>
#include <signal.h>

static volatile sig_atomic_t exiting=0;

static void sig_int(int signo)
{
	exiting = 1;
}

int main(){
    struct fentryxdp * obj= fentryxdp__open_and_load();
    int err = fentryxdp__attach(obj);
    if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}
    while (!exiting) {
        sleep(1);
    }

    cleanup:
    fentryxdp__destroy(obj);
}
