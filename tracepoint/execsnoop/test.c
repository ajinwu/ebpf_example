#include "execsnoop.skel.h"
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
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
    while (true) {
        printf("1\n");
        sleep(1);
    }

    cleanup:
    execsnoop_bpf__destroy(obj);
}
