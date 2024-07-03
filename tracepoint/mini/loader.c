#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

#include "mini.skel.h"

int main(){
    LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    struct mini_bpf *obj;
    obj = mini_bpf__open_opts(&open_opts);
    int err = mini_bpf__load(obj);
    if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}
    err = mini_bpf__attach(obj);
    if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}
    while (1) {
        sleep(10);
    }


cleanup:
    mini_bpf__destroy(obj);
    
}
