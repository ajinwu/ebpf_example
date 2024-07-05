#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpf_prog.skel.h"
#include <signal.h>


static volatile sig_atomic_t exiting=0;

static void sig_int(int signo)
{
	exiting = 1;
}

struct data_t {
    int value;
    char message[64];
};

int main() {

    struct bpf_prog* obj = bpf_prog__open_and_load();
    int err = bpf_prog__attach(obj);
    if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

    int map_fd = bpf_map__fd(obj->maps.mm_map);
    if (map_fd < 0) {
        perror("Failed to get map fd");
        return 1;
    }

    char ff[256] = "/root/test.txt";
    char data[256] = "/root/hija.txt";
    if (bpf_map_update_elem(map_fd, &ff, &data, BPF_ANY) != 0) {
        perror("Failed to update map");
        close(map_fd);
        return 1;
    }

    printf("Data written to map\n");
    while (!exiting) {
        sleep(1);
        printf("1\n");
    }
    cleanup:
        bpf_prog__destroy(obj);
        close(map_fd);
        return 0;
}
