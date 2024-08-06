#include "tail-call-bpf.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo) { exiting = 1; }

int main() {
  struct tail_call_bpf *obj = tail_call_bpf__open_and_load();
  if (signal(SIGINT, sig_int) == SIG_ERR) {
    fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
    goto cleanup;
  }
  int key1 = 1;
  int key2 = 2;
  int bpf_prog_fd1 = bpf_program__fd(obj->progs.sys_enter_tail1_handler);
  int bpf_prog_fd2 = bpf_program__fd(obj->progs.sys_enter_tail2_handler);

  int mapfd = bpf_map__fd(obj->maps.prog_array);
  if (mapfd < 0) {
    perror("Failed to get map fd");
    goto cleanup;
  }
  int ret = bpf_map_update_elem(mapfd, &key1, &bpf_prog_fd1, BPF_ANY);
  if (ret == -1) {
    printf("Failed to add program to prog array! %s\n", strerror(errno));
    goto cleanup;
  }
  ret = bpf_map_update_elem(mapfd, &key2, &bpf_prog_fd2, BPF_ANY);
  if (ret == -1) {
    printf("Failed to add program to prog array! %s\n", strerror(errno));
    goto cleanup;
  }
  int err = tail_call_bpf__attach(obj);
  if (err) {
    fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
    goto cleanup;
  }
  while (!exiting) {
    sleep(1);
  }

cleanup:
  tail_call_bpf__destroy(obj);
}
