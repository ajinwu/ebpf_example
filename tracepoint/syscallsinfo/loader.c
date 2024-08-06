#include "syscallsinfo.bpf.h"
#include "syscallsinfo.skel.h"
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo) { exiting = 1; }
bool initialized = false;
static int syscall_logger(void *ctx, void *data, size_t len) {
  struct inner_syscall_info *info = (struct inner_syscall_info *)data;
  if (!info) {
    return -1;
  }
  if (info->mode == SYS_ENTER) {
    initialized = true;
    printf("%s(", info->name);
    for (int i = 0; i < info->num_args; i++) {
      printf("%p,", info->args[i]);
    }
    printf("\b) = ");
  } else {
    if (initialized) {
      printf("0x%lx\n", info->retval);
    }
  }
  return 0;
}

int main(int argc, char *argv[]) {
  const char *file_path = argv[1];
  pid_t pid = fork();
  if (pid == 0) {
    int fd = open("/dev/null", O_WRONLY);
    if (fd == -1) {
      printf("failed to open /dev/null\n");
    }
    printf("fork\n");
    dup2(fd, 1);
    sleep(2);
    execve(file_path, NULL, NULL);
  } else {
    printf("Spawned child process with a PID of %d\n", pid);
    struct syscallsinfo_bpf *obj = syscallsinfo_bpf__open_and_load();
    int err = syscallsinfo_bpf__attach(obj);
    if (err) {
      printf("failed to attach the BPF program\n");
      goto cleanup;
    }
    if (signal(SIGINT, sig_int) == SIG_ERR) {
      fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
      err = 1;
      goto cleanup;
    }
    const char *key = "child_pid";
    err = bpf_map__update_elem(obj->maps.pid_map, key, 10, (void *)&pid,
                               sizeof(pid), 0);
    if (err) {
      printf("can not set map pid\n");
      goto cleanup;
    }
    struct ring_buffer *rbuffer = ring_buffer__new(
        bpf_map__fd(obj->maps.info_buff), syscall_logger, NULL, NULL);
    if (!rbuffer) {
      printf("failed to allocate ring buffer\n");
    }
    while (!exiting) {
      err = ring_buffer__poll(rbuffer, 100);
      if (err < 0 && err != -EINTR) {
        fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
        goto cleanup;
      }
      err = 0;
    }
  cleanup:
    syscallsinfo_bpf__destroy(obj);
  }
}
