#include "process.skel.h"
#include <signal.h>
#include <string.h>
#include <unistd.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define MAX_ARGS 21
#define MAX_STRING_SIZE 1024

static volatile sig_atomic_t exiting = 0;
static void sig_int(int signo) { exiting = 1; }


struct filenameargs {
    int user_uid;
    int login_uid;
    int process_id;
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS][MAX_STRING_SIZE];
    int count;
};

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
  const struct filenameargs *e = data;
  char args[sizeof(e->args)] = {0};
  for (int i = 0; i < e->count; i++) {
    strcat(args, " ");
    strcat(args, e->args[i]);
  }

  printf("uid:%d login_uid:%d process_id:%d %-16s %-s\n", e->user_uid, e->login_uid, e->process_id, e->filename, args);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
  fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main() {

  struct process_bpf *obj = process_bpf__open_and_load();
  int err = process_bpf__attach(obj);
  if (signal(SIGINT, sig_int) == SIG_ERR) {
    fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
    err = 1;
    goto cleanup;
  }
  if (err) {
    fprintf(stderr, "failed to load BPF object: %d\n", err);
    goto cleanup;
  }
  struct perf_buffer *pb = NULL;
  struct perf_buffer *pb2 = NULL;
  pb = perf_buffer__new(bpf_map__fd(obj->maps.dataf_map), 64, handle_event,
                        handle_lost_events, NULL, NULL);
  if (!pb) {
    err = -errno;
    fprintf(stderr, "failed to open ring buffer: %d\n", err);
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
  process_bpf__destroy(obj);
}
