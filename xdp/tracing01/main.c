#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <errno.h>
#include <unistd.h>

struct bpf_object *trace_attach(char *filename, char *tp_category,
                                const char *tp_name) {
  struct bpf_object *obj = bpf_object__open_file(filename, NULL);
  int err = libbpf_get_error(obj);
  if (err) {
    fprintf(stderr, "ERR: can not open file(%s) (%d): %s\n", filename, err,
            strerror(-err));
    return NULL;
  }
  err = bpf_object__load(obj);
  if (err) {
    fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n", filename, err,
            strerror(-err));
    bpf_object__close(obj);
    return NULL;
  }
  struct bpf_program *prog = bpf_object__next_program(obj, NULL);
  if (!prog) {
    fprintf(stderr,
            "ERR: Failed to retrieve program from BPF-OBJ file(%s) (%d): %s\n",
            filename, err, strerror(-err));
    bpf_object__close(obj);
    return NULL;
  }
  struct bpf_link *link =
      bpf_program__attach_tracepoint(prog, tp_category, tp_name);
  if (libbpf_get_error(link)) {
    printf("bpf_program__attach_tracepoint failed\n");
    bpf_object__close(obj);
    return NULL;
  }
  printf("load success\n");
  return obj;
}

void printmap(int map_fd) {
  unsigned int nr_cpus = libbpf_num_possible_cpus();
  __u64 value[nr_cpus];
  __s32 key;
  void *keyp = &key, *prev_keyp = NULL;
  while (true) {
    sleep(2);
    while (bpf_map_get_next_key(map_fd, prev_keyp, keyp) != -1) {
      if ((bpf_map_lookup_elem(map_fd, keyp, value)) != 0) {
        fprintf(stderr, "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
        break;
      }
      for (int i = 0; i < nr_cpus; i++) {
        printf("cpu: %d   count: %llu\n", i, value[i]);
      }
      if(prev_keyp == keyp){
        break;
      }
      prev_keyp = keyp;
    }
  }
}

int main() {
  // struct bpf_object *obj =
  //     trace_attach("trace_prog_kern.o", "xdp", "xdp_exception");
  // if (obj) {
  //   int map_fd = bpf_object__find_map_fd_by_name(obj, "xdp_stats_map");
  //   printmap(map_fd);
  // } else {
  //   printf("not obj");
  // }
  
}
