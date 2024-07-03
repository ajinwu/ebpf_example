// #include "envs/xdp-tools/lib/libbpf/src/bpf.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <errno.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <xdp/libxdp.h>
#include <pcap/pcap.h>
#include <bits/time.h>

// #include <linux/if_link.h>

#define ERRMSG 0
#define SUCCESSMSG 1
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#define MAX_CPUS 128
#define SAMPLE_SIZE 1024
#define NANOSECS_PER_USEC 1000
static unsigned int pcap_pkts;
static pcap_dumper_t* pdumper;

int print_map(struct xdp_program *prog, char *map_name);
int pinnedmap(struct xdp_program *prog, char *map_name);
struct xdp_program *get_prog(char *filename, char *prog_name) {
  struct xdp_program *prog;
  int err;
  char errmsg[1024];

  DECLARE_LIBBPF_OPTS(bpf_object_open_opts, bpf_opts);
  DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, .open_filename = filename,
                      .prog_name = prog_name, .opts = &bpf_opts, );

  // struct bpf_object_open_opts bpf_opts = {

  // };
  // struct xdp_program_opts xdp_opts = {
  //   .open_filename=filename,
  //   .prog_name = prog_name,
  //   .opts = &bpf_opts,
  // };

  // DECLARE_LIBXDP_OPTS(xdp_program_opts, opts);
  // opts.obj = bpf_object__open(filename);
  // opts.prog_name = "xdp";

  prog = xdp_program__create(&xdp_opts);
  
  // struct bpf_object* obj = bpf_object__open_file(filename, NULL);
  // bpf_object__find_program_by_name(obj, "xdp");

  err = libxdp_get_error(prog);
  if (err) {
    printf("%d\n", err);
    libxdp_strerror(err, errmsg, sizeof(errmsg));
    fprintf(stderr, "Couldn't get XDP program %s: %s\n", prog_name, errmsg);
    return ERRMSG;
  }
  return prog;
}

int trace_attach(char *filename,char * tp_category, const char * tp_name) {
  struct bpf_object *obj = bpf_object__open_file(filename, NULL);
  int err = libbpf_get_error(obj);
  if (err) {
    fprintf(stderr, "ERR: can not open file(%s) (%d): %s\n", filename, err,
            strerror(-err));
    return ERRMSG;
  }
  err = bpf_object__load(obj);
  if (err) {
    fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n", filename, err,
            strerror(-err));
    bpf_object__close(obj);
    return ERRMSG;
  }
  struct bpf_program *prog = bpf_object__next_program(obj, NULL);
  if (!prog) {
    fprintf(stderr,
            "ERR: Failed to retrieve program from BPF-OBJ file(%s) (%d): %s\n",
            filename, err, strerror(-err));
    bpf_object__close(obj);
    return ERRMSG;
  }
  struct bpf_link *link =
      bpf_program__attach_tracepoint(prog, tp_category, tp_name);
  if (libbpf_get_error(link)) {
    printf("bpf_program__attach_tracepoint failed\n");
    bpf_object__close(obj);
    return ERRMSG;
  }
  return SUCCESSMSG;
}

struct xdp_program * xdp_attach(char *filename, char *prog_name, char *netcard) {
  int err;
  char errmsg[1024];
  int ifindex = if_nametoindex(netcard);
  struct xdp_program *prog = get_prog(filename, prog_name);
  if (prog == 0) {
    return ERRMSG;
  }
  err = xdp_program__attach(prog, ifindex, XDP_MODE_UNSPEC, 0);
  if (err) {
    libxdp_strerror(err, errmsg, sizeof(errmsg));
    fprintf(stderr, "Couldn't attach XDP program on iface '%d' : %s (%d)\n",
            ifindex, errmsg, err);
    return ERRMSG;
  }

  int prog_fd = xdp_program__fd(prog);
  struct bpf_prog_info info = {0};
  __u32 info_len = sizeof(info);

  err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
  if (err) {
    fprintf(stderr, "ERR: can't get prog info - %s\n", strerror(errno));
    return ERRMSG;
  }
  // pinnedmap(prog, "stats_map");

  printf("Success: Loading "
         "XDP prog name:%s(id:%d) on device:%d(ifindex:)\n",
         info.name, info.id, ifindex);
  // print_map(prog, "stats_map");
  return prog;
}

int xdp_detach_by_id(int ifindex, int id) {
  struct bpf_object_open_opts opts;
  struct xdp_multiprog *mp = NULL;
  mp = xdp_multiprog__get_from_ifindex(ifindex);
  int err = -1;
  if (libxdp_get_error(mp)) {
    fprintf(stderr, "Unable to get xdp_dispatcher program: %s\n",
            strerror(errno));
    xdp_multiprog__close(mp);
    return ERRMSG;
  } else if (!mp) {
    fprintf(stderr, "No XDP program loaded on %d\n", ifindex);
    mp = NULL;
    xdp_multiprog__close(mp);
    return ERRMSG;
  }
  struct xdp_program *prog = NULL;
  enum xdp_attach_mode mode;
  while ((xdp_multiprog__next_prog(prog, mp))) {
    // 这里是指定id
    if (xdp_program__id(prog) == id) {
      mode = xdp_multiprog__attach_mode(mp);
      printf("Detaching XDP program with ID %u from %d\n",
             xdp_program__id(prog), ifindex);
      err = xdp_program__detach(prog, ifindex, mode, 0);
      if (err) {
        fprintf(stderr, "Unable to detach XDP program: %s\n", strerror(-err));
        xdp_multiprog__close(mp);
        return ERRMSG;
      }
    }
  }
  if (xdp_multiprog__is_legacy(mp)) {
    prog = xdp_multiprog__main_prog(mp);
    if (xdp_program__id(prog) == id) {
      mode = xdp_multiprog__attach_mode(mp);
      printf("Detaching XDP program with ID %u from %d\n",
             xdp_program__id(prog), ifindex);
      err = xdp_program__detach(prog, ifindex, mode, 0);
      if (err) {
        fprintf(stderr, "Unable to detach XDP program: %s\n", strerror(-err));
        xdp_multiprog__close(mp);
        return ERRMSG;
      }
    }
  }
  prog = xdp_multiprog__hw_prog(mp);
  if (xdp_program__id(prog) == id) {
    mode = xdp_multiprog__attach_mode(mp);
    printf("Detaching XDP program with ID %u from %d\n", xdp_program__id(prog),
           ifindex);
    err = xdp_program__detach(prog, ifindex, mode, 0);
    if (err) {
      fprintf(stderr, "Unable to detach XDP program: %s\n", strerror(-err));
      xdp_multiprog__close(mp);
      return ERRMSG;
    }
  }

  printf("Program  not loaded on %d\n", ifindex);
  xdp_multiprog__close(mp);
  return SUCCESSMSG;
}

int xdp_detach(int ifindex) {
  struct bpf_object_open_opts opts;
  struct xdp_multiprog *mp = NULL;
  mp = xdp_multiprog__get_from_ifindex(ifindex);
  int err = -1;
  if (libxdp_get_error(mp)) {
    fprintf(stderr, "Unable to get xdp_dispatcher program: %s\n",
            strerror(errno));
    xdp_multiprog__close(mp);
    return ERRMSG;
  } else if (!mp) {
    fprintf(stderr, "No XDP program loaded on %d\n", ifindex);
    mp = NULL;
    xdp_multiprog__close(mp);
    return ERRMSG;
  }
  //   卸载所有
  err = xdp_multiprog__detach(mp);
  if (err) {
    fprintf(stderr, "Unable to detach XDP program: %s\n", strerror(-err));
    xdp_multiprog__close(mp);
    return ERRMSG;
  }

  printf("Program  not loaded on %d\n", ifindex);
  xdp_multiprog__close(mp);
  return SUCCESSMSG;
}

int print_map(struct xdp_program *prog, char *map_name) {
  int err;

  struct bpf_map *map =
      bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), map_name);
  if (!map) {
    fprintf(stderr, "ERR: cannot find map by name: %s\n", "map");
  }
  int stats_map_fd = bpf_map__fd(map);
  if (stats_map_fd < 0) {
    fprintf(stderr, "ERR: cannot find map fd by name: %s\n", "map");
    return ERRMSG;
  }

  struct datarec {
    __u64 rx_packets;
  };
  struct record {
    __u64 timestamp;
    struct datarec total;
  };
  struct stats_record {
    struct record stats[1];
  };

  struct bpf_map_info info = {0};
  struct bpf_map_info map_expect = {0};
  map_expect.key_size = sizeof(__u32);
  map_expect.value_size = sizeof(struct datarec);
  map_expect.max_entries = 1024;

  __u32 info_len = sizeof(struct bpf_map_info);
  err = bpf_obj_get_info_by_fd(stats_map_fd, &info, &info_len);

  if (err) {
    fprintf(stderr, "ERR: %s() can't get info - %s\n", __func__,
            strerror(errno));
    return ERRMSG;
  }
  if (err) {
    fprintf(stderr, "ERR: map via FD not compatible\n");
    return err;
  }
  struct record myrecord = {0};
  while (1) {
    __u32 key;
    for (key = 0; key < 5; key++) {
      struct datarec value;
      int key1 = key;
      if ((bpf_map_lookup_elem(stats_map_fd, &key1, &value)) != 0) {
        fprintf(stderr, "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
      } else {
        printf("Key: %u, rx_packets: %llu\n", key, value.rx_packets);
      }
    }
    sleep(10);
  }
}


static void print_bpf_output(void* ctx, int cpu, void* data, __u32 size){
  struct {
		__u16 cookie;
		__u16 pkt_len;
		__u8  pkt_data[SAMPLE_SIZE];
	} __packed *e = data;
	struct pcap_pkthdr h = {
		.caplen	= e->pkt_len,
		.len	= e->pkt_len,
	};
	struct timespec ts;
	int i, err;

	if (e->cookie != 0xdead)
		printf("BUG cookie %x sized %d\n",
		       e->cookie, size);

	err = clock_gettime(CLOCK_MONOTONIC, &ts);
	if (err < 0)
		printf("Error with clock_gettime! (%i)\n", err);

	h.ts.tv_sec  = ts.tv_sec;
	h.ts.tv_usec = ts.tv_nsec / NANOSECS_PER_USEC;

	if (1) {
		printf("pkt len: %-5d bytes. hdr: ", e->pkt_len);
		for (i = 0; i < e->pkt_len; i++)
			printf("%02x ", e->pkt_data[i]);
		printf("\n");
	}

	pcap_dump((u_char *) pdumper, &h, e->pkt_data);
	pcap_pkts++;
}

int mapfromperf(struct xdp_program *prog){
  int err;

  struct bpf_map *map =
      bpf_object__next_map(xdp_program__bpf_obj(prog), NULL);
  if (!map) {
    fprintf(stderr, "ERR: cannot find map by name: %s\n", "map");
  }
  int stats_map_fd = bpf_map__fd(map);
  if (stats_map_fd < 0) {
    fprintf(stderr, "ERR: cannot find map fd by name: %s\n", "map");
    return ERRMSG;
  }
  struct perf_buffer *pb;
  static pcap_t* pd;

  pb = perf_buffer__new(stats_map_fd, 8, print_bpf_output, NULL, NULL, NULL);
  err = libbpf_get_error(pb);
	if (err) {
		fprintf(stderr, "perf_buffer setup failed");
		return 1;
	}
  pd = pcap_open_dead(DLT_EN10MB, 65535);
  if (!pd) {
		perf_buffer__free(pb);
		xdp_detach(if_nametoindex("ens18"));
    return -1;
	}
  
  pdumper = pcap_dump_open(pd, "11.pcap");
  if (!pdumper) {
		perf_buffer__free(pb);
	    pcap_close(pd);
		xdp_detach(if_nametoindex("ens18"));
    return -1;
	}
  while((err = perf_buffer__poll(pb, 1000)) >=0){}
  return 0;
}

int pinnedmap(struct xdp_program *prog, char *map_name) {
  const char *pin_basedir = "/sys/fs/bpf";
  char filename[100];
  sprintf(filename, "%s/%s", pin_basedir, map_name);
  int err;
  err = bpf_object__pin_maps(xdp_program__bpf_obj(prog), filename);
  if (err) {
    fprintf(stderr, "ERR: Pinning maps in %s\n", filename);
    return ERRMSG;
  }

  return SUCCESSMSG;
}

int unpinmap(struct xdp_program *prog, char *map_name) {
  const char *pin_basedir = "/sys/fs/bpf";
  char filename[100];
  sprintf(filename, "%s/%s", pin_basedir, map_name);

  int err = bpf_object__unpin_maps(xdp_program__bpf_obj(prog), filename);
  if (err) {
    fprintf(stderr, "ERR: Pinning maps in %s\n", filename);
    return ERRMSG;
  }
  return SUCCESSMSG;
}

int main( int argc, char *argv[]) {

  char* filename = argv[1];
  char* prog_name = argv[2];
  struct xdp_program *prog = xdp_attach(filename, prog_name, "lo");

  // xdp_detach(if_nametoindex("veth-basic05"));
  // struct xdp_program * prog = get_prog(filename, prog_name);
  // unpinmap(prog, "stats_map");
  // mapfromperf(prog);

}
