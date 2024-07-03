#include <bits/time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/libbpf_legacy.h>
#include <errno.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <pcap/dlt.h>
#include <pcap/pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <xdp/libxdp.h>

#define SAMPLE_SIZE 1024
#ifndef __packed
#define __packed __attribute__((packed))
#endif

static pcap_dumper_t *pdumper;
static unsigned int packet_len;

struct xdp_program *get_prog(char *filename, char *prog_name) {
  struct xdp_program *prog;
  struct bpf_object_open_opts bpf_opts = {
    .sz = sizeof(struct bpf_object_open_opts)

  };
  struct xdp_program_opts xdp_opts = {
    .open_filename=filename,
    .prog_name = prog_name,
    .opts = &bpf_opts,
    .sz = sizeof(struct xdp_program_opts)
  };

                      
  printf("%s\t%s\n", filename, prog_name);
  prog = xdp_program__create(&xdp_opts);
  int err = libxdp_get_error(prog);
  char errmsg[1024];
  if (err) {
    libxdp_strerror(err, errmsg, sizeof(errmsg));
    fprintf(stderr, "Couldn't get XDP program %s: %s\n", prog_name, errmsg);
    return 0;
  }
  return prog;
}

struct xdp_program *xdp_attach(char *filename, char *prog_name, char *netcard) {
  int ifindex = if_nametoindex(netcard);
  struct xdp_program *prog = get_prog(filename, prog_name);
  if (prog == 0) {
    return 0;
  }
  int err = xdp_program__attach(prog, ifindex, XDP_MODE_UNSPEC, 0);
  char errmsg[1024];
  if (err) {
    libxdp_strerror(err, errmsg, sizeof(errmsg));
    fprintf(stderr, "Couldn't attach XDP program on iface '%d' : %s (%d)\n",
            ifindex, errmsg, err);
    return 0;
  }
  int prog_fd = xdp_program__fd(prog);
  struct bpf_prog_info info = {0};
  uint32_t info_len = sizeof(info);
  err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
  if (err) {
    fprintf(stderr, "ERR: can't get prog info - %s\n", strerror(errno));
    return 0;
  }
  printf("Success: Loading "
         "XDP prog name:%s(id:%d) on device:%d(ifindex:)\n",
         info.name, info.id, ifindex);
  return prog;
}

int xdp_detach(char *netcard) {
  int ifindex = if_nametoindex(netcard);
  struct xdp_multiprog *mp = NULL;
  mp = xdp_multiprog__get_from_ifindex(ifindex);
  int err = -1;
  if (libxdp_get_error(mp)) {
    fprintf(stderr, "Unable to get xdp_dispatcher program: %s\n",
            strerror(errno));
    xdp_multiprog__close(mp);
    return 0;
  } else if (!mp) {
    fprintf(stderr, "No XDP program loaded on %d\n", ifindex);
    mp = NULL;
    xdp_multiprog__close(mp);
    return 0;
  }
  err = xdp_multiprog__detach(mp);
  if (err) {
    fprintf(stderr, "Unable to detach XDP program: %s\n", strerror(-err));
    xdp_multiprog__close(mp);
    return 0;
  }

  printf("Program  not loaded on %d\n", ifindex);
  xdp_multiprog__close(mp);
  return 1;
}

static void print_bpf_output(void *ctx, int cpu, void *data, uint32_t size) {
  struct {
    uint16_t cookie;
    uint16_t pkt_len;
    uint8_t pkt_data[SAMPLE_SIZE];
  } __packed *e = data;

  if (e->cookie != 0xdead) {
    printf("BUG cookie %x sized %d\n", e->cookie, size);
    return;
  }

  struct pcap_pkthdr phdr = {
      .caplen = e->pkt_len,
      .len = e->pkt_len,
  };

  struct timespec ts;
  int err = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (err < 0) {
    printf("Error with clock_gettime! (%i)\n", err);
    return;
  }
  phdr.ts.tv_sec = ts.tv_sec;
  phdr.ts.tv_usec = ts.tv_nsec / 1000;

  printf("pkt len: %-5d bytes. hdr: ", e->pkt_len);
  for (int i = 0; i < e->pkt_len; i++) {
    printf("%02x", e->pkt_data[i]);
  }
  printf("\n");
  pcap_dump((u_char *)pdumper, &phdr, e->pkt_data);
  packet_len++;
}

int savepacket(struct xdp_program *prog) {
  struct bpf_map *map = bpf_object__next_map(xdp_program__bpf_obj(prog), NULL);
  // bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "");
  if (!map) {
    fprintf(stderr, "ERR: cannot find map by name: %s\n", "map");
  }
  int stats_map_fd = bpf_map__fd(map);
  if (stats_map_fd < 0) {
    fprintf(stderr, "ERR: cannot find map fd by name: %s\n", "map");
    return 0;
  }
  struct perf_buffer *pbuffer;
  pbuffer =
      perf_buffer__new(stats_map_fd, 8, print_bpf_output, NULL, NULL, NULL);
  int err = libbpf_get_error(pbuffer);
  if (err) {
    fprintf(stderr, "perf_buffer setup failed");
    return 0;
  }
  static pcap_t *pcaps;
  pcaps = pcap_open_dead(DLT_EN10MB, 65535);
  if (!pcaps) {
    perf_buffer__free(pbuffer);
    // xdp_detach(if_nametoindex("ens18"));
    return -1;
  }
  pdumper = pcap_dump_open(pcaps, "32.pcap");
  if (!pdumper) {
    perf_buffer__free(pbuffer);
    return -1;
    pcap_close(pcaps);
  }
  while ((err = perf_buffer__poll(pbuffer, 1000)) >= 0) {
  }
  return 0;
}

int main(int argc, char* argv[]) {
  char *filename = argv[1];
  char *prog_name = argv[2];
  char *netcard = argv[3];

  struct xdp_program* prog = xdp_attach(filename, prog_name, netcard);
  savepacket(prog);
}
