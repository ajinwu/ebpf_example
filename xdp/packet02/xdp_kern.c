#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <string.h>

#define bpfprint(fmt, ...)                                                     \
  ({                                                                           \
    char ____fmt[] = fmt;                                                      \
    bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);                 \
  })

struct hdr_cursor {
  void *pos;
};

struct vlan_hdr {
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

static __always_inline int parse_ethhdr(void** pos, void *data_end, struct ethhdr** ethh) {
  struct ethhdr *eth = (void*)*pos;
  int hdrsize = sizeof(*eth);

  if (*pos + hdrsize > data_end)
    return -1;
  *pos += hdrsize;
  ethh = ethh;
  return eth->h_proto;
}

static inline int parse_ip(void** pos, void *data_end, struct iphdr** iph) {
  struct iphdr *ip = (void*)*pos;
  if (ip + 1 > data_end) {
    return -1;
  }
  int ipsize = ip->ihl * 4;
  if (ipsize < sizeof(*ip)) {
    return -1;
  }
  if (*pos + ipsize > data_end) {
    return -1;
  }
  *pos += ipsize;
  iph = ip;
  int protocol = ip->protocol;
  // bpfprint("src ip addr1: %d.%d.%d\n",(ip->saddr) & 0xFF,(ip->saddr >> 8) &
  // 0xFF,(ip->saddr >> 16) & 0xFF); bpfprint("src ip addr2:.%d\n",(ip->saddr >>
  // 24) & 0xFF);
  return protocol;
}

static inline int parse_icmp(void** pos, void *data_end, struct icmphdr** icmph) {
  struct icmphdr *icmp = (void*)*pos;
  if (icmp + 1 > data_end) {
    return -1;
  }
  *pos += sizeof(*icmp);
  int icmpcode = icmp->type;
  icmph = icmph;
  bpf_printk("icmp: %d\n", icmpcode);
  return icmpcode;
}

static inline int compare_bytes(const void *a, const void *b, size_t size) {
  const unsigned char *p1 = a;
  const unsigned char *p2 = b;
  for (size_t i = 0; i < size; i++) {
    if (p1[i] != p2[i])
      return p1[i] - p2[i];
  }
  return 0;
}

static __always_inline int parse_udphdr(struct hdr_cursor *nh, void *data_end,
                                        struct udphdr **udphdr) {
  int len;
  struct udphdr *h = nh->pos;

  if (h + 1 > data_end)
    return -1;

  nh->pos = h + 1;
  *udphdr = h;

  len = bpf_ntohs(h->len) - sizeof(struct udphdr);
  if (len < 0) {
    return -1;
  }

  return len;
}

// static inline int rewriteudp(struct hdr_cursor *nh,void* data_end){

//     // struct udphdr* uhdr = *pos;
//     struct udphdr* uhdr = nh->pos;
//     if(uhdr + 1 > data_end){
//         return -1;
//     }

//     bpf_printk("udpport src: %u   dst: %u",bpf_ntohs(uhdr->source),
//     bpf_ntohs(uhdr->dest));

//     int len = bpf_ntohs(uhdr->len) - sizeof(struct udphdr);
//     if(len<0){
//         return -1;
//     }
//     uhdr->dest = bpf_htons(bpf_ntohs(uhdr->dest) - 1);
//     uhdr->check += bpf_htons(1);
//     if(!uhdr->check){
//         uhdr->check += bpf_htons(1);
//     }
//     if(compare_bytes(nh->pos, uhdr, len) == 0){
//         bpf_printk("bytes not modify");
//     }else{
//         bpf_printk("bytes modifys");
//     }
// }

static inline int parse_tcphdr(struct hdr_cursor *nh, void *data_end,
                               struct udphdr **tcphdr) {
  struct tcphdr *h = nh->pos;
  if (h + 1 > data_end) {
    return -1;
  }
  int len = h->doff * 4;
  if (len < sizeof(*h)) {
    return -1;
  }
  if (nh->pos + len > data_end) {
    return -1;
  }
  nh->pos += len;
  *tcphdr = h;
  return len;
}

static inline int parse_tcphdr2(void *pos, void *data_end) {
  struct tcphdr *h = pos;
  if (h + 1 > data_end) {
    return -1;
  }
  int len = h->doff * 4;
  if (len < sizeof(*h)) {
    return -1;
  }
  if (pos + len > data_end) {
    return -1;
  }
  h->dest = bpf_htons(bpf_ntohs(h->dest) - 1);
  h->check += bpf_htons(1);
  if (!h->check) {
    h->check += bpf_htons(1);
  }
  pos += len;
  return len;
}

static inline int hasvlan(struct ethhdr *eth) {
  if (eth->h_proto == bpf_htons(ETH_P_8021Q) ||
      eth->h_proto == bpf_htons(ETH_P_8021AD)) {
    return 1;
  } else {
    return 0;
  }
}

static inline int vlan_pop(struct xdp_md *ctx, struct ethhdr *eth) {
  void *data_end = (void *)(long)ctx->data_end;
  if (eth + 1 > data_end) {
    return -1;
  }
  __be16 h_proto = eth->h_proto;
  struct ethhdr eth_copy;
  struct vlan_hdr *vlh;
  // if(!(eth->h_proto == bpf_htons(ETH_P_8021Q) || eth->h_proto ==
  // bpf_htons(ETH_P_8021AD))){
  //   // 这里是ip协议

  //   return -1;
  // }
  if (!hasvlan(eth)) {
    return -1;
  }
  vlh = (void *)(eth + 1);
  int vlid = bpf_ntohs(vlh->h_vlan_TCI);
  if (vlh + 1 > data_end) {
    return -1;
  }
  memcpy(&eth_copy, eth, sizeof(eth_copy));
  if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh))) {
    return -1;
  }
  eth = (void *)(long)ctx->data;
  data_end = (void *)(long)ctx->data_end;
  if (eth + 1 > data_end) {
    return -1;
  }
  memcpy(eth, &eth_copy, sizeof(*eth));
  eth->h_proto = h_proto;
  return vlid;
}

static inline int vlan_push(struct xdp_md *ctx, struct ethhdr *eth) {
  void *data_end = (void *)(long)ctx->data_end;
  if (eth + 1 > data_end) {
    return -1;
  }
  struct ethhdr eth_copy;
  struct vlan_hdr *vlh;
  if (hasvlan(eth)) {
    return -1;
  }
  memcpy(&eth_copy, eth, sizeof(eth_copy));
  if(bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(struct vlan_hdr))){
    return -1;
  }
  data_end = (void *)(long)ctx->data_end;
	eth = (void *)(long)ctx->data;

	if (eth + 1 > data_end){
		return -1;
  }
  memcpy(eth, &eth_copy, sizeof(eth_copy));
  vlh = (void *)(eth + 1);
  if(vlh + 1 > data_end){
    return -1;
  }
  vlh->h_vlan_encapsulated_proto = IPPROTO_IP;
  vlh->h_vlan_TCI = bpf_htons(10);
  eth->h_proto = bpf_htons(ETH_P_8021Q);
  return 0;

}

SEC("xdp")
int xdp_rewrite_port(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  void *pos = data;

  struct hdr_cursor nh = {.pos = data};
  struct udphdr *udphdr;
  struct udphdr *tcphdr;
  struct iphdr* iph;
  struct ethhdr* ethh;

  int eth_type = parse_ethhdr(&pos, data_end,&ethh);
  if (eth_type == bpf_htons(ETH_P_IP)) {
    struct ethhdr *eth = data;
    if(eth + 1 > data_end){
      return XDP_PASS;
    }
    vlan_push(ctx, eth);
    int ip_type = parse_ip(&pos, data_end, &iph);
    // if (ip_type != IPPROTO_ICMP){
    // 	return XDP_PASS;
    // }else{
    // 	int icmp_type = parse_icmp(&nh, data_end);
    // 	bpf_printk("icmp: %d", icmp_type);
    // }
    if (ip_type == 17) {
      //   if (parse_udphdr(&nh, data_end, &udphdr) >= 0) {
      //     udphdr->dest = bpf_htons(bpf_ntohs(udphdr->dest) - 1);
      //     udphdr->check += bpf_htons(1);
      //     if (!udphdr->check) {
      //       udphdr->check += bpf_htons(1);
      //     }
      //   }
    } else if (ip_type == IPPROTO_TCP) {
      // parse_tcphdr2(nh.pos, data_end);

      // if(parse_tcphdr(&nh, data_end, &tcphdr) >= 0){
      // 	tcphdr->dest = bpf_htons(bpf_ntohs(tcphdr->dest) - 1);
      // 	tcphdr->check += bpf_htons(1);
      // 	if(!tcphdr->check){
      // 		tcphdr->check += bpf_htons(1);
      // 	}
      // }
    }
  }

  return XDP_PASS;
}

static inline void swap_src_dst_mac(struct ethhdr* eth){
  __u8 h_tmp[ETH_ALEN];
  memcpy(h_tmp, eth->h_source, ETH_ALEN);
  memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
  memcpy(eth->h_dest, h_tmp, ETH_ALEN);
}

static inline void swap_src_dst_ipv4(struct iphdr* ip){
  __be32 tmp = ip->saddr;
  ip->saddr = ip->daddr;
  ip->daddr = tmp;
}

struct icmphdr_common {
	__u8		type;
	__u8		code;
	__sum16	cksum;
};
static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static inline __u16 icmp_checksum_diff(__u16 seed,
		struct icmphdr_common *icmphdr_new,
		struct icmphdr_common *icmphdr_old){
  __u32 csum, size = sizeof(struct icmphdr_common);
  csum = bpf_csum_diff((__be32*)icmphdr_old, size, (__be32*)icmphdr_new, size, seed);
  return csum_fold_helper(csum);
}

SEC("xdp_icmp_echo")
int xdp_icmp_echo_func(struct xdp_md* ctx){
  void* data = (void*)(long)ctx->data;
  void* data_end = (void*)(long)ctx->data_end;
  void* pos = data;

  struct ethhdr* eth;
  struct iphdr* ip;
  struct icmphdr* icmp;
  int eth_type = parse_ethhdr(&pos,data_end,&eth);
  if(eth_type == bpf_htons(ETH_P_IP)){
    bpf_printk("ip");
    int ip_type = parse_ip(&pos, data_end, &ip);
    if(ip_type == IPPROTO_ICMP){
      bpf_printk("icmp"); 
      int icmp_type = parse_icmp(&pos, data_end,&icmp);
      if(icmp_type == ICMP_ECHO){
        // swap_src_dst_ipv4(ip);
      }
    }
  }
  // swap_src_dst_mac(eth);
  // uint16_t oldsum = icmp->checksum;
  // icmp->checksum = 0;
  // struct icmphdr icmpold = *icmp;
  // struct icmphdr_common* icmpoldcomm = (struct icmphdr_common*)icmp;
  // icmp->type = ICMP_ECHOREPLY;


  // icmp->checksum = icmp_checksum_diff(~oldsum, (struct icmphdr_common*)icmp, icmpoldcomm);
  
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
