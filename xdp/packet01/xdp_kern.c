#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>


#define bpfprint(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

static __always_inline int parse_ethhdr(void** pos,void *data_end)
{
	struct ethhdr *eth = *pos;
	int hdrsize = sizeof(*eth);

	if (*pos + hdrsize > data_end)
		return -1;
	*pos = (void*)*pos + hdrsize;
	return eth->h_proto; 
}

static inline int parse_ip(void** pos,void* data_end){
	struct iphdr *ip = *pos;
	if (ip + 1 > data_end){
		return -1;
	}
	int ipsize = ip->ihl * 4;
	if(ipsize < sizeof(*ip)){
		return -1;
	}
	if(*pos + ipsize > data_end){
		return -1;
	}
	*pos = (void*)*pos + ipsize;
	int protocol = ip->protocol;
	bpfprint("src ip addr1: %d.%d.%d\n",(ip->saddr) & 0xFF,(ip->saddr >> 8) & 0xFF,(ip->saddr >> 16) & 0xFF);
	bpfprint("src ip addr2:.%d\n",(ip->saddr >> 24) & 0xFF);
	return protocol;
}



static inline  int parse_icmp(void** pos, void* data_end){
	struct icmphdr *icmp = *pos;
	if (icmp + 1 > data_end){
		return -1;
	}
	*pos = (void*)*pos + sizeof(*icmp);
	int icmpcode = icmp->type;
	bpf_printk("icmp: %d\n",icmpcode);
	return 0;
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	void* pos = data;
	void* p1 = pos;

	int eth_type = parse_ethhdr(&pos, data_end);
	void* p2 = pos;
	if(eth_type == bpf_htons(ETH_P_IP)){
		int ip_type = parse_ip(&pos, data_end);
		void* p3 = pos;
		if (ip_type != IPPROTO_ICMP){
			return XDP_PASS;
		}else{
			int icmp_type = parse_icmp(&pos, data_end);
			bpf_printk("icmp: %d", icmp_type);
		}
	}
	
	return XDP_PASS;

}

char _license[] SEC("license") = "GPL";
