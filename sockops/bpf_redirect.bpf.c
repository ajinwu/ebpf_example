// #include <vmlinux.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>


#define LOCALHOST_IPV4 16777343

struct sock_key {
    __u32 sip;
    __u32 dip;
    __u32 sport;
    __u32 dport;
    __u32 family;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __type(key, struct sock_key);
    __type(value, int);
} sock_ops_map SEC(".maps");


SEC("sk_msg")
int sk_msg_handler(struct sk_msg_md *msg){
    if(msg->remote_ip4 !=LOCALHOST_IPV4 || msg->local_ip4 != LOCALHOST_IPV4){
        return BPF_OK;
    }
    struct sock_key key = {
        .sip = msg->remote_ip4,
        .dip = msg->local_ip4,
        .sport = bpf_htonl(msg->remote_port),
        .dport = msg->local_port,
    };
    return bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
