#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "show_tcp_latency.h"

#define ETH_P_IP 0x0800

const volatile unsigned short target_rx_port = 0; // Receive destination port
const volatile unsigned short target_tx_port = 0; // Transmit destination port

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline int submit_event(void *ctx, struct event_t *e) {
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    return 0;
}

static __always_inline void fill_event(struct event_t *e, u32 type, u32 saddr, u32 daddr, 
                                     u16 sport, u16 dport, u32 seq, u32 ack_seq) {
    e->type = type;
    e->saddr = saddr;
    e->daddr = daddr;
    e->sport = sport;
    e->dport = dport;
    e->seq = seq;
    e->ack_seq = ack_seq;
    e->ts = bpf_ktime_get_ns();
    e->copied = 0;
    e->copied_seq = 0;
}

static __always_inline int process_skb(void *ctx, struct sk_buff *skb, u32 type, bool is_rx) {
    if (!skb) return 0;

    __u16 protocol = BPF_CORE_READ(skb, protocol);
    if (protocol != bpf_htons(ETH_P_IP)) return 0;

    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 network_header = BPF_CORE_READ(skb, network_header);
    
    struct iphdr iph;
    bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header);

    if (iph.protocol != IPPROTO_TCP) return 0;

    u32 ip_hlen = iph.ihl << 2;
    
    struct tcphdr tcph;
    bpf_probe_read_kernel(&tcph, sizeof(tcph), head + network_header + ip_hlen);

    u16 src = bpf_ntohs(tcph.source);
    u16 dst = bpf_ntohs(tcph.dest);
    
    if (is_rx) {
        if (target_rx_port != 0 && dst != target_rx_port) return 0;
    } else {
        if (target_tx_port != 0 && dst != target_tx_port) return 0;
    }

    struct event_t e;
    fill_event(&e, type, iph.saddr, iph.daddr, src, dst, 
               bpf_ntohl(tcph.seq), bpf_ntohl(tcph.ack_seq));

    submit_event(ctx, &e);
    return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int tracepoint_netif_receive_skb(struct trace_event_raw_net_dev_template *ctx) {
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
    return process_skb(ctx, skb, TYPE_NETIF_RECEIVE_SKB, true);
}

SEC("kprobe/ip_rcv_finish")
int kprobe__ip_rcv_finish(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3_CORE(ctx);
    return process_skb(ctx, skb, TYPE_IP_RCV_FINISH, true);
}

SEC("kprobe/tcp_v4_do_rcv")
int kprobe__tcp_v4_do_rcv(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2_CORE(ctx);
    return process_skb(ctx, skb, TYPE_TCP_V4_DO_RCV, true);
}

SEC("kprobe/tcp_queue_rcv")
int kprobe__tcp_queue_rcv(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2_CORE(ctx);
    return process_skb(ctx, skb, TYPE_TCP_QUEUE_RCV, true);
}

SEC("kprobe/sock_def_readable")
int kprobe__sock_def_readable(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    
    struct sock_common skc;
    bpf_probe_read_kernel(&skc, sizeof(skc), &sk->__sk_common);

    // skc_num is the local port
    // skc_dport is the remote port
    u16 lport = skc.skc_num;
    u16 dport = bpf_ntohs(skc.skc_dport);

    if (target_rx_port != 0 && lport != target_rx_port) return 0;

    struct event_t e;
    e.type = TYPE_SOCK_DEF_READABLE;
    
    // Packet Source IP is the socket's Remote IP
    // Packet Destination IP is the socket's Local IP
    e.saddr = skc.skc_daddr;     
    e.daddr = skc.skc_rcv_saddr; 
    e.sport = dport;             // Remote port is the source port
    e.dport = lport;             // Local port is the destination port
    
    e.ts = bpf_ktime_get_ns();
    e.seq = 0;
    e.ack_seq = 0;
    e.copied = 0;
    e.copied_seq = 0;

    submit_event(ctx, &e);
    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    int copied = (int)PT_REGS_PARM2_CORE(ctx);

    struct sock_common skc;
    bpf_probe_read_kernel(&skc, sizeof(skc), &sk->__sk_common);

    u16 lport = skc.skc_num;
    u16 dport = bpf_ntohs(skc.skc_dport);

    if (target_rx_port != 0 && lport != target_rx_port) return 0;

    struct tcp_sock *ts = (struct tcp_sock *)sk;
    u32 copied_seq;
    bpf_probe_read_kernel(&copied_seq, sizeof(copied_seq), &ts->copied_seq);

    struct event_t e;
    e.type = TYPE_TCP_CLEANUP_RBUF;

    e.saddr = skc.skc_daddr;     
    e.daddr = skc.skc_rcv_saddr; 
    e.sport = dport;
    e.dport = lport;
    
    e.ts = bpf_ktime_get_ns();
    e.seq = 0;
    e.ack_seq = 0;
    e.copied = copied;
    e.copied_seq = copied_seq;

    submit_event(ctx, &e);
    return 0;
}

SEC("kprobe/ip_output")
int kprobe__ip_output(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3_CORE(ctx);
    return process_skb(ctx, skb, TYPE_IP_OUTPUT, false);
}

SEC("kprobe/dev_hard_start_xmit")
int kprobe__dev_hard_start_xmit(struct pt_regs *ctx) {
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1_CORE(ctx);
    return process_skb(ctx, skb, TYPE_DEV_HARD_START_XMIT, false);
}

char LICENSE[] SEC("license") = "GPL";

