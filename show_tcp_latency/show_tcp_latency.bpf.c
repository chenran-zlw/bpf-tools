#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "show_tcp_latency.h"

#define ETH_P_IP 0x0800
#define AF_INET 2

const volatile unsigned short target_rx_port = 0; 
const volatile unsigned short target_tx_port = 0; 

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline bool match_ports(u16 sport, u16 dport) {
    if (target_rx_port == 0 && target_tx_port == 0) return true;
    
    if (target_rx_port != 0) {
        if (sport == target_rx_port || dport == target_rx_port) return true;
    }
    if (target_tx_port != 0) {
        if (sport == target_tx_port || dport == target_tx_port) return true;
    }
    return false;
}

static __always_inline int submit_event(void *ctx, struct event_t *e) {
    e->ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    return 0;
}

static __always_inline int process_skb(void *ctx, struct sk_buff *skb, u32 type) {
    if (!skb) return 0;

    __u16 protocol = BPF_CORE_READ(skb, protocol);
    if (protocol != bpf_htons(ETH_P_IP)) return 0;

    unsigned char *head = BPF_CORE_READ(skb, head);
    __u16 network_header = BPF_CORE_READ(skb, network_header);
    
    struct iphdr iph;
    if (bpf_probe_read_kernel(&iph, sizeof(iph), head + network_header) < 0) return 0;
    if (iph.protocol != IPPROTO_TCP) return 0;

    u32 ip_hlen = iph.ihl << 2;
    struct tcphdr tcph;
    if (bpf_probe_read_kernel(&tcph, sizeof(tcph), head + network_header + ip_hlen) < 0) return 0;

    u16 src = bpf_ntohs(tcph.source);
    u16 dst = bpf_ntohs(tcph.dest);
    
    if (!match_ports(src, dst)) return 0;

    struct event_t e = {
        .type = type,
        .saddr = iph.saddr,
        .daddr = iph.daddr,
        .sport = src,
        .dport = dst,
        .seq = bpf_ntohl(tcph.seq),
        .ack_seq = bpf_ntohl(tcph.ack_seq)
    };

    return submit_event(ctx, &e);
}

SEC("tracepoint/net/netif_receive_skb")
int tracepoint_netif_receive_skb(struct trace_event_raw_net_dev_template *ctx) {
    return process_skb(ctx, (struct sk_buff *)ctx->skbaddr, TYPE_NETIF_RECEIVE_SKB);
}

SEC("kprobe/ip_rcv_finish")
int kprobe__ip_rcv_finish(struct pt_regs *ctx) {
    return process_skb(ctx, (struct sk_buff *)PT_REGS_PARM3_CORE(ctx), TYPE_IP_RCV_FINISH);
}

SEC("kprobe/tcp_v4_do_rcv")
int kprobe__tcp_v4_do_rcv(struct pt_regs *ctx) {
    return process_skb(ctx, (struct sk_buff *)PT_REGS_PARM2_CORE(ctx), TYPE_TCP_V4_DO_RCV);
}

SEC("kprobe/sock_def_readable")
int kprobe__sock_def_readable(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    struct sock_common skc;
    bpf_probe_read_kernel(&skc, sizeof(skc), &sk->__sk_common);

    if (skc.skc_family != AF_INET) return 0; // 只抓 IPv4

    u16 lport = skc.skc_num;
    u16 rport = bpf_ntohs(skc.skc_dport);

    if (!match_ports(lport, rport)) return 0;

    struct event_t e = {
        .type = TYPE_SOCK_DEF_READABLE,
        .saddr = skc.skc_daddr,
        .daddr = skc.skc_rcv_saddr,
        .sport = rport,
        .dport = lport
    };
    return submit_event(ctx, &e);
}

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1_CORE(ctx);
    int copied = (int)PT_REGS_PARM2_CORE(ctx);
    struct sock_common skc;
    bpf_probe_read_kernel(&skc, sizeof(skc), &sk->__sk_common);

    if (skc.skc_family != AF_INET || copied <= 0) return 0;

    u16 lport = skc.skc_num;
    u16 rport = bpf_ntohs(skc.skc_dport);
    if (!match_ports(lport, rport)) return 0;

    struct tcp_sock *ts = (struct tcp_sock *)sk;
    u32 copied_seq;
    bpf_probe_read_kernel(&copied_seq, sizeof(copied_seq), &ts->copied_seq);

    struct event_t e = {
        .type = TYPE_TCP_CLEANUP_RBUF,
        .saddr = skc.skc_daddr,
        .daddr = skc.skc_rcv_saddr,
        .sport = rport,
        .dport = lport,
        .copied = (u32)copied,
        .copied_seq = copied_seq
    };
    return submit_event(ctx, &e);
}

// --- 发送路径 ---
SEC("kprobe/ip_output")
int kprobe__ip_output(struct pt_regs *ctx) {
    return process_skb(ctx, (struct sk_buff *)PT_REGS_PARM3_CORE(ctx), TYPE_IP_OUTPUT);
}

SEC("kprobe/dev_hard_start_xmit")
int kprobe__dev_hard_start_xmit(struct pt_regs *ctx) {
    return process_skb(ctx, (struct sk_buff *)PT_REGS_PARM1_CORE(ctx), TYPE_DEV_HARD_START_XMIT);
}

char LICENSE[] SEC("license") = "GPL";
