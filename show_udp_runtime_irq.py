#!/usr/bin/python3
# -*- coding: utf-8 -*-

from __future__ import print_function
from bcc import BPF
import argparse
import socket
import struct
import time
from bcc.utils import printb
import ctypes as ct
import re

examples = """examples:
    ./netshow.py --mode all          # Trace both UDP send and receive
    ./netshow.py --mode tx -p 181    # Trace sends from PID 181 and show IRQ affinity
    ./netshow.py --mode rx --port 5201 # Trace receives for port 5201 to check RSS
"""
parser = argparse.ArgumentParser(description="Unified tool to trace UDP send (TX) and receive (RX) paths", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=examples)
parser.add_argument("--mode", choices=['tx', 'rx', 'all'], default='all', help="The direction to trace: tx, rx, or all (default: all)")
parser.add_argument("-p", "--pid", type=int, help="TX mode: trace this PID only")
parser.add_argument("--port", type=int, help="RX mode: trace this destination port only")
parser.add_argument("-c", "--cpu", type=int, help="Filter events processed by this CPU only")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
args = parser.parse_args()

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/udp.h>
#include <linux/sched.h>
#include <net/ip.h>
#include <linux/etherdevice.h>
#define TASK_COMM_LEN 16
struct pid_comm_t { u32 pid; char name[TASK_COMM_LEN]; };
struct tx_event_t {
    u32 pid; char name[TASK_COMM_LEN]; u64 saddr_l, saddr_h, daddr_l, daddr_h;
    u16 lport, rport, ip_proto; u32 cpu; u16 queue_num;
};
struct rx_event_t {
    u64 saddr_l, saddr_h, daddr_l, daddr_h; u16 lport, rport, ip_proto;
    u32 cpu; u32 pkt_len;
};
BPF_HASH(skb_to_pid, struct sk_buff *, struct pid_comm_t);
BPF_PERF_OUTPUT(tx_events);
BPF_PERF_OUTPUT(rx_events);
static inline int parse_headers(struct sk_buff *skb, u16 *lport, u16 *rport, u16 *ip_proto) {
    u16 network_header, transport_header, protocol;
    bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
    bpf_probe_read_kernel(&protocol, sizeof(protocol), &skb->protocol);
    protocol = bpf_ntohs(protocol);
    if (protocol == ETH_P_IP) *ip_proto = 4;
    else if (protocol == ETH_P_IPV6) *ip_proto = 6;
    else return 0;
    bpf_probe_read_kernel(&transport_header, sizeof(transport_header), &skb->transport_header);
    if (transport_header == 0) {
        if (*ip_proto == 4) {
            struct iphdr ip; bpf_probe_read_kernel(&ip, sizeof(ip), (void *)(skb->head + network_header));
            if (ip.protocol != IPPROTO_UDP) return 0;
            transport_header = network_header + (ip.ihl << 2);
        } else {
            struct ipv6hdr ip6; bpf_probe_read_kernel(&ip6, sizeof(ip6), (void *)(skb->head + network_header));
            if (ip6.nexthdr != IPPROTO_UDP) return 0;
            transport_header = network_header + sizeof(struct ipv6hdr);
        }
    }
    struct udphdr udp; bpf_probe_read_kernel(&udp, sizeof(udp), (void *)(skb->head + transport_header));
    *lport = udp.source; *rport = udp.dest;
    return 1;
}
int kprobe__ip_send_skb(struct pt_regs *ctx, struct net *net, struct sk_buff *skb) {
    u32 pid = bpf_get_current_pid_tgid() >> 32; FILTER_PID
    struct pid_comm_t data = {.pid = pid};
    bpf_get_current_comm(&data.name, sizeof(data.name));
    skb_to_pid.update(&skb, &data); return 0;
}
int kprobe__dev_hard_start_xmit(struct pt_regs *ctx, struct sk_buff *skb) {
    struct pid_comm_t *p = skb_to_pid.lookup(&skb); if (p == 0) return 0;
    struct tx_event_t evt = {.pid = p->pid};
    bpf_probe_read_kernel_str(&evt.name, sizeof(evt.name), p->name);
    if (!parse_headers(skb, &evt.lport, &evt.rport, &evt.ip_proto)) return 0;
    evt.cpu = bpf_get_smp_processor_id();
    bpf_probe_read_kernel(&evt.queue_num, sizeof(evt.queue_num), &skb->queue_mapping);
    u16 network_header; bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
    if (evt.ip_proto == 4) { struct iphdr ip; bpf_probe_read_kernel(&ip, sizeof(ip), (void *)(skb->head + network_header)); evt.saddr_l = ip.saddr; evt.daddr_l = ip.daddr;
    } else { struct ipv6hdr ip6; bpf_probe_read_kernel(&ip6, sizeof(ip6), (void *)(skb->head + network_header)); bpf_probe_read_kernel(&evt.saddr_l, sizeof(u64), &ip6.saddr.in6_u.u6_addr8[0]); bpf_probe_read_kernel(&evt.saddr_h, sizeof(u64), &ip6.saddr.in6_u.u6_addr8[8]); bpf_probe_read_kernel(&evt.daddr_l, sizeof(u64), &ip6.daddr.in6_u.u6_addr8[0]); bpf_probe_read_kernel(&evt.daddr_h, sizeof(u64), &ip6.daddr.in6_u.u6_addr8[8]); }
    tx_events.perf_submit(ctx, &evt, sizeof(evt)); return 0;
}
int kprobe__kfree_skb(struct pt_regs *ctx, struct sk_buff *skb) { skb_to_pid.delete(&skb); return 0; }
RAW_TRACEPOINT_PROBE(netif_receive_skb) {
    struct sk_buff *skb = (struct sk_buff *)ctx->args[0];
    if (skb == NULL) return 0;
    u16 protocol;
    bpf_probe_read_kernel(&protocol, sizeof(protocol), &skb->protocol);
    if (bpf_ntohs(protocol) != ETH_P_IP && bpf_ntohs(protocol) != ETH_P_IPV6) return 0;
    struct rx_event_t evt = {};
    u16 lport_be, rport_be;
    if (!parse_headers(skb, &lport_be, &rport_be, &evt.ip_proto)) return 0;
    u16 dport = bpf_ntohs(rport_be);
    FILTER_PORT
    evt.lport = bpf_ntohs(lport_be);
    evt.rport = dport;
    evt.cpu = bpf_get_smp_processor_id();
    bpf_probe_read_kernel(&evt.pkt_len, sizeof(evt.pkt_len), &skb->len);
    u16 network_header;
    bpf_probe_read_kernel(&network_header, sizeof(network_header), &skb->network_header);
    if (evt.ip_proto == 4) {
        struct iphdr ip; bpf_probe_read_kernel(&ip, sizeof(ip), (void *)(skb->head + network_header));
        evt.saddr_l = ip.saddr; evt.daddr_l = ip.daddr;
    } else {
        struct ipv6hdr ip6; bpf_probe_read_kernel(&ip6, sizeof(ip6), (void *)(skb->head + network_header));
        bpf_probe_read_kernel(&evt.saddr_l, sizeof(u64), &ip6.saddr.in6_u.u6_addr8[0]);
        bpf_probe_read_kernel(&evt.saddr_h, sizeof(u64), &ip6.saddr.in6_u.u6_addr8[8]);
        bpf_probe_read_kernel(&evt.daddr_l, sizeof(u64), &ip6.daddr.in6_u.u6_addr8[0]);
        bpf_probe_read_kernel(&evt.daddr_h, sizeof(u64), &ip6.daddr.in6_u.u6_addr8[8]);
    }
    rx_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""
if args.pid: bpf_text = bpf_text.replace('FILTER_PID', 'if (pid != %s) { return 0; }' % args.pid)
else: bpf_text = bpf_text.replace('FILTER_PID', '')
if args.port: bpf_text = bpf_text.replace('FILTER_PORT', 'if (dport != %s) { return 0; }' % args.port)
else: bpf_text = bpf_text.replace('FILTER_PORT', '')
if args.ebpf: print(bpf_text); exit()
try:
    b = BPF(text=bpf_text)
except Exception as e:
    print(f"Failed to compile or load BPF program: {e}")
    exit(1)

TASK_COMM_LEN = 16
class TxEvent(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint), ("name", ct.c_char * TASK_COMM_LEN),
        ("saddr_l", ct.c_uint64), ("saddr_h", ct.c_uint64),
        ("daddr_l", ct.c_uint64), ("daddr_h", ct.c_uint64),
        ("lport", ct.c_ushort), ("rport", ct.c_ushort),
        ("ip_proto", ct.c_ushort), ("cpu", ct.c_uint), ("queue_num", ct.c_ushort),
    ]
class RxEvent(ct.Structure):
    _fields_ = [
        ("saddr_l", ct.c_uint64), ("saddr_h", ct.c_uint64),
        ("daddr_l", ct.c_uint64), ("daddr_h", ct.c_uint64),
        ("lport", ct.c_ushort), ("rport", ct.c_ushort),
        ("ip_proto", ct.c_ushort), ("cpu", ct.c_uint), ("pkt_len", ct.c_uint),
    ]

TX_DEVICE_PREFIX = "-output"
RX_DEVICE_PREFIX = "-input"
irq_cache = {}
last_cache_refresh = 0

def find_irq_by_queue(device_prefix, queue_index):
    queue_index_str = str(queue_index)
    target_name = f"{device_prefix}.{queue_index_str}"
    irqs = []
    try:
        with open('/proc/interrupts', 'r') as f:
            for line in f:
                if line.strip().endswith(target_name):
                    irq_str = line.split(':')[0].strip()
                    if irq_str.isdigit(): irqs.append(int(irq_str))
    except Exception: pass
    return irqs

def find_cpu_by_irq(irq_num):
    if irq_num < 0: return None
    path = f"/proc/irq/{irq_num}/smp_affinity_list"
    try:
        with open(path, 'r') as f: return f.read().strip()
    except Exception: return None

def is_cpu_in_affinity_list(affinity_str, cpu_id):
    for part in affinity_str.split(','):
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if start <= cpu_id <= end:
                    return True
            except ValueError:
                continue 
        else:
            try:
                if int(part) == cpu_id:
                    return True
            except ValueError:
                continue 
    return False

def find_rx_info_by_cpu(target_cpu):
    global last_cache_refresh, irq_cache
    now = time.time()
    if now - last_cache_refresh > 5: 
        irq_cache.clear()
        try:
            with open('/proc/interrupts', 'r') as f:
                for line in f:
                    if RX_DEVICE_PREFIX not in line: continue
                    parts = line.strip().split()
                    irq_str = parts[0].strip(":")
                    if not irq_str.isdigit(): continue
                    
                    irq_num = int(irq_str)
                    irq_name = parts[-1]
                    match = re.search(r'\.(\d+)$', irq_name)
                    if not match: continue
                    queue_num = int(match.group(1))

                    affinity_path = f"/proc/irq/{irq_num}/smp_affinity_list"
                    with open(affinity_path, 'r') as aff_f:
                        affinity_cpus_str = aff_f.read().strip()                        
                        for cpu_to_check in range(256): 
                            if is_cpu_in_affinity_list(affinity_cpus_str, cpu_to_check):
                                if cpu_to_check not in irq_cache:
                                    irq_cache[cpu_to_check] = []
                                irq_cache[cpu_to_check].append({
                                    'irq': irq_num,
                                    'queue': queue_num,
                                    'affinity': affinity_cpus_str
                                })
        except Exception: pass
        last_cache_refresh = now

    return irq_cache.get(target_cpu, [])

def print_tx_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(TxEvent)).contents
    if args.cpu is not None and args.cpu != event.cpu: return
    irqs = find_irq_by_queue(TX_DEVICE_PREFIX, event.queue_num)
    irq = irqs[0] if irqs else -1
    irq_cpu = find_cpu_by_irq(irq) or "-"
    if event.ip_proto == 4:
        saddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", int(event.saddr_l)))
        daddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", int(event.daddr_l)))
    else:
        saddr = socket.inet_ntop(socket.AF_INET6, struct.pack("QQ", event.saddr_l, event.saddr_h))
        daddr = socket.inet_ntop(socket.AF_INET6, struct.pack("QQ", event.daddr_l, event.daddr_h))
    lport = socket.ntohs(event.lport)
    rport = socket.ntohs(event.rport)
    printb(b"TX  %-3d %-6d %-7s %-16s %-15s %-26s %-6d %-26s %-6d %-12s" % (
        event.cpu, event.queue_num, str(irq).encode(), event.name, irq_cpu.encode(),
        saddr.encode(), lport, daddr.encode(), rport, str(event.pid).encode()))

def print_rx_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(RxEvent)).contents
    if args.cpu is not None and args.cpu != event.cpu: return
    inferred_info = find_rx_info_by_cpu(event.cpu)
    queue_str = ",".join(sorted(list(set([str(q['queue']) for q in inferred_info])))) or "-"
    irq_str = ",".join(sorted(list(set([str(q['irq']) for q in inferred_info])))) or "-"
    affinity_str = ",".join(sorted(list(set([q['affinity'] for q in inferred_info])))) or "-"
    if event.ip_proto == 4:
        saddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", int(event.saddr_l)))
        daddr = socket.inet_ntop(socket.AF_INET, struct.pack("I", int(event.daddr_l)))
    else:
        saddr = socket.inet_ntop(socket.AF_INET6, struct.pack("QQ", event.saddr_l, event.saddr_h))
        daddr = socket.inet_ntop(socket.AF_INET6, struct.pack("QQ", event.daddr_l, event.daddr_h))
    printb(b"RX  %-3d %-6s %-7s %-16s %-15s %-26s %-6d %-26s %-6d %-12d" % (
        event.cpu, queue_str.encode(), irq_str.encode(), b"(inferred)", affinity_str.encode(),
        saddr.encode(), event.rport, daddr.encode(), event.lport, event.pkt_len))

print("%-4s %-3s %-6s %-7s %-16s %-15s %-26s %-6s %-26s %-6s %-12s" % (
    "DIR", "CPU", "QUEUE", "IRQ", "COMM/NOTE", "IRQ_AFFINITY", "SADDR", "SPORT", "DADDR", "DPORT", "PID/LEN"))
if args.mode in ['tx', 'all']: b["tx_events"].open_perf_buffer(print_tx_event)
if args.mode in ['rx', 'all']: b["rx_events"].open_perf_buffer(print_rx_event)
print("Tracing network events... Hit Ctrl-C to end.")
try:
    while True: b.perf_buffer_poll()
except KeyboardInterrupt: print("\nDetaching...")

