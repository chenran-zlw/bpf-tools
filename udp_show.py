#!/usr/libexec/platform-python

from __future__ import print_function
from bcc import BPF
import argparse
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import sleep, strftime
from subprocess import call
from collections import namedtuple, defaultdict
from bcc.utils import printb

def range_check(string):
    value = int(string)
    if value < 1:
        msg = "value must be stricly positive, got %d" % (value,)
        raise argparse.ArgumentTypeError(msg)
    return value

examples = """examples:
    ./udpshow          # trace virtqueue deal with udp
    ./udptop -p 181    # only trace PID 181
"""

parser = argparse.ArgumentParser(
    description="trace virtqueue deal with udp",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid",
    help="trace this PID only")
parser.add_argument("-c", "--cpu", type=int,
    help="trace this CPU only")
parser.add_argument("interval", nargs="?", default=1, type=range_check,
    help="output interval, in seconds (default 1)")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

bpf_text ="""
#include <uapi/linux/udp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <uapi/linux/ip.h>
#include <linux/virtio.h>
#include <linux/scatterlist.h>
#include <net/xsk_buff_pool.h>
#include <linux/mm_types.h>
#include <uapi/linux/if_xdp.h>
#include <linux/hrtimer.h>
#include <uapi/linux/virtio_net.h>

struct udp_key_t {
    u32 pid;
    char name[TASK_COMM_LEN];
    unsigned int saddr;
    unsigned int daddr;
    unsigned short lport;
    unsigned short dport;
    u32 cpu;
    u16 queue_num;
    u8 ip_proto;
};
BPF_PERF_OUTPUT(udp_events);


int kprobe__dev_hard_start_xmit(struct pt_regs *ctx, struct sk_buff *first, struct net_device *dev,
				    struct netdev_queue *txq, int *ret)
{
    struct iphdr ih ={};
    struct udphdr uh ={};
    u16 network_header,transport_header;
    char *head;

    bpf_probe_read(&head, sizeof(head), &first->head);
    bpf_probe_read(&network_header, sizeof(network_header), &first->network_header);

    if (network_header != 0)
    {
       bpf_probe_read(&ih, sizeof(ih), head+network_header); 
       transport_header = network_header + (ih.ihl << 2);
    }

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID
    u32 tid = bpf_get_current_pid_tgid();

    struct udp_key_t evt = {.pid = pid};
    evt.ip_proto = ih.protocol;
    evt.cpu = bpf_get_smp_processor_id();
    bpf_get_current_comm(&evt.name, sizeof(evt.name));

    evt.saddr = ih.saddr;
    evt.daddr = ih.daddr;

    if (evt.ip_proto == 17)
    {
        if (transport_header != 0 && transport_header != 0xffff)
        {
            bpf_probe_read(&uh, sizeof(uh), head+transport_header);
            evt.lport = uh.source;
            evt.dport = uh.dest;
        }
    }

    bpf_probe_read(&evt.queue_num, sizeof(evt.queue_num), &first->queue_mapping);
    
    udp_events.perf_submit(ctx, &evt, sizeof(evt));
        
    return 0;
}
"""

if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

def print_udp_event(cpu, data, size):
    event = b["udp_events"].event(data)
    printb(b"%-5d %-5d %-7d %-12s %-16s %-5d %-16s %-5d" % (event.cpu, event.queue_num, event.pid,
        event.name, 
        inet_ntop(AF_INET, pack("I", event.daddr)).encode(),
        event.dport,
        inet_ntop(AF_INET, pack("I", event.saddr)).encode(),
        event.lport))

b = BPF(text=bpf_text)

print("%-5s %-5s %-7s %-12s %-16s %-5s %-16s %-5s" % ("CPU", "QUEUE", "PID", "COMM", "RADDR", "RPORT", "LADDR", "LPORT"))

b["udp_events"].open_perf_buffer(print_udp_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()

