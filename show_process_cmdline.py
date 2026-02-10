#!/usr/bin/python3
# -*- coding: utf-8 -*-
from bcc import BPF
import argparse
import ctypes as ct
import time

parser = argparse.ArgumentParser(
    description="Trace exec() syscalls and show command line arguments",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-p", "--pid", help="trace this PID only")
args = parser.parse_args()

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

#define ARGSIZE  128
#define MAXARG   20
#define TASK_COMM_LEN 16

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char argv[MAXARG][ARGSIZE];
};

BPF_PERF_OUTPUT(events);
BPF_PERCPU_ARRAY(data_map, struct data_t, 1);

static int __bpf_read_arg_str(struct data_t *data, const char *const *argv, int id) {
    const char *argp = NULL;
    bpf_probe_read_user(&argp, sizeof(argp), &argv[id]);
    if (argp) {
        bpf_probe_read_user_str(&data->argv[id], ARGSIZE, argp);
        return 1;
    }
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    FILTER_PID

    u32 zero = 0;
    struct data_t *data = data_map.lookup(&zero);
    if (!data) {
        return 0;
    }

    data->pid = pid;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    const char *const *argv = (const char *const *)args->argv;

    int i;
    #pragma unroll
    for (i = 0; i < MAXARG; i++) {
        if (__bpf_read_arg_str(data, argv, i) == 0) {
            goto EOA;
        }
    }

EOA:
    if (i < MAXARG) {
        data->argv[i][0] = '\\0';
    }

    events.perf_submit(args, data, sizeof(struct data_t));
    return 0;
}
"""

if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '')

ARGSIZE = 128
MAXARG = 20
TASK_COMM_LEN = 16

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("argv", (ct.c_char * ARGSIZE) * MAXARG)
    ]

try:
    b = BPF(text=bpf_text)
except Exception as e:
    print(f"Failed to load BPF program: {e}")
    exit(1)

print("Tracing exec() syscalls... Ctrl-C to stop.")
print("%-20s %-6s %-16s %s" % ("TIME", "PID", "COMM", "ARGS"))

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    argv_list = []
    for i in range(MAXARG):
        arg_bytes = event.argv[i].value
        arg = arg_bytes.decode('utf-8', 'replace')

        if arg:
            argv_list.append(arg)
        else:
            break

    argv_str = " ".join(argv_list)

    print("%-20s %-6d %-16s %s" % (
        time.strftime("%Y-%m-%d %H:%M:%S"),
        event.pid,
        event.comm.decode('utf-8', 'replace'),
        argv_str
    ))

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching...")
        exit()
