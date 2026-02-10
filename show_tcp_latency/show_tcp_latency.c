#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include "show_tcp_latency.h"
#include "show_tcp_latency.skel.h"

static struct env {
    int rx_port;
    int tx_port;
    bool verbose;
} env = {
    .rx_port = 0,
    .tx_port = 0,
    .verbose = false,
};

const char *argp_program_version = "show_tcp_latency 1.0";
const char *argp_program_bug_address = "<chenran.zlw@alibaba-inc.com>";
const char argp_program_doc[] =
    "Trace TCP packet latency.\n"
    "\n"
    "USAGE: ./show_tcp_latency [-r RX_PORT] [-t TX_PORT]\n";

static const struct argp_option opts[] = {
    {"rx-port", 'r', "PORT", 0, "Rx destination port to filter (default 0)"},
    {"tx-port", 't', "PORT", 0, "Tx destination port to filter (default 0)"},
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
    case 'r':
        env.rx_port = atoi(arg);
        break;
    case 't':
        env.tx_port = atoi(arg);
        break;
    case 'v':
        env.verbose = true;
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static const char* type_to_str(int type) {
    switch (type) {
        case TYPE_NETIF_RECEIVE_SKB: return "netif_receive_skb";
        case TYPE_IP_RCV_FINISH: return "ip_rcv_finish";
        case TYPE_TCP_V4_DO_RCV: return "tcp_v4_do_rcv";
        case TYPE_TCP_QUEUE_RCV: return "tcp_queue_rcv";
        case TYPE_SOCK_DEF_READABLE: return "sock_def_readable";
        case TYPE_TCP_CLEANUP_RBUF: return "tcp_cleanup_rbuf";
        case TYPE_IP_OUTPUT: return "ip_output";
        case TYPE_DEV_HARD_START_XMIT: return "dev_hard_start_xmit";
        default: return "unknown";
    }
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct event_t *e = data;
    char saddr[INET_ADDRSTRLEN];
    char daddr[INET_ADDRSTRLEN];
    char ts_buf[64];
    struct tm *tm_info;
    struct timespec ts;
    
    inet_ntop(AF_INET, &e->saddr, saddr, sizeof(saddr));
    inet_ntop(AF_INET, &e->daddr, daddr, sizeof(daddr));

    clock_gettime(CLOCK_REALTIME, &ts);
    tm_info = localtime(&ts.tv_sec);
    strftime(ts_buf, sizeof(ts_buf), "%F-%T", tm_info);

    printf("%s.%06ld %-20s IP src %s, dst %s, TCP src port %d, dst port %d ",
           ts_buf, ts.tv_nsec / 1000,
           type_to_str(e->type),
           saddr, daddr, e->sport, e->dport);
    
    if (e->type == TYPE_TCP_CLEANUP_RBUF) {
        printf("copied: %u, copied_seq: %u\n", e->copied, e->copied_seq);
    } else {
        printf("seq: %u, ack_seq: %u\n", e->seq, e->ack_seq);
    }
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

int main(int argc, char **argv) {
    struct show_tcp_latency_bpf *skel;
    struct perf_buffer *pb = NULL;
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    int err;

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Warning: Failed to increase RLIMIT_MEMLOCK limit. You may need to run as root or manually run 'ulimit -l unlimited'.\n");
    }

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_print(libbpf_print_fn);

    skel = show_tcp_latency_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    skel->rodata->target_rx_port = env.rx_port;
    skel->rodata->target_tx_port = env.tx_port;

    err = show_tcp_latency_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = show_tcp_latency_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }
    
    struct perf_buffer_opts pb_opts = {};
    pb_opts.sample_cb = handle_event;
    pb_opts.lost_cb = handle_lost_events;

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, &pb_opts);
    if (!pb) {
        err = -1;
        fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Tracing TCP latency... RxPort: %d, TxPort: %d. Hit Ctrl-C to end.\n", 
           env.rx_port, env.tx_port);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        err = perf_buffer__poll(pb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    perf_buffer__free(pb);
    show_tcp_latency_bpf__destroy(skel);

    return -err;
}

