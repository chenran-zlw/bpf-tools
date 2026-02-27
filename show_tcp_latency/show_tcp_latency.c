#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include "show_tcp_latency.h"
#include "show_tcp_latency.skel.h"

static struct env {
    int rx_port;
    int tx_port;
} env = {0, 0};

static const struct argp_option opts[] = {
    {"rx-port", 'r', "PORT", 0, "Proxy listening port (e.g. 99)"},
    {"tx-port", 't', "PORT", 0, "Backend RS port (e.g. 999)"},
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    if (key == 'r') env.rx_port = atoi(arg);
    else if (key == 't') env.tx_port = atoi(arg);
    else if (key == ARGP_KEY_ARG) argp_usage(state);
    return 0;
}

static const struct argp argp = { .options = opts, .parser = parse_arg };
static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

static int bump_memlock_rlimit(void) {
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static const char* type_to_str(int type) {
    switch (type) {
        case TYPE_NETIF_RECEIVE_SKB: return "NET_RECV";
        case TYPE_IP_RCV_FINISH:     return "IP_RCV";
        case TYPE_TCP_V4_DO_RCV:     return "TCP_RCV";
        case TYPE_SOCK_DEF_READABLE: return "SOCK_READABLE";
        case TYPE_TCP_CLEANUP_RBUF:  return "TCP_CLEAN_RBUF";
        case TYPE_IP_OUTPUT:         return "IP_OUT";
        case TYPE_DEV_HARD_START_XMIT: return "NIC_XMIT";
        default: return "UNKNOWN";
    }
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct event_t *e = data;
    char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
    char time_buf[64];
    struct tm *tm_info;
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    tm_info = localtime(&ts.tv_sec);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    inet_ntop(AF_INET, &e->saddr, s, sizeof(s));
    inet_ntop(AF_INET, &e->daddr, d, sizeof(d));

    printf("%s.%03ld %-15s %15s:%-5d -> %15s:%-5d ",
           time_buf, ts.tv_nsec / 1000000, type_to_str(e->type),
           s, e->sport, d, e->dport);
    
    if (e->type == TYPE_TCP_CLEANUP_RBUF)
        printf("[Copied: %u, Seq: %u]\n", e->copied, e->copied_seq);
    else
        printf("[Seq: %u, Ack: %u]\n", e->seq, e->ack_seq);
}

int main(int argc, char **argv) {
    struct show_tcp_latency_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) return err;

    if (bump_memlock_rlimit()) return 1;

    skel = show_tcp_latency_bpf__open();
    if (!skel) return 1;

    skel->rodata->target_rx_port = (unsigned short)env.rx_port;
    skel->rodata->target_tx_port = (unsigned short)env.tx_port;

    err = show_tcp_latency_bpf__load(skel);
    if (err) goto cleanup;

    err = show_tcp_latency_bpf__attach(skel);
    if (err) goto cleanup;
    
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64, &(struct perf_buffer_opts){
        .sample_cb = handle_event,
    });
    if (!pb) goto cleanup;

    printf("Tracing... (Ctrl-C to stop)\n");
    printf("%-23s %-15s %-21s    %-21s %s\n", "TIME", "EVENT", "SOURCE", "DESTINATION", "DETAILS");
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) break;
    }

cleanup:
    perf_buffer__free(pb);
    show_tcp_latency_bpf__destroy(skel);
    return 0;
}
