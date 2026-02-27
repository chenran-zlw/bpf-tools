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

static struct env { int rx; int tx; } env = {0, 0};
static const struct argp_option opts[] = {
    {"rx-port", 'r', "PORT", 0, "Proxy listen port"},
    {"tx-port", 't', "PORT", 0, "Backend RS port"},
    {},
};
static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    if (key == 'r') env.rx = atoi(arg);
    else if (key == 't') env.tx = atoi(arg);
    return 0;
}
static const struct argp argp = { .options = opts, .parser = parse_arg };
static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

static int bump_memlock_rlimit(void) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    return setrlimit(RLIMIT_MEMLOCK, &r);
}

static const char* type_to_str(int type) {
    switch (type) {
        case TYPE_NETIF_RECEIVE_SKB: return "NET_RECV";
        case TYPE_IP_RCV_FINISH:     return "IP_RCV";
        case TYPE_TCP_V4_DO_RCV:     return "TCP_DO_RCV";
        case TYPE_TCP_QUEUE_RCV:     return "TCP_QUEUE_RCV";
        case TYPE_SOCK_DEF_READABLE: return "SOCK_READABLE";
        case TYPE_TCP_CLEANUP_RBUF:  return "TCP_CLEAN_RBUF";
        case TYPE_IP_OUTPUT:         return "IP_OUT";
        case TYPE_DEV_HARD_START_XMIT: return "NIC_XMIT";
        default: return "UNKNOWN";
    }
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    const struct event_t *e = data;
    char s[64], d[64], tbuf[64];
    struct tm *tm;
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    tm = localtime(&ts.tv_sec);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);
    
    inet_ntop(AF_INET, &e->saddr, s, sizeof(s));
    inet_ntop(AF_INET, &e->daddr, d, sizeof(d));

    printf("%s.%03ld %-15s %15s:%-5d -> %15s:%-5d ",
           tbuf, ts.tv_nsec / 1000000, type_to_str(e->type), s, e->sport, d, e->dport);
    
    if (e->type == TYPE_TCP_CLEANUP_RBUF)
        printf("[Copied: %u, C_Seq: %u]\n", e->copied, e->copied_seq);
    else
        printf("[Seq: %u, Ack: %u]\n", e->seq, e->ack_seq);
}

int main(int argc, char **argv) {
    struct show_tcp_latency_bpf *skel;
    struct perf_buffer *pb = NULL;
    int err;

    argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (bump_memlock_rlimit()) fprintf(stderr, "Memlock limit bump failed\n");

    skel = show_tcp_latency_bpf__open();
    if (!skel) return 1;

    skel->rodata->target_rx_port = (unsigned short)env.rx;
    skel->rodata->target_tx_port = (unsigned short)env.tx;

    err = show_tcp_latency_bpf__load(skel);
    if (err) { fprintf(stderr, "Load failed\n"); goto cleanup; }

    err = show_tcp_latency_bpf__attach(skel);
    if (err) { fprintf(stderr, "Attach failed\n"); goto cleanup; }
    
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 64, &(struct perf_buffer_opts){
        .sample_cb = handle_event,
    });

    printf("Tracing A-B-C latency... (Ctrl-C to stop)\n");
    printf("%-23s %-15s %-21s    %-21s %s\n", "TIME", "EVENT", "SOURCE", "DESTINATION", "DETAILS");
    
    signal(SIGINT, sig_handler);
    while (!exiting) { perf_buffer__poll(pb, 100); }

cleanup:
    perf_buffer__free(pb);
    show_tcp_latency_bpf__destroy(skel);
    return 0;
}
