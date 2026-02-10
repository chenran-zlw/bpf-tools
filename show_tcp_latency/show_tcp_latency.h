#ifndef __SHOW_TCP_LATENCY_H
#define __SHOW_TCP_LATENCY_H

#define MAX_COMM_LEN 16

enum event_type {
    TYPE_NETIF_RECEIVE_SKB = 1,
    TYPE_IP_RCV_FINISH,
    TYPE_TCP_V4_DO_RCV,
    TYPE_TCP_QUEUE_RCV,
    TYPE_SOCK_DEF_READABLE,
    TYPE_TCP_CLEANUP_RBUF,
    TYPE_IP_OUTPUT,
    TYPE_DEV_HARD_START_XMIT
};

struct event_t {
    unsigned int saddr;
    unsigned int daddr;
    unsigned short sport;
    unsigned short dport;
    unsigned int seq;
    unsigned int ack_seq;
    unsigned long long ts;
    unsigned int type;
    unsigned int copied;      // For tcp_cleanup_rbuf
    unsigned int copied_seq;  // For tcp_cleanup_rbuf
};

#endif /* __SHOW_TCP_LATENCY_H */

