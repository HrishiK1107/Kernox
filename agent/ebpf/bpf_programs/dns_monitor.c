/*
 * Kernox — DNS Query Monitor (eBPF)
 *
 * Hooks udp_sendmsg to capture outbound DNS queries (port 53).
 * Extracts destination IP and the DNS query domain name from
 * the UDP payload.
 */

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/in.h>

#define MAX_DNS_NAME 128

struct dns_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u8  event_type;    // 0 = dns_query
    char comm[16];
    u32 dest_ip;
    u16 dest_port;
    char dns_name[MAX_DNS_NAME];
};

BPF_PERCPU_ARRAY(dns_scratch, struct dns_event_t, 1);
BPF_PERF_OUTPUT(dns_events);

/* Extract DNS query name from raw packet data */
static inline int parse_dns_name(struct msghdr *msg, char *out, int max_len) {
    // DNS query starts at byte 12 of UDP payload
    // We'll try to read labels from the query section
    struct iov_iter *iter;
    const struct iovec *iov;
    void *base;
    u32 len;

    // Zero out
    __builtin_memset(out, 0, max_len);

    // Try to read from iovec
    bpf_probe_read(&iter, sizeof(iter), &msg->msg_iter);

    // Read first iov
    bpf_probe_read(&iov, sizeof(iov), &iter->iov);
    if (!iov) return 0;

    bpf_probe_read(&base, sizeof(base), &iov->iov_base);
    bpf_probe_read(&len, sizeof(len), &iov->iov_len);

    if (len < 17 || len > 512) return 0;

    // DNS header is 12 bytes, query starts at offset 12
    // Read up to MAX_DNS_NAME bytes of the query name
    char buf[MAX_DNS_NAME];
    __builtin_memset(buf, 0, sizeof(buf));

    int to_read = len - 12;
    if (to_read > MAX_DNS_NAME - 1) to_read = MAX_DNS_NAME - 1;
    if (to_read <= 0) return 0;

    bpf_probe_read_user(buf, to_read, base + 12);

    // Convert DNS label format (3www6google3com0) to dotted (www.google.com)
    int i = 0, j = 0;
    #pragma unroll
    for (int iter = 0; iter < 64; iter++) {
        if (i >= to_read || i >= MAX_DNS_NAME - 1) break;
        u8 label_len = (u8)buf[i];
        if (label_len == 0) break;
        if (label_len > 63) break;

        if (j > 0 && j < max_len - 1) {
            out[j++] = '.';
        }
        i++;

        #pragma unroll
        for (int k = 0; k < 63; k++) {
            if (k >= label_len) break;
            if (i >= to_read || j >= max_len - 1) break;
            out[j++] = buf[i++];
        }
    }
    out[j] = '\0';
    return j;
}

int trace_udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len) {
    int zero = 0;
    struct dns_event_t *event = dns_scratch.lookup(&zero);
    if (!event) return 0;

    // Only capture UDP to port 53 (DNS)
    u16 dport = 0;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    dport = ntohs(dport);

    if (dport != 53) return 0;

    // Fill event
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();

    event->pid = pid_tgid >> 32;
    event->uid = uid_gid & 0xFFFFFFFF;
    event->event_type = 0;
    event->dest_port = dport;

    // Get PPID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = 0;
    bpf_probe_read_kernel(&ppid, sizeof(ppid),
        &task->real_parent->tgid);
    event->ppid = ppid;

    // Get comm
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Get dest IP
    u32 daddr = 0;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    event->dest_ip = daddr;

    // Try to parse DNS name
    parse_dns_name(msg, event->dns_name, MAX_DNS_NAME);

    dns_events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}
