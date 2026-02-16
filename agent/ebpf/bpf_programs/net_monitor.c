/*
 * Kernox — eBPF Network Activity Monitoring Program
 *
 * Attaches to:
 *   - kprobe/tcp_connect  (outbound TCP connections)
 *
 * Captures: PID, PPID, UID, comm, destination IP, destination port
 * Sends structured events to userspace via BPF_PERF_OUTPUT.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define TASK_COMM_LEN 16

/* ── Data structure sent to userspace ────────────────────────── */
struct net_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 daddr;     /* destination IPv4 address */
    u16 dport;     /* destination port */
    u16 protocol;  /* IPPROTO_TCP = 6 */
};

/* ── Perf output ─────────────────────────────────────────────── */
BPF_PERF_OUTPUT(net_events);

/* ─────────────────────────────────────────────────────────────
 *  KPROBE: tcp_connect
 *  Fires when a TCP connection is initiated.
 * ───────────────────────────────────────────────────────────── */
int trace_tcp_connect(struct pt_regs *ctx, struct sock *sk) {
    struct net_event_t event = {};
    struct task_struct *task;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0) return 0;

    event.pid = pid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    task = (struct task_struct *)bpf_get_current_task();
    event.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    /* Read destination address and port from sock struct */
    bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    u16 dport;
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    event.dport = ntohs(dport);
    event.protocol = 6;  /* TCP */

    net_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
