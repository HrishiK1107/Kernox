/*
 * Kernox — eBPF Privilege Escalation Detection Program
 *
 * Attaches to:
 *   - tracepoint/syscalls/sys_enter_setuid   (setuid calls)
 *   - tracepoint/syscalls/sys_enter_setgid   (setgid calls)
 *
 * Also detects sudo by matching comm in execve events
 * (handled in Python side via process_monitor).
 *
 * Sends structured events to userspace via BPF_PERF_OUTPUT.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TASK_COMM_LEN 16

/* ── Event types ─────────────────────────────────────────────── */
enum priv_event_type {
    PRIV_SETUID = 1,
    PRIV_SETGID = 2,
};

/* ── Data structure sent to userspace ────────────────────────── */
struct priv_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;           /* current UID */
    u32 target_id;     /* target UID/GID being set to */
    u8  event_type;
    char comm[TASK_COMM_LEN];
};

/* ── Perf output ─────────────────────────────────────────────── */
BPF_PERF_OUTPUT(priv_events);

/* ─────────────────────────────────────────────────────────────
 *  TRACEPOINT: sys_enter_setuid
 * ───────────────────────────────────────────────────────────── */
TRACEPOINT_PROBE(syscalls, sys_enter_setuid) {
    struct priv_event_t event = {};
    struct task_struct *task;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0) return 0;

    event.pid = pid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.target_id = args->uid;
    event.event_type = PRIV_SETUID;

    task = (struct task_struct *)bpf_get_current_task();
    event.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    priv_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

/* ─────────────────────────────────────────────────────────────
 *  TRACEPOINT: sys_enter_setgid
 * ───────────────────────────────────────────────────────────── */
TRACEPOINT_PROBE(syscalls, sys_enter_setgid) {
    struct priv_event_t event = {};
    struct task_struct *task;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0) return 0;

    event.pid = pid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.target_id = args->gid;
    event.event_type = PRIV_SETGID;

    task = (struct task_struct *)bpf_get_current_task();
    event.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    priv_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
