/*
 * Kernox — eBPF File Activity Monitoring Program
 *
 * Attaches to:
 *   - tracepoint/syscalls/sys_enter_openat   (file open)
 *   - tracepoint/syscalls/sys_enter_write    (file write)
 *   - tracepoint/syscalls/sys_enter_renameat2 (file rename)
 *
 * Captures: PID, PPID, UID, comm, filename, flags
 * Sends structured events to userspace via BPF_PERF_OUTPUT.
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define FNAME_SIZE     128
#define TASK_COMM_LEN   16

/* ── Event types ─────────────────────────────────────────────── */
enum file_event_type {
    FILE_EVENT_OPEN   = 1,
    FILE_EVENT_WRITE  = 2,
    FILE_EVENT_RENAME = 3,
};

/* ── Data structure sent to userspace ────────────────────────── */
struct file_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u8  event_type;
    char comm[TASK_COMM_LEN];
    char filename[FNAME_SIZE];
    u32 flags;       /* open flags or write count */
};

/* ── Perf output ─────────────────────────────────────────────── */
BPF_PERF_OUTPUT(file_events);

/* ── Per-CPU scratch space ───────────────────────────────────── */
BPF_PERCPU_ARRAY(file_scratch, struct file_event_t, 1);

/* ── Helper: fill common fields ──────────────────────────────── */
static __always_inline int fill_common(struct file_event_t *event) {
    struct task_struct *task;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0) return -1;

    event->pid = pid;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    task = (struct task_struct *)bpf_get_current_task();
    event->ppid = task->real_parent->tgid;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    return 0;
}

/* ─────────────────────────────────────────────────────────────
 *  TRACEPOINT: sys_enter_openat
 * ───────────────────────────────────────────────────────────── */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    int zero = 0;
    struct file_event_t *event = file_scratch.lookup(&zero);
    if (!event) return 0;

    if (fill_common(event) < 0) return 0;

    event->event_type = FILE_EVENT_OPEN;
    event->flags = args->flags;

    const char *fname = args->filename;
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), fname);

    file_events.perf_submit(args, event, sizeof(*event));
    return 0;
}

/* ─────────────────────────────────────────────────────────────
 *  TRACEPOINT: sys_enter_write
 *  We capture which process is writing and how many bytes.
 * ───────────────────────────────────────────────────────────── */
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    int zero = 0;
    struct file_event_t *event = file_scratch.lookup(&zero);
    if (!event) return 0;

    if (fill_common(event) < 0) return 0;

    event->event_type = FILE_EVENT_WRITE;
    event->flags = args->count;  /* bytes being written */
    event->filename[0] = '\0';   /* fd-based, no filename available */

    file_events.perf_submit(args, event, sizeof(*event));
    return 0;
}

/* ─────────────────────────────────────────────────────────────
 *  TRACEPOINT: sys_enter_renameat2
 * ───────────────────────────────────────────────────────────── */
TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    int zero = 0;
    struct file_event_t *event = file_scratch.lookup(&zero);
    if (!event) return 0;

    if (fill_common(event) < 0) return 0;

    event->event_type = FILE_EVENT_RENAME;
    event->flags = 0;

    const char *oldname = args->oldname;
    bpf_probe_read_user_str(&event->filename, sizeof(event->filename), oldname);

    file_events.perf_submit(args, event, sizeof(*event));
    return 0;
}
