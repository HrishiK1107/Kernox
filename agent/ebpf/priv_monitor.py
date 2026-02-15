"""
Kernox — eBPF Privilege Escalation Monitor

Loads the privilege escalation eBPF program via BCC. Detects
setuid/setgid calls that indicate privilege changes, a key
indicator in the attack kill chain.
"""

import ctypes
import os
import pwd
import sys

from bcc import BPF

from agent.config import BPF_PROGRAM_DIR
from agent.events.event_emitter import EventEmitter


# ── ctypes struct matching the C side ────────────────────────

TASK_COMM_LEN = 16

PRIV_SETUID = 1
PRIV_SETGID = 2

_EVENT_TYPE_NAMES = {
    PRIV_SETUID: "privilege_setuid",
    PRIV_SETGID: "privilege_setgid",
}


class PrivEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("target_id", ctypes.c_uint32),
        ("event_type", ctypes.c_uint8),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
    ]


def _uid_to_username(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


class PrivEscalationMonitor:
    """
    eBPF-based privilege escalation monitor.

    Detects setuid/setgid syscalls that change process privileges.
    Particularly important for detecting escalation from normal
    user (uid!=0) to root (uid=0).
    """

    def __init__(self, emitter: EventEmitter):
        self._emitter = emitter
        self._bpf: BPF | None = None
        self._running = False

    def start(self) -> None:
        self._load_bpf()
        self._attach_callbacks()
        self._running = True

    def poll(self) -> None:
        if self._bpf:
            self._bpf.perf_buffer_poll(timeout=0)

    def stop(self) -> None:
        self._running = False
        if self._bpf:
            self._bpf.cleanup()
            self._bpf = None

    def _load_bpf(self) -> None:
        path = os.path.join(BPF_PROGRAM_DIR, "priv_monitor.c")
        if not os.path.exists(path):
            print(f"[ERROR] BPF source not found: {path}", file=sys.stderr)
            sys.exit(1)

        with open(path) as f:
            src = f.read()

        print("[*] Loading privilege escalation monitor eBPF...", file=sys.stderr)
        self._bpf = BPF(text=src)
        print("[*] Privilege escalation monitor loaded.", file=sys.stderr)

    def _attach_callbacks(self) -> None:
        self._bpf["priv_events"].open_perf_buffer(self._handle_event)

    def _handle_event(self, cpu, data, size) -> None:
        if not self._running:
            return
        try:
            event = ctypes.cast(data, ctypes.POINTER(PrivEvent)).contents

            pid = event.pid
            uid = event.uid
            target_id = event.target_id
            etype = event.event_type
            comm = event.comm.decode("utf-8", errors="replace")
            username = _uid_to_username(uid)

            event_name = _EVENT_TYPE_NAMES.get(etype, f"privilege_unknown_{etype}")

            # Determine severity: escalation to root is CRITICAL
            severity = "MEDIUM"
            if target_id == 0 and uid != 0:
                severity = "CRITICAL"
                event_name = "privilege_escalation_to_root"

            self._emitter.emit({
                "event_type": event_name,
                "pid": pid,
                "ppid": event.ppid,
                "uid": uid,
                "username": username,
                "process_name": comm,
                "target_id": target_id,
                "target_username": _uid_to_username(target_id),
                "severity": severity,
            })
        except Exception:
            pass
