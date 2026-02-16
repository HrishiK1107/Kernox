"""
Kernox — eBPF File Activity Monitor

Loads the file monitoring eBPF program via BCC. Tracks file opens,
writes, and renames. Detects rapid file modification bursts
(potential ransomware indicator).
"""

import ctypes
import os
import pwd
import sys
import time
import threading
from collections import defaultdict

from bcc import BPF

from agent.config import BPF_PROGRAM_DIR
from agent.events.event_emitter import EventEmitter


# ── ctypes struct matching the C side ────────────────────────

FNAME_SIZE = 128
TASK_COMM_LEN = 16

FILE_EVENT_OPEN = 1
FILE_EVENT_WRITE = 2
FILE_EVENT_RENAME = 3

_EVENT_TYPE_NAMES = {
    FILE_EVENT_OPEN: "file_open",
    FILE_EVENT_WRITE: "file_write",
    FILE_EVENT_RENAME: "file_rename",
}

_EVENT_SEVERITY = {
    FILE_EVENT_OPEN: "info",
    FILE_EVENT_WRITE: "low",
    FILE_EVENT_RENAME: "medium",
}


class FileEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint8),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("filename", ctypes.c_char * FNAME_SIZE),
        ("flags", ctypes.c_uint32),
    ]


def _uid_to_username(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


class FileMonitor:
    """
    eBPF-based file activity monitor.

    Detects file open/write/rename events and tracks rapid file
    modification bursts (configurable threshold).
    """

    # Burst detection: if a PID writes more than BURST_THRESHOLD files
    # within BURST_WINDOW_SEC seconds, emit a ransomware warning.
    BURST_THRESHOLD = 20
    BURST_WINDOW_SEC = 5.0

    def __init__(self, emitter: EventEmitter):
        self._emitter = emitter
        self._bpf: BPF | None = None
        self._running = False
        # Burst tracking: pid -> list of timestamps
        self._write_times: dict[int, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def start(self) -> None:
        self._load_bpf()
        self._attach_callbacks()
        self._running = True

    def poll(self) -> None:
        """Poll perf buffer once (called from main loop)."""
        if self._bpf:
            self._bpf.perf_buffer_poll(timeout=0)

    def stop(self) -> None:
        self._running = False
        if self._bpf:
            self._bpf.cleanup()
            self._bpf = None

    def _load_bpf(self) -> None:
        path = os.path.join(BPF_PROGRAM_DIR, "file_monitor.c")
        if not os.path.exists(path):
            print(f"[ERROR] BPF source not found: {path}", file=sys.stderr)
            sys.exit(1)

        with open(path) as f:
            src = f.read()

        print("[*] Loading file monitor eBPF...", file=sys.stderr)
        self._bpf = BPF(text=src)
        print("[*] File monitor loaded.", file=sys.stderr)

    def _attach_callbacks(self) -> None:
        self._bpf["file_events"].open_perf_buffer(self._handle_event)

    def _handle_event(self, cpu, data, size) -> None:
        if not self._running:
            return
        try:
            event = ctypes.cast(data, ctypes.POINTER(FileEvent)).contents

            pid = event.pid
            uid = event.uid
            etype = event.event_type
            comm = event.comm.decode("utf-8", errors="replace")
            fname = event.filename.decode("utf-8", errors="replace")
            username = _uid_to_username(uid)

            event_name = _EVENT_TYPE_NAMES.get(etype, "file_open")
            severity = _EVENT_SEVERITY.get(etype, "info")

            self._emitter.emit({
                "event_type": event_name,
                "severity": severity,
                "pid": pid,
                "ppid": event.ppid,
                "uid": uid,
                "username": username,
                "process_name": comm,
                "filename": fname,
                "flags": event.flags,
            })

            # Burst detection for writes and renames
            if etype in (FILE_EVENT_WRITE, FILE_EVENT_RENAME):
                self._check_burst(pid, comm, username)
        except Exception:
            pass

    def _check_burst(self, pid: int, comm: str, username: str) -> None:
        now = time.time()
        with self._lock:
            times = self._write_times[pid]
            times.append(now)
            # Prune old entries outside the window
            cutoff = now - self.BURST_WINDOW_SEC
            self._write_times[pid] = [t for t in times if t > cutoff]

            if len(self._write_times[pid]) >= self.BURST_THRESHOLD:
                self._emitter.emit({
                    "event_type": "alert_ransomware_burst",
                    "severity": "high",
                    "pid": pid,
                    "username": username,
                    "process_name": comm,
                    "burst_count": len(self._write_times[pid]),
                    "window_seconds": self.BURST_WINDOW_SEC,
                })
                # Reset to avoid spamming
                self._write_times[pid] = []
