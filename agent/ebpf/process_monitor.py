"""
Kernox — eBPF Process Monitor

Loads the eBPF C program via BCC, attaches to kernel tracepoints,
and reads process execution/exit events from perf buffers.

Enriches events with username and process lineage
before passing them to the EventEmitter.
"""

import ctypes
import os
import pwd
import sys

from bcc import BPF

from agent.config import BPF_PROGRAM_DIR
from agent.events.event_emitter import EventEmitter
from agent.tracking.process_tree import ProcessTree


# ── ctypes structures matching the eBPF C structs ────────────────

ARGSIZE = 128
TASK_COMM_LEN = 16

EVENT_PROCESS_EXEC = 1
EVENT_PROCESS_EXIT = 2


class ExecEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint8),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("filename", ctypes.c_char * ARGSIZE),
    ]


class ExitEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint8),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("exit_code", ctypes.c_int),
    ]


def _uid_to_username(uid: int) -> str:
    """Resolve a UID to a username, falling back to the string UID."""
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


class ProcessMonitor:
    """
    eBPF-based process monitor using BCC.

    Loads the eBPF C program, attaches to tracepoints, and
    continuously polls perf buffers for process events.
    """

    def __init__(self, emitter: EventEmitter, tree: ProcessTree):
        self._emitter = emitter
        self._tree = tree
        self._bpf: BPF | None = None
        self._running = False

    def start(self) -> None:
        """Load the eBPF program and start polling."""
        self._load_bpf()
        self._attach_callbacks()
        self._running = True
        self._poll_loop()

    def stop(self) -> None:
        """Stop the monitor and clean up."""
        self._running = False
        if self._bpf:
            self._bpf.cleanup()
            self._bpf = None

    # ── Internal ─────────────────────────────────────────────

    def _load_bpf(self) -> None:
        """Load the eBPF C program from disk via BCC."""
        bpf_source_path = os.path.join(BPF_PROGRAM_DIR, "process_exec.c")

        if not os.path.exists(bpf_source_path):
            print(f"[ERROR] BPF source not found: {bpf_source_path}", file=sys.stderr)
            sys.exit(1)

        with open(bpf_source_path, "r") as f:
            bpf_source = f.read()

        print("[*] Loading eBPF program...", file=sys.stderr)
        self._bpf = BPF(text=bpf_source)
        print("[*] eBPF program loaded successfully.", file=sys.stderr)

    def _attach_callbacks(self) -> None:
        """Register perf buffer callbacks."""
        self._bpf["exec_events"].open_perf_buffer(self._handle_exec_event)
        self._bpf["exit_events"].open_perf_buffer(self._handle_exit_event)
        print("[*] Perf buffers attached. Monitoring processes...", file=sys.stderr)

    def _poll_loop(self) -> None:
        """Blocking loop that polls perf buffers."""
        while self._running:
            try:
                self._bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[WARN] Perf poll error: {e}", file=sys.stderr)

    # ── Event handlers ───────────────────────────────────────

    def _handle_exec_event(self, cpu, data, size) -> None:
        """Process a process-execution event from the eBPF program."""
        if not self._running:
            return
        try:
            event = ctypes.cast(data, ctypes.POINTER(ExecEvent)).contents

            pid = event.pid
            ppid = event.ppid
            uid = event.uid
            comm = event.comm.decode("utf-8", errors="replace")
            filename = event.filename.decode("utf-8", errors="replace")
            username = _uid_to_username(uid)

            # Update the process tree
            self._tree.add_process(
                pid=pid,
                ppid=ppid,
                comm=comm,
                cmdline=filename,
                uid=uid,
                username=username,
            )

            # Get lineage from the tree
            lineage = self._tree.get_lineage_string(pid)

            # Emit enriched event
            self._emitter.emit({
                "event_type": "process_start",
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "username": username,
                "process_name": comm,
                "filename": filename,
                "lineage": lineage,
            })
        except Exception:
            pass

    def _handle_exit_event(self, cpu, data, size) -> None:
        """Process a process-exit event from the eBPF program."""
        if not self._running:
            return
        try:
            event = ctypes.cast(data, ctypes.POINTER(ExitEvent)).contents

            pid = event.pid
            ppid = event.ppid
            uid = event.uid
            comm = event.comm.decode("utf-8", errors="replace")
            exit_code = event.exit_code
            username = _uid_to_username(uid)

            # Get lineage before removing from tree
            lineage = self._tree.get_lineage_string(pid)

            # Emit exit event
            self._emitter.emit({
                "event_type": "process_stop",
                "pid": pid,
                "ppid": ppid,
                "uid": uid,
                "username": username,
                "process_name": comm,
                "exit_code": exit_code,
                "lineage": lineage,
            })

            # Remove from process tree
            self._tree.remove_process(pid)
        except Exception:
            pass
