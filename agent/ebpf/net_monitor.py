"""
Kernox — eBPF Network Activity Monitor

Loads the network monitoring eBPF program via BCC. Tracks outbound
TCP connections with destination IP, port, and responsible process.
Detects C2 beaconing patterns (periodic connections to same dest).
"""

import ctypes
import os
import pwd
import socket
import struct
import sys
import time
import threading
from collections import defaultdict

from bcc import BPF

from agent.config import BPF_PROGRAM_DIR
from agent.events.event_emitter import EventEmitter


# ── ctypes struct matching the C side ────────────────────────

TASK_COMM_LEN = 16


class NetEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("daddr", ctypes.c_uint32),
        ("dport", ctypes.c_uint16),
        ("protocol", ctypes.c_uint16),
    ]


def _uid_to_username(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _int_to_ip(addr: int) -> str:
    """Convert a 32-bit network-order integer to dotted IP string."""
    return socket.inet_ntoa(struct.pack("I", addr))


class NetworkMonitor:
    """
    eBPF-based network activity monitor.

    Tracks outbound TCP connections and detects C2-style beaconing
    (repeated connections to the same IP:port).
    """

    # Beaconing detection: if a PID connects to the same dest
    # more than BEACON_THRESHOLD times in BEACON_WINDOW_SEC, alert.
    BEACON_THRESHOLD = 10
    BEACON_WINDOW_SEC = 60.0

    def __init__(self, emitter: EventEmitter):
        self._emitter = emitter
        self._bpf: BPF | None = None
        self._running = False
        # Beaconing tracker: (pid, daddr, dport) -> [timestamps]
        self._conn_times: dict[tuple, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

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
        path = os.path.join(BPF_PROGRAM_DIR, "net_monitor.c")
        if not os.path.exists(path):
            print(f"[ERROR] BPF source not found: {path}", file=sys.stderr)
            sys.exit(1)

        with open(path) as f:
            src = f.read()

        print("[*] Loading network monitor eBPF...", file=sys.stderr)
        self._bpf = BPF(text=src)
        self._bpf.attach_kprobe(event="tcp_connect", fn_name="trace_tcp_connect")
        print("[*] Network monitor loaded.", file=sys.stderr)

    def _attach_callbacks(self) -> None:
        self._bpf["net_events"].open_perf_buffer(self._handle_event)

    def _handle_event(self, cpu, data, size) -> None:
        if not self._running:
            return
        try:
            event = ctypes.cast(data, ctypes.POINTER(NetEvent)).contents

            pid = event.pid
            uid = event.uid
            comm = event.comm.decode("utf-8", errors="replace")
            username = _uid_to_username(uid)
            daddr = _int_to_ip(event.daddr)
            dport = event.dport

            self._emitter.emit({
                "event_type": "network_connect",
                "severity": "low",
                "pid": pid,
                "ppid": event.ppid,
                "uid": uid,
                "username": username,
                "process_name": comm,
                "dest_ip": daddr,
                "dest_port": dport,
                "protocol": "TCP",
            })

            # Beaconing detection
            self._check_beaconing(pid, daddr, dport, comm, username)
        except Exception:
            pass

    def _check_beaconing(
        self, pid: int, daddr: str, dport: int, comm: str, username: str
    ) -> None:
        now = time.time()
        key = (pid, daddr, dport)

        with self._lock:
            times = self._conn_times[key]
            times.append(now)
            cutoff = now - self.BEACON_WINDOW_SEC
            self._conn_times[key] = [t for t in times if t > cutoff]

            if len(self._conn_times[key]) >= self.BEACON_THRESHOLD:
                self._emitter.emit({
                    "event_type": "alert_c2_beaconing",
                    "severity": "high",
                    "pid": pid,
                    "username": username,
                    "process_name": comm,
                    "dest_ip": daddr,
                    "dest_port": dport,
                    "connection_count": len(self._conn_times[key]),
                    "window_seconds": self.BEACON_WINDOW_SEC,
                })
                self._conn_times[key] = []
