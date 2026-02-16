"""
Kernox — DNS Query Monitor

eBPF-based monitor that captures outbound DNS queries (UDP port 53).
Hooks udp_sendmsg kprobe to detect what domains endpoints are resolving.

Detects:
  - All DNS queries with domain name
  - Suspicious domain patterns (long domains, high entropy — potential DGA)
"""

import ctypes
import os
import math
from collections import Counter

from agent.logging_config import logger

TASK_COMM_LEN = 16
MAX_DNS_NAME = 128


class DnsEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint8),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("dest_ip", ctypes.c_uint32),
        ("dest_port", ctypes.c_uint16),
        ("dns_name", ctypes.c_char * MAX_DNS_NAME),
    ]


class DnsMonitor:
    """
    Hooks udp_sendmsg to capture outbound DNS queries.
    """

    # DGA detection thresholds
    DGA_MIN_LENGTH = 20     # suspicious if domain part > 20 chars
    DGA_ENTROPY_THRESH = 3.5  # Shannon entropy threshold

    def __init__(self, emitter):
        self._emitter = emitter
        self._bpf = None
        self._running = False

    def start(self) -> None:
        """Load eBPF program and attach kprobe."""
        try:
            from bcc import BPF

            bpf_path = os.path.join(
                os.path.dirname(__file__), "bpf_programs", "dns_monitor.c"
            )
            with open(bpf_path) as f:
                bpf_text = f.read()

            self._bpf = BPF(text=bpf_text)
            self._bpf.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")
            self._bpf["dns_events"].open_perf_buffer(self._handle_event)
            self._running = True
            logger.info("DNS monitor started (udp_sendmsg kprobe)")
        except Exception as e:
            logger.warning("Failed to start DNS monitor: %s", e)

    def stop(self) -> None:
        """Stop the DNS monitor."""
        self._running = False

    def poll(self) -> None:
        """Poll perf buffer for DNS events."""
        if self._bpf and self._running:
            try:
                self._bpf.perf_buffer_poll(timeout=0)
            except Exception:
                pass

    def _handle_event(self, cpu, data, size) -> None:
        """Process a DNS query event from eBPF."""
        if not self._running:
            return

        try:
            event = ctypes.cast(data, ctypes.POINTER(DnsEvent)).contents

            pid = event.pid
            ppid = event.ppid
            uid = event.uid
            comm = event.comm.decode("utf-8", errors="replace").rstrip("\x00")
            dest_ip = self._int_to_ip(event.dest_ip)
            dns_name = event.dns_name.decode("utf-8", errors="replace").rstrip("\x00")

            if not dns_name:
                return

            # Determine username from UID
            try:
                import pwd
                username = pwd.getpwuid(uid).pw_name
            except (KeyError, ImportError):
                username = str(uid)

            # Check for DGA-like domains
            is_suspicious = self._check_dga(dns_name)
            severity = "medium" if is_suspicious else "info"
            event_type = "alert_suspicious_dns" if is_suspicious else "dns_query"

            self._emitter.emit({
                "event_type": event_type,
                "severity": severity,
                "pid": pid,
                "ppid": ppid,
                "process_name": comm,
                "username": username,
                "dest_ip": dest_ip,
                "dest_port": 53,
                "dns_name": dns_name,
            })

        except Exception:
            pass

    @staticmethod
    def _int_to_ip(addr: int) -> str:
        """Convert network-order u32 to dotted IP string."""
        return f"{addr & 0xFF}.{(addr >> 8) & 0xFF}.{(addr >> 16) & 0xFF}.{(addr >> 24) & 0xFF}"

    @staticmethod
    def _check_dga(domain: str) -> bool:
        """
        Basic DGA (Domain Generation Algorithm) detection.
        Flags domains with high Shannon entropy + unusual length.
        """
        # Strip TLD
        parts = domain.split(".")
        if len(parts) < 2:
            return False

        # Focus on the second-level domain
        sld = parts[-2] if len(parts) >= 2 else domain

        # Length check
        if len(sld) < DnsMonitor.DGA_MIN_LENGTH:
            return False

        # Shannon entropy
        freq = Counter(sld)
        length = len(sld)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

        return entropy >= DnsMonitor.DGA_ENTROPY_THRESH
