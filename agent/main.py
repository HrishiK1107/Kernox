#!/usr/bin/env python3
"""
Kernox — eBPF Endpoint Agent

Main entry point. Ties together:
  - eBPF Process Monitor (execve / exit tracing)
  - eBPF File Activity Monitor (open / write / rename)
  - eBPF Network Monitor (outbound TCP connections)
  - eBPF Privilege Escalation Monitor (setuid / setgid)
  - Process Lineage Tree (parent→child DAG)
  - Event Emitter (JSON output)
  - Heartbeat (periodic health signals)
  - Response Hook (kill, block, isolate, quarantine)

Usage:
    sudo python3 -m agent.main

Requires root privileges for eBPF operations.
"""

import os
import signal
import sys

# ── Ensure we can import the agent package ──────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from agent.config import ENDPOINT_ID, HOSTNAME, PROCESS_TREE_MAX_SIZE
from agent.ebpf.process_monitor import ProcessMonitor
from agent.ebpf.file_monitor import FileMonitor
from agent.ebpf.net_monitor import NetworkMonitor
from agent.ebpf.priv_monitor import PrivEscalationMonitor
from agent.events.event_emitter import EventEmitter
from agent.tracking.process_tree import ProcessTree
from agent.health.heartbeat import Heartbeat
from agent.response.response_hook import ResponseHook


BANNER = r"""
  _  __                          
 | |/ / ___  _ __  _ __   ___ __  __
 | ' / / _ \| '__|| '_ \ / _ \\ \/ /
 | . \|  __/| |   | | | | (_) |>  < 
 |_|\_\\___||_|   |_| |_|\___//_/\_\

  eBPF Endpoint Agent v1.0
"""


def main() -> None:
    # ── Check privileges ─────────────────────────────────────
    if os.geteuid() != 0:
        print("[ERROR] This agent requires root privileges.", file=sys.stderr)
        print("        Run with: sudo python3 -m agent.main", file=sys.stderr)
        sys.exit(1)

    print(BANNER, file=sys.stderr)
    print(f"[*] Hostname  : {HOSTNAME}", file=sys.stderr)
    print(f"[*] Endpoint  : {ENDPOINT_ID}", file=sys.stderr)
    print(f"[*] Tree limit: {PROCESS_TREE_MAX_SIZE}", file=sys.stderr)
    print("", file=sys.stderr)

    # ── Initialize components ────────────────────────────────
    tree = ProcessTree(max_size=PROCESS_TREE_MAX_SIZE)
    emitter = EventEmitter()
    heartbeat = Heartbeat(event_emitter=emitter, process_tree=tree)

    # eBPF monitors
    proc_monitor = ProcessMonitor(emitter=emitter, tree=tree)
    file_monitor = FileMonitor(emitter=emitter)
    net_monitor = NetworkMonitor(emitter=emitter)
    priv_monitor = PrivEscalationMonitor(emitter=emitter)

    # Response hook
    response_hook = ResponseHook(emitter=emitter)

    monitors = [file_monitor, net_monitor, priv_monitor]

    # ── Graceful shutdown ────────────────────────────────────
    _shutting_down = False

    def shutdown(signum, frame):
        nonlocal _shutting_down
        if _shutting_down:
            return
        _shutting_down = True

        print("\n[*] Shutting down Kernox agent...", file=sys.stderr)
        proc_monitor.stop()
        for m in monitors:
            m.stop()
        heartbeat.stop()
        print(f"[*] Total events emitted: {emitter.event_count}", file=sys.stderr)
        print(f"[*] Processes tracked   : {tree.size}", file=sys.stderr)
        print("[*] Agent stopped.", file=sys.stderr)
        os._exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Start all monitors ───────────────────────────────────
    heartbeat.start()
    print("[*] Heartbeat started.", file=sys.stderr)

    # Start auxiliary monitors (they load their own BPF programs)
    for m in monitors:
        try:
            m.start()
        except Exception as e:
            print(f"[WARN] Failed to start {m.__class__.__name__}: {e}", file=sys.stderr)

    # Start response hook listener
    response_hook.start()
    print("[*] Response hook listening.", file=sys.stderr)

    # Process monitor runs the main poll loop
    # We interleave polling of all monitors
    print("[*] All monitors active. Watching endpoint...", file=sys.stderr)
    print("", file=sys.stderr)

    try:
        proc_monitor._load_bpf()
        proc_monitor._attach_callbacks()
        proc_monitor._running = True

        while proc_monitor._running:
            proc_monitor._bpf.perf_buffer_poll(timeout=50)
            for m in monitors:
                m.poll()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[ERROR] Monitor loop failed: {e}", file=sys.stderr)
    finally:
        shutdown(None, None)


if __name__ == "__main__":
    main()
