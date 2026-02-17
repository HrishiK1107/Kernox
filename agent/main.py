#!/usr/bin/env python3
"""
Kernox — eBPF Endpoint Agent

Main entry point. Ties together all eBPF monitors, process lineage,
event emitter, heartbeat, response hook, and detection engine.

Usage:
    sudo python3 -m agent.main
    sudo python3 -m agent

Requires root privileges for eBPF operations.
"""

import os
import signal
import sys

# ── Ensure we can import the agent package ──────────────────────
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from agent.logging_config import logger
from agent.config import ENDPOINT_ID, HOSTNAME, PROCESS_TREE_MAX_SIZE, PID_FILE
from agent.pidfile import acquire_pidfile, release_pidfile
from agent.ebpf.process_monitor import ProcessMonitor
from agent.ebpf.file_monitor import FileMonitor
from agent.ebpf.net_monitor import NetworkMonitor
from agent.ebpf.priv_monitor import PrivEscalationMonitor
from agent.ebpf.auth_monitor import AuthMonitor
from agent.ebpf.dns_monitor import DnsMonitor
from agent.ebpf.log_tamper_monitor import LogTamperMonitor
from agent.events.event_emitter import EventEmitter
from agent.tracking.process_tree import ProcessTree
from agent.tracking.container_info import enrich_with_container_info
from agent.health.heartbeat import Heartbeat
from agent.response.response_hook import ResponseHook
from agent.detection.rule_engine import RuleEngine


BANNER = r"""
  _  __                          
 | |/ / ___  _ __  _ __   ___ __  __
 | ' / / _ \| '__|| '_ \ / _ \\ \/ /
 | . \|  __/| |   | | | | (_) |>  < 
 |_|\_\___||_|   |_| |_|\___//_/\_\

  eBPF Endpoint Agent v1.0
"""


def main() -> None:
    if os.geteuid() != 0:
        logger.error("This agent requires root privileges.")
        logger.error("Run with: sudo python3 -m agent.main")
        sys.exit(1)

    print(BANNER, file=sys.stderr)
    logger.info("Hostname  : %s", HOSTNAME)
    logger.info("Endpoint  : %s", ENDPOINT_ID)
    logger.info("Tree limit: %d", PROCESS_TREE_MAX_SIZE)

    # ── Acquire PID file (single instance) ───────────────────
    acquire_pidfile(PID_FILE)

    tree = ProcessTree(max_size=PROCESS_TREE_MAX_SIZE)
    emitter = EventEmitter()
    heartbeat = Heartbeat(event_emitter=emitter, process_tree=tree)

    # eBPF monitors
    proc_monitor = ProcessMonitor(emitter=emitter, tree=tree)
    file_monitor = FileMonitor(emitter=emitter)
    net_monitor = NetworkMonitor(emitter=emitter)
    priv_monitor = PrivEscalationMonitor(emitter=emitter)
    auth_monitor = AuthMonitor(emitter=emitter)
    dns_monitor = DnsMonitor(emitter=emitter)
    log_tamper = LogTamperMonitor(emitter=emitter)

    # Detection rule engine
    rule_engine = RuleEngine(emitter=emitter)
    rules_loaded = rule_engine.load_rules()

    # Response hook
    response_hook = ResponseHook(emitter=emitter)

    monitors = [file_monitor, net_monitor, priv_monitor, auth_monitor,
                dns_monitor, log_tamper]

    # ── Graceful shutdown ────────────────────────────────────
    _shutting_down = False

    def shutdown(signum, frame):
        nonlocal _shutting_down
        if _shutting_down:
            return
        _shutting_down = True

        logger.info("Shutting down Kernox agent...")
        proc_monitor.stop()
        for m in monitors:
            m.stop()
        heartbeat.stop()
        release_pidfile(PID_FILE)
        logger.info("Total events emitted: %d", emitter.event_count)
        logger.info("Processes tracked   : %d", tree.size)
        if rules_loaded:
            logger.info("Detection rules     : %d loaded", rules_loaded)
        logger.info("Agent stopped.")
        os._exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Start all monitors ───────────────────────────────────
    heartbeat.start()
    logger.info("Heartbeat started.")

    for m in monitors:
        try:
            m.start()
        except Exception as e:
            logger.warning("Failed to start %s: %s", m.__class__.__name__, e)

    response_hook.start()
    logger.info("Response hook listening.")

    if rules_loaded:
        logger.info("Detection engine: %d rules active", rules_loaded)

    # ── Main poll loop ───────────────────────────────────────
    logger.info("All monitors active. Watching endpoint...")

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
        logger.error("Monitor loop failed: %s", e)
    finally:
        shutdown(None, None)


if __name__ == "__main__":
    main()
