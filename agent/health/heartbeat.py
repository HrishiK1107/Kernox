"""
Kernox — Agent Heartbeat

Periodically sends agent health status.
Phase 1: stdout output.
Future: HTTP POST to backend heartbeat endpoint.
"""

import json
import platform
import sys
import threading
import time
from datetime import datetime, timezone

from agent.config import (
    HOSTNAME,
    ENDPOINT_ID,
    HEARTBEAT_INTERVAL_SEC,
    EVENT_OUTPUT_MODE,
)


class Heartbeat:
    """
    Background thread that emits periodic heartbeat signals.

    Includes: alive status, system info, last event timestamp,
    agent uptime, and tracked process count.
    """

    def __init__(self, event_emitter=None, process_tree=None):
        self._emitter = event_emitter
        self._tree = process_tree
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._start_time = time.time()

    def start(self) -> None:
        """Start the heartbeat background thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="sentinel-heartbeat",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the heartbeat thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        """Main heartbeat loop."""
        while not self._stop_event.is_set():
            self._send_heartbeat()
            self._stop_event.wait(timeout=HEARTBEAT_INTERVAL_SEC)

    def _send_heartbeat(self) -> None:
        """Construct and emit a heartbeat message via the emitter."""
        uptime = time.time() - self._start_time

        if self._emitter:
            self._emitter.emit({
                "event_type": "heartbeat",
                "severity": "info",
                "process_name": "kernox-agent",
                "username": "root",
            })
