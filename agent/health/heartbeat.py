"""
Kernox — Agent Heartbeat

Periodically sends agent health status through the event emitter.
"""

import threading
import time


class Heartbeat:
    """
    Background thread that emits periodic heartbeat signals.
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
            name="kernox-heartbeat",
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
        from agent.config import HEARTBEAT_INTERVAL_SEC
        while not self._stop_event.is_set():
            self._send_heartbeat()
            self._stop_event.wait(timeout=HEARTBEAT_INTERVAL_SEC)

    def _send_heartbeat(self) -> None:
        """Emit a heartbeat event through the hardened schema."""
        if self._emitter:
            self._emitter.emit({
                "event_type": "heartbeat",
                "severity": "info",
                "process_name": "kernox-agent",
                "username": "root",
            })
