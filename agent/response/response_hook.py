"""
Kernox — Response Execution Hook

Provides functions for the SOAR response engine to execute
containment actions on the endpoint:
  - Kill a process
  - Block an IP address (iptables)
  - Isolate the host (drop all except backend)
  - Quarantine a file

Every action is recorded as a reversible transaction for rollback.
"""

import os
import shutil
import subprocess
import sys
import threading
import json
from datetime import datetime, timezone

from agent.config import BACKEND_URL, HOSTNAME, ENDPOINT_ID
from agent.events.event_emitter import EventEmitter


class ResponseHook:
    """
    Executes containment actions received from the SOAR engine.

    All actions are logged and reversible via the rollback mechanism.
    Phase 1: Actions are triggered locally (CLI-based).
    Future: Poll backend API for pending commands.
    """

    QUARANTINE_DIR = "/var/kernox/quarantine"

    def __init__(self, emitter: EventEmitter):
        self._emitter = emitter
        self._transactions: list[dict] = []
        self._lock = threading.Lock()

    def start(self) -> None:
        """Ensure quarantine dir exists."""
        os.makedirs(self.QUARANTINE_DIR, exist_ok=True)

    # ── Actions ──────────────────────────────────────────────

    def kill_process(self, pid: int, reason: str = "") -> bool:
        """Kill a process by PID (SIGKILL)."""
        try:
            os.kill(pid, 9)
            self._record_transaction("kill_process", {"pid": pid}, reason)
            self._emitter.emit({
                "event_type": "response_action",
                "action": "kill_process",
                "pid": pid,
                "reason": reason,
                "status": "success",
            })
            return True
        except ProcessLookupError:
            self._emitter.emit({
                "event_type": "response_action",
                "action": "kill_process",
                "pid": pid,
                "reason": reason,
                "status": "failed",
                "error": "Process not found",
            })
            return False
        except PermissionError:
            self._emitter.emit({
                "event_type": "response_action",
                "action": "kill_process",
                "pid": pid,
                "reason": reason,
                "status": "failed",
                "error": "Permission denied",
            })
            return False

    def block_ip(self, ip: str, reason: str = "") -> bool:
        """Block an IP address using iptables."""
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True,
            )
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                check=True, capture_output=True,
            )
            self._record_transaction("block_ip", {"ip": ip}, reason)
            self._emitter.emit({
                "event_type": "response_action",
                "action": "block_ip",
                "ip": ip,
                "reason": reason,
                "status": "success",
            })
            return True
        except subprocess.CalledProcessError as e:
            self._emitter.emit({
                "event_type": "response_action",
                "action": "block_ip",
                "ip": ip,
                "reason": reason,
                "status": "failed",
                "error": str(e),
            })
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Unblock a previously blocked IP (rollback)."""
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True,
            )
            subprocess.run(
                ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                check=True, capture_output=True,
            )
            self._emitter.emit({
                "event_type": "response_rollback",
                "action": "unblock_ip",
                "ip": ip,
                "status": "success",
            })
            return True
        except subprocess.CalledProcessError:
            return False

    def isolate_host(self, backend_ip: str = "", reason: str = "") -> bool:
        """
        Isolate this host by dropping all traffic except to the backend.
        Uses iptables to block everything, then whitelist backend communication.
        """
        if not backend_ip:
            # Extract IP from BACKEND_URL
            from urllib.parse import urlparse
            parsed = urlparse(BACKEND_URL)
            backend_ip = parsed.hostname or "127.0.0.1"

        try:
            rules = [
                # Allow established connections
                ["iptables", "-A", "INPUT", "-m", "state", "--state",
                 "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                # Allow backend
                ["iptables", "-A", "INPUT", "-s", backend_ip, "-j", "ACCEPT"],
                ["iptables", "-A", "OUTPUT", "-d", backend_ip, "-j", "ACCEPT"],
                # Allow loopback
                ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
                ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
                # Drop everything else
                ["iptables", "-A", "INPUT", "-j", "DROP"],
                ["iptables", "-A", "OUTPUT", "-j", "DROP"],
            ]
            for rule in rules:
                subprocess.run(rule, check=True, capture_output=True)

            self._record_transaction(
                "isolate_host", {"backend_ip": backend_ip}, reason
            )
            self._emitter.emit({
                "event_type": "response_action",
                "action": "isolate_host",
                "backend_ip": backend_ip,
                "reason": reason,
                "status": "success",
            })
            return True
        except subprocess.CalledProcessError as e:
            self._emitter.emit({
                "event_type": "response_action",
                "action": "isolate_host",
                "reason": reason,
                "status": "failed",
                "error": str(e),
            })
            return False

    def unisolate_host(self) -> bool:
        """Remove isolation rules (rollback). Flushes iptables."""
        try:
            subprocess.run(
                ["iptables", "-F"], check=True, capture_output=True,
            )
            self._emitter.emit({
                "event_type": "response_rollback",
                "action": "unisolate_host",
                "status": "success",
            })
            return True
        except subprocess.CalledProcessError:
            return False

    def quarantine_file(self, filepath: str, reason: str = "") -> bool:
        """Move a file to the quarantine directory."""
        if not os.path.exists(filepath):
            self._emitter.emit({
                "event_type": "response_action",
                "action": "quarantine_file",
                "filepath": filepath,
                "status": "failed",
                "error": "File not found",
            })
            return False

        try:
            basename = os.path.basename(filepath)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = os.path.join(self.QUARANTINE_DIR, f"{ts}_{basename}")
            shutil.move(filepath, dest)

            self._record_transaction(
                "quarantine_file",
                {"original_path": filepath, "quarantine_path": dest},
                reason,
            )
            self._emitter.emit({
                "event_type": "response_action",
                "action": "quarantine_file",
                "filepath": filepath,
                "quarantine_path": dest,
                "reason": reason,
                "status": "success",
            })
            return True
        except Exception as e:
            self._emitter.emit({
                "event_type": "response_action",
                "action": "quarantine_file",
                "filepath": filepath,
                "status": "failed",
                "error": str(e),
            })
            return False

    def restore_file(self, quarantine_path: str, original_path: str) -> bool:
        """Restore a quarantined file (rollback)."""
        try:
            shutil.move(quarantine_path, original_path)
            self._emitter.emit({
                "event_type": "response_rollback",
                "action": "restore_file",
                "original_path": original_path,
                "status": "success",
            })
            return True
        except Exception:
            return False

    # ── Transaction log ──────────────────────────────────────

    def _record_transaction(
        self, action: str, details: dict, reason: str
    ) -> None:
        with self._lock:
            self._transactions.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "details": details,
                "reason": reason,
                "hostname": HOSTNAME,   
                "endpoint_id": ENDPOINT_ID,
            })

    def get_transactions(self) -> list[dict]:
        """Get all recorded transactions for audit."""
        with self._lock:
            return list(self._transactions)
