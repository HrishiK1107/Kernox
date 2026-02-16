"""
Kernox — Log Tampering Detection

Monitors critical log files for unauthorized modifications,
truncation, or deletion. Uses inotify-based file watching.

Detects:
  - Log file deletion (rm /var/log/auth.log)
  - Log file truncation (echo > /var/log/syslog)
  - Unexpected modification of wtmp/btmp (binary log tampering)
"""

import os
import time
import threading
from pathlib import Path

from agent.logging_config import logger

# Critical log files to monitor
WATCHED_LOGS = [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/var/log/faillog",
]


class LogTamperMonitor:
    """
    Watches critical log files for tampering indicators:
    - File deletion
    - File truncation (size decrease)
    - Permission changes
    """

    CHECK_INTERVAL_SEC = 10

    def __init__(self, emitter):
        self._emitter = emitter
        self._running = False
        self._thread: threading.Thread | None = None
        self._baselines: dict[str, dict] = {}

    def start(self) -> None:
        """Start the log tamper monitor."""
        self._build_baselines()
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="kernox-log-tamper",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Log tamper monitor started (watching %d files)",
            len(self._baselines),
        )

    def stop(self) -> None:
        """Stop the monitor."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def poll(self) -> None:
        """No-op — runs in own thread."""
        pass

    def _build_baselines(self) -> None:
        """Snapshot current state of all watched log files."""
        for log_path in WATCHED_LOGS:
            try:
                stat = os.stat(log_path)
                self._baselines[log_path] = {
                    "size": stat.st_size,
                    "inode": stat.st_ino,
                    "mode": stat.st_mode,
                    "mtime": stat.st_mtime,
                    "exists": True,
                }
            except (OSError, PermissionError):
                self._baselines[log_path] = {"exists": False}

    def _monitor_loop(self) -> None:
        """Periodically check log files for tamper indicators."""
        while self._running:
            for log_path, baseline in self._baselines.items():
                try:
                    self._check_file(log_path, baseline)
                except Exception:
                    pass
            time.sleep(self.CHECK_INTERVAL_SEC)

    def _check_file(self, log_path: str, baseline: dict) -> None:
        """Check a single log file against its baseline."""
        was_present = baseline.get("exists", False)

        try:
            stat = os.stat(log_path)
        except FileNotFoundError:
            if was_present:
                # File was deleted!
                self._alert("log_deleted", log_path, {
                    "detail": "Critical log file deleted",
                    "previous_size": baseline.get("size", 0),
                })
                baseline["exists"] = False
            return
        except PermissionError:
            return

        # File reappeared after deletion
        if not was_present:
            self._alert("log_recreated", log_path, {
                "detail": "Deleted log file was recreated (possible cover-up)",
                "new_size": stat.st_size,
            })
            baseline.update({
                "size": stat.st_size,
                "inode": stat.st_ino,
                "mode": stat.st_mode,
                "mtime": stat.st_mtime,
                "exists": True,
            })
            return

        # File truncated (size decreased)
        prev_size = baseline.get("size", 0)
        if stat.st_size < prev_size and prev_size > 0:
            self._alert("log_truncated", log_path, {
                "detail": "Log file truncated (evidence destruction)",
                "previous_size": prev_size,
                "current_size": stat.st_size,
            })

        # Inode changed (file replaced)
        prev_inode = baseline.get("inode", 0)
        if stat.st_ino != prev_inode and prev_inode > 0:
            self._alert("log_replaced", log_path, {
                "detail": "Log file replaced (different inode — possible swap attack)",
                "previous_inode": prev_inode,
                "current_inode": stat.st_ino,
            })

        # Permission changed
        prev_mode = baseline.get("mode", 0)
        if stat.st_mode != prev_mode and prev_mode > 0:
            self._alert("log_permission_changed", log_path, {
                "detail": "Log file permissions modified",
                "previous_mode": oct(prev_mode),
                "current_mode": oct(stat.st_mode),
            })

        # Update baseline
        baseline.update({
            "size": stat.st_size,
            "inode": stat.st_ino,
            "mode": stat.st_mode,
            "mtime": stat.st_mtime,
            "exists": True,
        })

    def _alert(self, tamper_type: str, log_path: str, details: dict) -> None:
        """Emit a log tampering alert."""
        logger.warning("Log tampering detected: %s on %s", tamper_type, log_path)
        self._emitter.emit({
            "event_type": "alert_log_tamper",
            "severity": "critical",
            "process_name": "kernox-log-tamper",
            "username": "root",
            "filename": log_path,
            "tamper_type": tamper_type,
            **details,
        })
