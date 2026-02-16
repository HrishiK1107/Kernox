"""
Kernox — Authentication Event Monitor

Monitors /var/log/auth.log for login-related security events.
Not eBPF-based — uses inotify-based log tailing.

Detects:
  - SSH login successes
  - SSH login failures
  - Brute force patterns (5+ failures in 60s from same source)
"""

import os
import re
import time
import threading
from collections import defaultdict

from agent.logging_config import logger

# ── Log line patterns ────────────────────────────────────────

# sshd: Failed password for root from 192.168.1.50 port 49812 ssh2
_FAILED_RE = re.compile(
    r"sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)"
)

# sshd: Accepted password for root from 192.168.1.50 port 49812 ssh2
# sshd: Accepted publickey for root from 192.168.1.50 port 49812 ssh2
_ACCEPTED_RE = re.compile(
    r"sshd\[\d+\]: Accepted (\S+) for (\S+) from (\S+) port (\d+)"
)

# sudo:  aaryaman : TTY=pts/0 ; PWD=/home/aaryaman ; USER=root ; COMMAND=/bin/ls
_SUDO_RE = re.compile(
    r"sudo:\s+(\S+)\s+:.*USER=(\S+)\s*;\s*COMMAND=(.+)"
)

AUTH_LOG_PATH = "/var/log/auth.log"


class AuthMonitor:
    """
    Tails /var/log/auth.log and emits structured events for
    login successes, failures, and brute force detection.
    """

    BRUTE_THRESHOLD = 5       # failures before alert
    BRUTE_WINDOW_SEC = 60     # sliding window

    def __init__(self, emitter):
        self._emitter = emitter
        self._running = False
        self._thread: threading.Thread | None = None
        self._fail_times: dict[str, list[float]] = defaultdict(list)
        self._file = None
        self._inode = None

    def start(self) -> None:
        """Start tailing auth.log in a background thread."""
        if not os.path.exists(AUTH_LOG_PATH):
            logger.warning("Auth log not found at %s — auth monitor disabled", AUTH_LOG_PATH)
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._tail_loop,
            name="kernox-auth-monitor",
            daemon=True,
        )
        self._thread.start()
        logger.info("Auth monitor started (tailing %s)", AUTH_LOG_PATH)

    def stop(self) -> None:
        """Stop the auth monitor."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass

    def poll(self) -> None:
        """No-op — auth monitor runs in its own thread."""
        pass

    def _tail_loop(self) -> None:
        """Continuously tail auth.log, handling log rotation."""
        try:
            self._file = open(AUTH_LOG_PATH, "r")
            self._file.seek(0, os.SEEK_END)  # start at end (only new lines)
            self._inode = os.fstat(self._file.fileno()).st_ino
        except (OSError, PermissionError) as e:
            logger.error("Cannot open %s: %s", AUTH_LOG_PATH, e)
            return

        while self._running:
            line = self._file.readline()
            if line:
                self._process_line(line.strip())
            else:
                # Check for log rotation (inode changed)
                try:
                    current_inode = os.stat(AUTH_LOG_PATH).st_ino
                    if current_inode != self._inode:
                        logger.info("Auth log rotated, reopening")
                        self._file.close()
                        self._file = open(AUTH_LOG_PATH, "r")
                        self._inode = current_inode
                        continue
                except OSError:
                    pass
                time.sleep(0.5)  # no new data, wait

    def _process_line(self, line: str) -> None:
        """Parse a single auth.log line and emit events."""
        if not self._running:
            return

        try:
            # Failed SSH login
            m = _FAILED_RE.search(line)
            if m:
                username, source_ip, port = m.group(1), m.group(2), m.group(3)
                self._emitter.emit({
                    "event_type": "auth_login_failure",
                    "severity": "medium",
                    "username": username,
                    "process_name": "sshd",
                    "source_ip": source_ip,
                    "source_port": int(port),
                })
                self._check_brute_force(source_ip, username)
                return

            # Successful SSH login
            m = _ACCEPTED_RE.search(line)
            if m:
                auth_method, username, source_ip, port = (
                    m.group(1), m.group(2), m.group(3), m.group(4)
                )
                self._emitter.emit({
                    "event_type": "auth_login_success",
                    "severity": "info",
                    "username": username,
                    "process_name": "sshd",
                    "source_ip": source_ip,
                    "source_port": int(port),
                    "auth_method": auth_method,
                })
                return

            # Sudo usage
            m = _SUDO_RE.search(line)
            if m:
                invoking_user, target_user, command = (
                    m.group(1), m.group(2), m.group(3).strip()
                )
                self._emitter.emit({
                    "event_type": "auth_sudo",
                    "severity": "low",
                    "username": invoking_user,
                    "process_name": "sudo",
                    "target_username": target_user,
                    "filename": command,
                })
                return

        except Exception:
            pass

    def _check_brute_force(self, source_ip: str, username: str) -> None:
        """Detect brute force: 5+ failures from same IP in 60 seconds."""
        now = time.time()
        key = source_ip
        cutoff = now - self.BRUTE_WINDOW_SEC

        # Prune old entries
        self._fail_times[key] = [
            t for t in self._fail_times[key] if t > cutoff
        ]
        self._fail_times[key].append(now)

        if len(self._fail_times[key]) >= self.BRUTE_THRESHOLD:
            self._emitter.emit({
                "event_type": "alert_brute_force",
                "severity": "high",
                "username": username,
                "process_name": "sshd",
                "source_ip": source_ip,
                "connection_count": len(self._fail_times[key]),
                "window_seconds": self.BRUTE_WINDOW_SEC,
            })
            # Reset to avoid spamming
            self._fail_times[key] = []
            logger.warning(
                "Brute force detected from %s targeting user '%s'",
                source_ip, username,
            )
