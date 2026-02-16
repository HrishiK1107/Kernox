"""
Kernox — PID File Management

Prevents multiple agent instances from running simultaneously.
Creates /var/run/kernox.pid on start, removes on shutdown.
"""

import os
import sys
import atexit

from agent.logging_config import logger

DEFAULT_PID_FILE = "/var/run/kernox.pid"


def acquire_pidfile(path: str = DEFAULT_PID_FILE) -> None:
    """Write our PID to the pidfile. Abort if another instance is running."""
    if os.path.exists(path):
        try:
            with open(path) as f:
                old_pid = int(f.read().strip())
            # Check if that process is still alive
            os.kill(old_pid, 0)
            logger.error("Another Kernox agent is already running (PID %d)", old_pid)
            sys.exit(1)
        except (ValueError, ProcessLookupError, PermissionError):
            # Stale PID file — process is gone, we can take over
            logger.warning("Removing stale PID file (old PID gone)")
            os.remove(path)

    # Write our PID
    with open(path, "w") as f:
        f.write(str(os.getpid()))

    # Register cleanup
    atexit.register(release_pidfile, path)
    logger.info("PID file created: %s (PID %d)", path, os.getpid())


def release_pidfile(path: str = DEFAULT_PID_FILE) -> None:
    """Remove the PID file on shutdown."""
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass
