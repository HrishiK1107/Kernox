"""
Kernox Agent — Configuration

All settings can be overridden via KERNOX_* environment variables.
"""

import socket
import uuid
import os

# ── Endpoint identity ────────────────────────────────────────────
HOSTNAME = socket.gethostname()
ENDPOINT_ID = os.environ.get(
    "KERNOX_ENDPOINT_ID",
    f"{HOSTNAME}-{uuid.uuid4().hex[:8]}"
)

# ── Backend connection ───────────────────────────────────────────
BACKEND_URL = os.environ.get("KERNOX_BACKEND_URL", "http://192.168.1.10:8000")
API_EVENTS_ENDPOINT = f"{BACKEND_URL}/api/v1/events"
API_HEARTBEAT_ENDPOINT = f"{BACKEND_URL}/api/v1/heartbeat"

# ── Agent behaviour ─────────────────────────────────────────────
HEARTBEAT_INTERVAL_SEC = int(os.environ.get("KERNOX_HEARTBEAT_INTERVAL", "30"))
PROCESS_TREE_MAX_SIZE = 10000          # Max tracked processes before pruning
EVENT_OUTPUT_MODE = "stdout"           # "stdout" | "http" (http for future backend)

# ── Paths ────────────────────────────────────────────────────────
BPF_PROGRAM_DIR = os.path.join(os.path.dirname(__file__), "ebpf", "bpf_programs")
PID_FILE = os.environ.get("KERNOX_PID_FILE", "/var/run/kernox.pid")
