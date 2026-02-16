"""
Kernox — Hardened Event Emitter

Formats security events into a strict, validated JSON schema.
Defends against:
  - JSON injection         → string sanitization (control chars stripped)
  - Field pollution         → fixed schema, no arbitrary fields pass through
  - Mass assignment         → whitelisted fields only per event type
  - Overposting             → unknown keys silently dropped
  - Replay attacks          → UUID event_id per event
  - Malformed timestamps    → strict ISO 8601 UTC only
  - Oversized payload DoS   → max field lengths enforced
  - Enum bypass             → strict event_type + severity enums
  - Version downgrade       → schema_version in every event
  - Debug leakage           → no internal state exposed
"""

import json
import re
import sys
import threading
import uuid
from datetime import datetime, timezone

from agent.config import HOSTNAME, ENDPOINT_ID, EVENT_OUTPUT_MODE


# ── Strict enums ─────────────────────────────────────────────

VALID_EVENT_TYPES = frozenset({
    # Process
    "process_start",
    "process_stop",
    # File
    "file_open",
    "file_write",
    "file_rename",
    "file_delete",
    # Network
    "network_connect",
    # DNS
    "dns_query",
    # Privilege
    "privilege_change",
    # Authentication
    "auth_login_success",
    "auth_login_failure",
    "auth_sudo",
    # Alerts
    "alert_ransomware_burst",
    "alert_c2_beaconing",
    "alert_privilege_escalation",
    "alert_brute_force",
    "alert_suspicious_dns",
    "alert_log_tamper",
    "alert_rule_match",
    # Response actions
    "response_action",
    "response_rollback",
    # Health
    "heartbeat",
})

VALID_SEVERITIES = frozenset({
    "info",
    "low",
    "medium",
    "high",
    "critical",
})

SCHEMA_VERSION = "1.0"

# ── Field length limits (anti-DoS) ───────────────────────────

MAX_STRING_LEN = 256
MAX_PATH_LEN = 512
MAX_LINEAGE_LEN = 1024

# ── Sanitization ─────────────────────────────────────────────

# Strip control characters except newline/tab (anti JSON injection)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize_str(value: str, max_len: int = MAX_STRING_LEN) -> str:
    """Sanitize a string: strip control chars, truncate."""
    if not isinstance(value, str):
        value = str(value)
    value = _CONTROL_CHAR_RE.sub("", value)
    return value[:max_len]


def _sanitize_int(value, default: int = 0) -> int:
    """Coerce to int safely."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class EventEmitter:
    """
    Thread-safe, schema-hardened event emitter.

    Every event is validated against a fixed schema before output.
    No arbitrary fields pass through to the backend.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._event_count = 0
        self._last_event_time: str | None = None
        self._http_transport = None

    # ── Public API ───────────────────────────────────────────

    def emit(self, event: dict) -> None:
        """
        Validate, harden, and emit a security event.

        Args:
            event: Raw event dict. Must contain 'event_type'.
                   All other fields are whitelisted per type.
        """
        hardened = self._harden(event)
        if hardened is None:
            return  # silently drop malformed events

        self._output(hardened)

        with self._lock:
            self._event_count += 1
            self._last_event_time = hardened["timestamp"]

    @property
    def event_count(self) -> int:
        with self._lock:
            return self._event_count

    @property
    def last_event_time(self) -> str | None:
        with self._lock:
            return self._last_event_time

    # ── Schema construction ──────────────────────────────────

    def _harden(self, raw: dict) -> dict | None:
        """Build a hardened event from raw data. Returns None if invalid."""
        event_type = raw.get("event_type", "")
        if event_type not in VALID_EVENT_TYPES:
            return None  # reject unknown event types (enum bypass)

        severity = raw.get("severity", "info")
        if severity not in VALID_SEVERITIES:
            severity = "info"  # default, never trust raw severity

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        hardened = {
            "event_id": str(uuid.uuid4()),
            "schema_version": SCHEMA_VERSION,
            "timestamp": now,

            "endpoint": {
                "endpoint_id": _sanitize_str(ENDPOINT_ID),
                "hostname": _sanitize_str(HOSTNAME),
            },

            "event_type": event_type,
            "severity": severity,

            # Fixed sub-objects — always present, null if unused
            "process": self._build_process(raw),
            "file": self._build_file(raw),
            "network": self._build_network(raw),
            "auth": self._build_auth(raw),

            # Optional alert metadata
            "alert": self._build_alert(raw),

            # Reserved for HMAC signature (future)
            "signature": None,
        }

        return hardened

    def _build_process(self, raw: dict) -> dict | None:
        """Extract process fields if present."""
        pid = raw.get("pid")
        if pid is None:
            return None

        result = {
            "pid": _sanitize_int(pid),
            "ppid": _sanitize_int(raw.get("ppid", 0)),
            "name": _sanitize_str(raw.get("process_name", "")),
            "path": _sanitize_str(raw.get("filename", ""), MAX_PATH_LEN),
            "user": _sanitize_str(raw.get("username", "")),
        }

        # Include lineage only if present (process events)
        lineage = raw.get("lineage")
        if lineage:
            result["lineage"] = _sanitize_str(lineage, MAX_LINEAGE_LEN)

        return result

    def _build_file(self, raw: dict) -> dict | None:
        """Extract file fields for file events."""
        et = raw.get("event_type", "")
        if not et.startswith("file_"):
            return None

        return {
            "path": _sanitize_str(raw.get("filename", ""), MAX_PATH_LEN),
            "flags": _sanitize_int(raw.get("flags", 0)),
        }

    def _build_network(self, raw: dict) -> dict | None:
        """Extract network fields for network events."""
        if raw.get("event_type") != "network_connect":
            return None

        return {
            "dest_ip": _sanitize_str(raw.get("dest_ip", "")),
            "dest_port": _sanitize_int(raw.get("dest_port", 0)),
            "protocol": _sanitize_str(raw.get("protocol", "TCP")),
        }

    def _build_auth(self, raw: dict) -> dict | None:
        """Extract auth/privilege fields for privilege and auth events."""
        et = raw.get("event_type", "")
        is_priv = et.startswith("privilege_") or et == "alert_privilege_escalation"
        is_auth = et.startswith("auth_") or et == "alert_brute_force"

        if not is_priv and not is_auth:
            return None

        result = {}

        # Privilege escalation fields
        if is_priv:
            result["uid"] = _sanitize_int(raw.get("uid", 0))
            result["target_id"] = _sanitize_int(raw.get("target_id", 0))
            result["target_user"] = _sanitize_str(raw.get("target_username", ""))

        # Auth login fields
        if is_auth:
            if "source_ip" in raw:
                result["source_ip"] = _sanitize_str(raw.get("source_ip", ""))
            if "source_port" in raw:
                result["source_port"] = _sanitize_int(raw.get("source_port", 0))
            if "auth_method" in raw:
                result["auth_method"] = _sanitize_str(raw.get("auth_method", ""))
            if "target_username" in raw:
                result["target_user"] = _sanitize_str(raw.get("target_username", ""))

        return result

    def _build_alert(self, raw: dict) -> dict | None:
        """Extract alert-specific metadata for alert events."""
        et = raw.get("event_type", "")
        if not et.startswith("alert_"):
            return None

        alert = {}
        # Burst detection
        if "burst_count" in raw:
            alert["burst_count"] = _sanitize_int(raw["burst_count"])
            alert["window_seconds"] = float(raw.get("window_seconds", 0))
        # Beaconing detection
        if "connection_count" in raw:
            alert["connection_count"] = _sanitize_int(raw["connection_count"])
            alert["window_seconds"] = float(raw.get("window_seconds", 0))
        # Response action
        if "action" in raw:
            alert["action"] = _sanitize_str(raw["action"])
            alert["status"] = _sanitize_str(raw.get("status", ""))

        return alert if alert else None

    # ── Output ───────────────────────────────────────────────

    def _output(self, event: dict) -> None:
        """Write validated event to configured output."""
        if EVENT_OUTPUT_MODE == "http":
            self._output_http(event)
        else:
            self._output_stdout(event)

    def _output_stdout(self, event: dict) -> None:
        """Write event as JSON to stdout."""
        line = json.dumps(event, default=str, ensure_ascii=True)
        with self._lock:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    def _output_http(self, event: dict) -> None:
        """Send event via HTTP transport."""
        if self._http_transport is None:
            from agent.config import API_EVENTS_ENDPOINT
            from agent.transport.http_transport import HTTPTransport
            self._http_transport = HTTPTransport(API_EVENTS_ENDPOINT)
            self._http_transport.start()
        self._http_transport.enqueue(event)
