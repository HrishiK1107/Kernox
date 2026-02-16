# Kernox — eBPF Endpoint Agent

A lightweight, production-grade endpoint detection and response (EDR) agent built on **eBPF** (via BCC). Monitors process execution, file activity, network connections, and privilege escalation in real time with zero kernel modules.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Kernox Agent                    │
├──────────┬──────────┬──────────┬────────────────┤
│ Process  │  File    │ Network  │  Privilege      │
│ Monitor  │ Monitor  │ Monitor  │  Escalation     │
│ (execve, │ (openat, │ (tcp_    │  Monitor        │
│  exit)   │  write,  │ connect) │  (setuid/gid)   │
│          │  rename) │          │                  │
├──────────┴──────────┴──────────┴────────────────┤
│            Process Lineage Tree (DAG)            │
├──────────────────────────────────────────────────┤
│         Hardened Event Emitter (JSON)             │
├──────────────────────────────────────────────────┤
│  Response Hook  │  Heartbeat  │  PID File Guard  │
└─────────────────┴─────────────┴──────────────────┘
```

## Features

| Feature | Details |
|---------|---------|
| **Process Monitoring** | Hooks `execve` and `sched_process_exit` tracepoints |
| **Process Lineage** | Thread-safe DAG tracking parent→child chains |
| **File Monitoring** | Hooks `openat`, `write`, `renameat2` — detects ransomware bursts |
| **Network Monitoring** | Hooks `tcp_connect` kprobe — detects C2 beaconing |
| **Privilege Escalation** | Hooks `setuid`/`setgid` — flags root escalation as CRITICAL |
| **Response Hook** | Kill process, block IP, isolate host, quarantine file + rollback |
| **Hardened Schema** | UUID event_id, strict enums, sanitized strings, fixed structure |
| **Single Instance** | PID file guard prevents duplicate agents |
| **Structured Logging** | Centralized Python logging (configurable level) |

## Requirements

- **Linux** kernel 4.15+ with BPF support
- **Python** 3.10+
- **BCC** (BPF Compiler Collection) — `apt install bpfcc-tools python3-bpfcc`
- **Root** privileges (for eBPF and iptables)

## Quick Start

```bash
# Clone
git clone https://github.com/aaryaman005/Kernox.git
cd Kernox

# Install BCC (Ubuntu/Debian)
sudo apt install bpfcc-tools python3-bpfcc

# Run
sudo python3 -m agent.main
```

## Configuration

All settings are configurable via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `KERNOX_ENDPOINT_ID` | `{hostname}-{uuid}` | Unique agent identifier |
| `KERNOX_BACKEND_URL` | `http://192.168.1.10:8000` | Backend API base URL |
| `KERNOX_HEARTBEAT_INTERVAL` | `30` | Heartbeat interval in seconds |
| `KERNOX_LOG_LEVEL` | `INFO` | Log level (DEBUG/INFO/WARNING/ERROR) |
| `KERNOX_PID_FILE` | `/var/run/kernox.pid` | PID file path |

## Event Schema

Every event follows a hardened, fixed-structure schema:

```json
{
  "event_id": "c2f6e8c2-9e2b-4f3c-b32a-0d2f8e4d1f91",
  "schema_version": "1.0",
  "timestamp": "2026-02-16T07:12:00Z",
  "endpoint": {
    "endpoint_id": "ubuntu-node-1-a1b2c3d4",
    "hostname": "ubuntu-node-1"
  },
  "event_type": "process_start",
  "severity": "low",
  "process": {
    "pid": 4123,
    "ppid": 1,
    "name": "bash",
    "path": "/bin/bash",
    "user": "root"
  },
  "file": null,
  "network": null,
  "auth": null,
  "alert": null,
  "signature": null
}
```

### Event Types

`process_start` · `process_stop` · `file_open` · `file_write` · `file_rename` · `network_connect` · `privilege_change` · `alert_ransomware_burst` · `alert_c2_beaconing` · `alert_privilege_escalation` · `heartbeat`

### Severity Levels

`info` · `low` · `medium` · `high` · `critical`

## Systemd Service

```bash
# Install
sudo cp kernox.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable kernox
sudo systemctl start kernox

# Check status
sudo systemctl status kernox
sudo journalctl -u kernox -f
```

## Project Structure

```
Kernox/
├── agent/
│   ├── __init__.py
│   ├── __main__.py          # python3 -m agent entry point
│   ├── main.py              # Main orchestrator
│   ├── config.py            # Configuration from env vars
│   ├── logging_config.py    # Centralized logging
│   ├── pidfile.py           # Single-instance guard
│   ├── ebpf/
│   │   ├── bpf_programs/    # eBPF C programs
│   │   │   ├── process_exec.c
│   │   │   ├── file_monitor.c
│   │   │   ├── net_monitor.c
│   │   │   └── priv_monitor.c
│   │   ├── process_monitor.py
│   │   ├── file_monitor.py
│   │   ├── net_monitor.py
│   │   └── priv_monitor.py
│   ├── events/
│   │   └── event_emitter.py  # Hardened JSON schema
│   ├── tracking/
│   │   └── process_tree.py   # Process lineage DAG
│   ├── health/
│   │   └── heartbeat.py
│   └── response/
│       └── response_hook.py  # Kill/block/isolate/quarantine
├── kernox.service            # systemd unit
├── README.md
└── .gitignore
```

## License

MIT
