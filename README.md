# Kernox — eBPF Endpoint Agent

A lightweight, production-grade endpoint detection and response (EDR) agent built on eBPF (via BCC). Monitors process execution, file activity, network connections, DNS queries, authentication events, and privilege escalation in real time with zero kernel modules.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         Kernox Agent                             │
├──────────┬──────────┬──────────┬────────────┬────────────────────┤
│ Process  │  File    │ Network  │ Privilege  │  DNS               │
│ Monitor  │ Monitor  │ Monitor  │ Escalation │  Monitor           │
│ (execve, │ (openat, │ (tcp_    │ Monitor    │  (udp_sendmsg,     │
│  exit)   │  write,  │ connect) │ (setuid/   │   DGA detection)   │
│          │  rename) │          │  setgid)   │                    │
├──────────┴──────────┴──────────┴────────────┴────────────────────┤
│   Auth Monitor    │  Log Tamper Monitor  │  Container Tracking   │
│   (auth.log,      │  (deletion, trunca-  │  (Docker/K8s/LXC     │
│    brute force)   │   tion, inode swap)  │   cgroup detection)   │
├───────────────────┴──────────────────────┴───────────────────────┤
│              Detection Rule Engine (Sigma-style YAML DSL)        │
├──────────────────────────────────────────────────────────────────┤
│              Process Lineage Tree (Thread-safe DAG)              │
├──────────────────────────────────────────────────────────────────┤
│       Hardened Event Emitter (JSON — stdout or HTTP POST)        │
├──────────────────────────────────────────────────────────────────┤
│  Response Hook  │  Heartbeat  │  PID File Guard  │  HTTP Transport│
└─────────────────┴─────────────┴──────────────────┴───────────────┘
```

---

## Features

### eBPF Monitors

| Feature | Hook | Details |
|---------|------|---------|
| Process Monitoring | `execve`, `sched_process_exit` | Full process lifecycle tracking |
| File Monitoring | `openat`, `vfs_write`, `vfs_rename` | Ransomware burst detection (20+ writes in 5s) |
| Network Monitoring | `tcp_connect` kprobe | C2 beaconing detection (10+ connects to same IP in 60s) |
| Privilege Escalation | `setuid`, `setgid` tracepoints | Flags non-root → root escalation as CRITICAL |
| DNS Monitoring | `udp_sendmsg` kprobe | Captures DNS queries, DGA detection via Shannon entropy |

### Log-Based Monitors

| Feature | Source | Details |
|---------|--------|---------|
| Authentication Monitor | `/var/log/auth.log` | SSH login success/failure, sudo usage, brute force (5+ fails in 60s) |
| Log Tamper Detection | 7 critical log files | Detects deletion, truncation, inode swap, permission changes |

### Detection & Response

| Feature | Details |
|---------|---------|
| Process Lineage | Thread-safe DAG tracking parent→child chains |
| Detection Rule Engine | Sigma-style YAML rules with `equals`/`contains`/`regex`/`gt`/`lt`/`in` operators |
| Container Tracking | Docker/Kubernetes/LXC detection via `/proc/{pid}/cgroup` |
| Response Hook | Kill process, block IP, isolate host, quarantine file + rollback |
| HTTP Transport | Batched POST (50 events/2s), exponential backoff retry, JSONL fallback |

### Production Features

| Feature | Details |
|---------|---------|
| Hardened Schema | UUID `event_id`, strict enums, sanitized strings, fixed structure |
| Single Instance | PID file guard prevents duplicate agents |
| Structured Logging | Centralized Python logging (configurable level) |
| Systemd Service | Auto-restart, journal logging, eBPF capabilities, security hardening |

---

## Requirements

- Linux kernel 4.15+ with BPF support
- Python 3.10+
- BCC (BPF Compiler Collection) — `apt install bpfcc-tools python3-bpfcc`
- Root privileges (for eBPF and iptables)
- PyYAML (optional, for detection rule engine) — `pip install pyyaml`

---

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

---

## Configuration

All settings are configurable via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `KERNOX_ENDPOINT_ID` | `{hostname}-{uuid}` | Unique agent identifier |
| `KERNOX_BACKEND_URL` | `http://192.168.1.10:8000` | Backend API base URL |
| `KERNOX_OUTPUT_MODE` | `stdout` | Event output: `stdout` or `http` |
| `KERNOX_HEARTBEAT_INTERVAL` | `30` | Heartbeat interval in seconds |
| `KERNOX_LOG_LEVEL` | `INFO` | Log level (DEBUG/INFO/WARNING/ERROR) |
| `KERNOX_PID_FILE` | `/var/run/kernox.pid` | PID file path |

### HTTP Mode

```bash
export KERNOX_OUTPUT_MODE=http
export KERNOX_BACKEND_URL=http://your-backend:8000
sudo -E python3 -m agent.main
```

---

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

| Category | Types |
|----------|-------|
| Process | `process_start` · `process_stop` |
| File | `file_open` · `file_write` · `file_rename` · `file_delete` |
| Network | `network_connect` |
| DNS | `dns_query` |
| Privilege | `privilege_change` |
| Authentication | `auth_login_success` · `auth_login_failure` · `auth_sudo` |
| Alerts | `alert_ransomware_burst` · `alert_c2_beaconing` · `alert_privilege_escalation` · `alert_brute_force` · `alert_suspicious_dns` · `alert_log_tamper` · `alert_rule_match` |
| Response | `response_action` · `response_rollback` |
| Health | `heartbeat` |

### Severity Levels

`info` · `low` · `medium` · `high` · `critical`

---

## Detection Rules

Write custom Sigma-style YAML rules in `agent/rules/`:

```yaml
name: Reverse Shell Detection
description: Detects shell processes making network connections
severity: critical
conditions:
  - field: process.name
    operator: in
    value: [bash, sh, nc, python3, perl]
  - field: event_type
    operator: equals
    value: network_connect
match: all
action: alert
```

**Supported operators:** `equals` · `not_equals` · `contains` · `regex` · `gt` · `lt` · `gte` · `lte` · `in`

**Built-in rules:** Suspicious downloads, reverse shells, sensitive file access

---

## Red Team Simulations

Test detection capabilities with the included simulation pack:

```bash
# While agent is running in another terminal:

# Ransomware burst → alert_ransomware_burst
python3 simulations/sim_ransomware.py

# C2 beaconing → alert_c2_beaconing
python3 simulations/sim_c2_beacon.py

# Privilege escalation → alert_privilege_escalation
python3 simulations/sim_privesc.py

# SSH brute force → alert_brute_force (needs sshd)
python3 simulations/sim_bruteforce.py
```

All simulations are **safe and non-destructive** — they use temp files, non-routable IPs, and intentionally failing syscalls.

---

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

---

## Project Structure

```
Kernox/
├── agent/
│   ├── __init__.py
│   ├── __main__.py              # python3 -m agent entry point
│   ├── main.py                  # Main orchestrator
│   ├── config.py                # Configuration from env vars
│   ├── logging_config.py        # Centralized logging
│   ├── pidfile.py               # Single-instance guard
│   ├── ebpf/
│   │   ├── bpf_programs/        # eBPF C programs
│   │   │   ├── process_exec.c
│   │   │   ├── file_monitor.c
│   │   │   ├── net_monitor.c
│   │   │   ├── priv_monitor.c
│   │   │   └── dns_monitor.c
│   │   ├── process_monitor.py
│   │   ├── file_monitor.py
│   │   ├── net_monitor.py
│   │   ├── priv_monitor.py
│   │   ├── dns_monitor.py       # DNS + DGA detection
│   │   ├── auth_monitor.py      # SSH/sudo/brute force
│   │   └── log_tamper_monitor.py # Log file integrity
│   ├── events/
│   │   └── event_emitter.py     # Hardened JSON schema
│   ├── tracking/
│   │   ├── process_tree.py      # Process lineage DAG
│   │   └── container_info.py    # Docker/K8s/LXC detection
│   ├── detection/
│   │   └── rule_engine.py       # Sigma-style YAML DSL
│   ├── transport/
│   │   └── http_transport.py    # Batched HTTP POST + retry
│   ├── health/
│   │   └── heartbeat.py
│   ├── response/
│   │   └── response_hook.py     # Kill/block/isolate/quarantine
│   └── rules/                   # Detection rule definitions
│       ├── suspicious_download.yml
│       ├── reverse_shell.yml
│       └── sensitive_file_access.yml
├── simulations/                 # Red team attack scripts
│   ├── sim_ransomware.py
│   ├── sim_c2_beacon.py
│   ├── sim_privesc.py
│   └── sim_bruteforce.py
├── kernox.service               # systemd unit
├── README.md
└── .gitignore
```

---

## License

MIT
