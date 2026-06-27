<p align="center">
  <h1 align="center">Kernox</h1>
  <p align="center">
    Real-time Endpoint Detection & Response (EDR) Platform
    <br />
    <em>eBPF Agent · FastAPI Backend · React Dashboard</em>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/react-18-61DAFB?logo=react&logoColor=black" />
  <img src="https://img.shields.io/badge/fastapi-0.110+-009688?logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/eBPF-kernel_4.15+-orange?logo=linux&logoColor=white" />
  <img src="https://img.shields.io/badge/postgresql-16-4169E1?logo=postgresql&logoColor=white" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
</p>

---

Kernox is a production-grade EDR platform that monitors Linux endpoints in real time using eBPF, processes telemetry through a detection and correlation pipeline, and visualizes security insights on a modern dashboard. The system consists of three core components: a kernel-level **Agent**, a **Backend** API with detection/correlation engines, and a **Frontend** security dashboard.

---

## Table of Contents

- [Architecture](#architecture)
- [Security Model](#security-model)
- [Agent](#agent)
- [Backend](#backend)
- [Frontend](#frontend)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Event Schema](#event-schema)
- [API Reference](#api-reference)
- [Detection Rules](#detection-rules)
- [Red Team Simulations](#red-team-simulations)
- [CI/CD Pipeline](#cicd-pipeline)
- [Project Structure](#project-structure)
- [License](#license)

---

## Architecture

```
                            ┌──────────────────────────────────────────────┐
                            │            Frontend (React + Vite)           │
                            │  ┌────────┐ ┌────────┐ ┌────────┐ ┌──────┐ │
                            │  │  Home  │ │ Alerts │ │Endpts  │ │Analyt│ │
                            │  │  Page  │ │  Page  │ │  Page  │ │ ics  │ │
                            │  └────────┘ └────────┘ └────────┘ └──────┘ │
                            │  Recharts · Radix UI · TailwindCSS · Motion│
                            └──────────────────┬───────────────────────────┘
                                               │ HTTP (proxied /api)
                            ┌──────────────────▼───────────────────────────┐
                            │        Backend (FastAPI + PostgreSQL)        │
                            │                                              │
                            │  ┌──────────────────────────────────────┐    │
                            │  │         Security Layer               │    │
                            │  │  HMAC-SHA256 · Rate Limiter · Replay │    │
                            │  │  Guard · Timestamp Drift · HTTPS     │    │
                            │  └──────────────────────────────────────┘    │
                            │                                              │
                            │  ┌──────────────────────────────────────┐    │
                            │  │        Processing Pipeline           │    │
                            │  │  Detection Engine → Correlation      │    │
                            │  │  Engine → Risk Scoring Engine        │    │
                            │  └──────────────────────────────────────┘    │
                            │                                              │
                            │  Models: Endpoints · Events · Alerts ·      │
                            │          Campaigns · Alert Status History    │
                            └──────────────────┬───────────────────────────┘
                                               │ HMAC-signed HTTP POST
┌──────────────────────────────────────────────▼───────────────────────────────┐
│                            Agent (eBPF + Python)                             │
├──────────┬──────────┬──────────┬────────────┬──────────┬─────────────────────┤
│ Process  │  File    │ Network  │ Privilege  │  DNS     │  Auth               │
│ Monitor  │ Monitor  │ Monitor  │ Escalation │ Monitor  │  Monitor            │
│ (execve, │ (openat, │ (tcp_    │ Monitor    │ (udp_    │  (auth.log,         │
│  exit)   │  write,  │ connect) │ (setuid/   │  sendmsg,│   brute force)      │
│          │  rename) │          │  setgid)   │  DGA)    │                     │
├──────────┴──────────┴──────────┴────────────┴──────────┴─────────────────────┤
│  Log Tamper Monitor  │  Detection Rule Engine (YAML DSL)                     │
├──────────────────────┴───────────────────────────────────────────────────────┤
│  Process Lineage DAG  │  Container Tracking  │  Response Hooks               │
├───────────────────────┴──────────────────────┴───────────────────────────────┤
│              HTTP Transport (HMAC-SHA256 · Retry · JSONL Fallback)           │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Data flow:** Agent captures kernel events via eBPF → signs and sends them over HTTP → Backend validates, stores, runs detection rules → correlates alerts into campaigns → Frontend polls and visualizes in real time.

---

## Security Model

Kernox implements defense-in-depth security across the entire telemetry pipeline:

### Agent → Backend (Transport Security)

| Layer | Implementation | Details |
|-------|---------------|---------|
| **HMAC-SHA256 Signing** | `X-Signature` header | Every event is signed with a shared secret; backend verifies before processing |
| **Endpoint Registration** | Pre-shared `endpoint_id` + `secret_key` | Unregistered agents are rejected with `403 Forbidden` |
| **Timestamp Drift Validation** | ±300s tolerance window | Events with drifted timestamps are rejected (`400 Bad Request`) |
| **Replay Protection** | In-memory `EventGuard` set | Duplicate `event_id` values are rejected (`409 Conflict`) |
| **Rate Limiting** | Per-endpoint sliding window | 50,000 events/minute per endpoint; excess returns `429 Too Many Requests` |

### Backend Middleware Stack

| Middleware | Purpose |
|-----------|---------|
| **SecurityMiddleware** | UUID request IDs, JSON content-type enforcement, max body size (1MB) |
| **SecurityHeadersMiddleware** | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, HSTS in production |
| **HTTPSMiddleware** | HTTPS enforcement in production environments |
| **CORS** | Whitelist-based origin control (dev: `localhost:5173`, `localhost:3000`) |

### Agent-side Security

| Feature | Details |
|---------|---------|
| **PID File Guard** | Prevents duplicate agent instances |
| **Systemd Hardening** | `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, minimal capabilities |
| **eBPF Capabilities** | `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_KILL` — no full root after init |

---

## Agent

The agent is a lightweight Python process that attaches eBPF programs to kernel hooks for real-time telemetry collection. It runs with root privileges and sends structured events to the backend.

### eBPF Monitors

| Monitor | Kernel Hook | Detections |
|---------|------------|------------|
| **Process** | `execve`, `sched_process_exit` | Full process lifecycle, suspicious process names (`nc`, `mimikatz`, etc.) |
| **File** | `openat`, `vfs_write`, `vfs_rename` | Ransomware burst (20+ writes in 5s), sensitive file access |
| **Network** | `tcp_connect` kprobe | C2 beaconing (10+ connects to same IP in 60s), port scanning |
| **Privilege Escalation** | `setuid`, `setgid` tracepoints | Non-root → root escalation flagged as CRITICAL |
| **DNS** | `udp_sendmsg` kprobe | DNS query capture, DGA detection via Shannon entropy |

### Log-Based Monitors

| Monitor | Source | Detections |
|---------|--------|------------|
| **Authentication** | `/var/log/auth.log` | SSH success/failure, sudo usage, brute force (5+ fails in 60s) |
| **Log Tamper** | 7 critical log files | Deletion, truncation, inode swap, permission changes |

### Built-in Detection & Response

| Feature | Details |
|---------|---------|
| **Process Lineage** | Thread-safe DAG tracking parent→child chains |
| **Detection Rule Engine** | Sigma-style YAML rules with `equals`/`contains`/`regex`/`gt`/`lt`/`in` operators |
| **Container Tracking** | Docker/Kubernetes/LXC detection via `/proc/{pid}/cgroup` |
| **Response Hooks** | Kill process, block IP (iptables), isolate host, quarantine file + rollback |
| **HTTP Transport** | HMAC-SHA256 signed, buffered queue, exponential backoff retry (1s → 30s), JSONL fallback |

---

## Backend

The backend is a FastAPI application backed by PostgreSQL. It ingests agent telemetry, runs detection rules, correlates alerts into attack campaigns, and serves analytics to the frontend.

### Processing Pipeline

```
Event Ingestion → Trust Check → HMAC Verify → Rate Limit → Replay Guard
    → Timestamp Validation → Persist Event → Detection Engine
    → Alert Generation (with cooldown) → Correlation Engine
    → Risk Scoring → Campaign Update
```

### Detection Engine

Server-side detection rules defined in `rule_registry.py` evaluate incoming events and generate alerts:

| Rule | Severity | Trigger |
|------|----------|---------|
| `AUTH_BRUTE_FORCE` | Critical | 5+ `auth_failure` events in 300s window |
| `RANSOMWARE_BURST` | Critical | 20+ `file_write` events in 5s window |
| `PRIVILEGE_ESCALATION` | Critical | `privilege_change` event |
| `SUSPICIOUS_PROCESS_NAME` | High | Process start with name matching `nc`, `ncat`, `mimikatz`, etc. |
| `C2_BEACONING` | High | 8+ `network_connect` events to same destination in 30s |
| `UNUSUAL_FILE_DELETE` | Medium | `file_delete` event |
| `NETWORK_RECON` | Low | `network_connect` event |

**Alert cooldown:** Same rule + same endpoint won't fire again within a 300-second window to prevent alert fatigue.

### Correlation Engine

Alerts are automatically grouped into **Campaigns** using a 15-minute sliding window:
- New alerts within 15 minutes of the last alert on the same endpoint extend the existing campaign
- Campaigns track chain length, first/last alerts, and a composite risk score

### Risk Scoring Engine

Deterministic, explainable scoring:

```
Final Score = base_score + critical_bonus + multi_rule_bonus + chain_bonus
```

| Component | Value | Condition |
|-----------|-------|-----------|
| Base Score | Sum of alert `risk_score` values | Always |
| Critical Bonus | +20 | Campaign contains a critical alert |
| Multi-Rule Bonus | +15 | Campaign has ≥2 distinct rule types |
| Chain Bonus | +10 | Campaign has ≥3 alerts |
| **Cap** | 100 | Maximum score |

### Database Models

| Model | Description |
|-------|-------------|
| `Endpoint` | Registered agents with `endpoint_id`, `secret_key`, `hostname`, `last_seen` |
| `Event` | Raw telemetry events with structured payload (JSONB) |
| `Alert` | Detection results: rule name, severity, risk score, linked event IDs |
| `Campaign` | Correlated alert chains with composite risk scoring breakdown |
| `AlertStatusHistory` | Audit trail for alert status transitions |

---

## Frontend

A modern React SPA built with Vite, featuring real-time security monitoring dashboards.

### Tech Stack

| Library | Purpose |
|---------|---------|
| React 18 | UI framework |
| Vite 6 | Build tool + dev server with API proxy |
| TailwindCSS 4 | Utility-first styling |
| Recharts | Line/area/bar/pie charts |
| Radix UI | Accessible headless components |
| Motion (Framer) | Glassmorphism cards and micro-animations |
| Lucide | Icon library |

### Pages

| Page | Features |
|------|----------|
| **Home** | Metric cards (Total Alerts, Critical, High, Endpoints, Avg Risk Index), 30-day trends chart, severity distribution pie, recent alerts table |
| **Alerts** | Full alert list with severity badges, status management (Open/Acknowledged/Resolved), inline detail drawer, detection rule display |
| **Endpoints** | Registered endpoint list with health status, last seen timestamps, endpoint registration modal |
| **Analytics** | Alert trend lines, severity distribution, daily alert volume bar chart, alerts-per-endpoint breakdown, top detection rules table |

### Design

- Dark glassmorphism theme with blue/orange accent gradients
- Severity-keyed color system: 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Low
- Bottom navigation bar with real-time alert badge
- Backend health status dropdown with live API checks

---

## Quick Start

### Prerequisites

- **OS:** Linux (kernel 4.15+ with BPF support)
- **Python:** 3.10+
- **Node.js:** 18+
- **PostgreSQL:** 14+
- **BCC:** `apt install bpfcc-tools python3-bpfcc`

### 1. Clone

```bash
git clone https://github.com/aaryaman005/Kernox.git
cd Kernox
```

### 2. Set Up PostgreSQL & Backend

```bash
cd backend

# Automated setup: creates DB, user, venv, installs deps, seeds test endpoint
chmod +x setup_postgres.sh
./setup_postgres.sh

# Start the backend
source venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The backend will be available at `http://localhost:8000` with interactive API docs at `/docs`.

### 3. Set Up Frontend

```bash
# In a new terminal
cd frontend
npm install
npm run dev
```

The dashboard will be available at `http://localhost:5173`.

### 4. Start the Agent

```bash
# In a new terminal (requires root for eBPF)
cd Kernox
sudo KERNOX_ENDPOINT_ID=kernox-test-agent \
     KERNOX_HMAC_SECRET=kernox-dev-secret \
     KERNOX_BACKEND_URL=http://localhost:8000 \
     KERNOX_OUTPUT_MODE=http \
     python3 -m agent.main
```

### 5. Generate Test Alerts (Optional)

```bash
# Run the simulation suite (while agent is running)
python3 simulations/sim_extended.py

# Or seed alerts directly into the database
python3 simulations/seed_alerts.py
```

---

## Configuration

### Agent Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KERNOX_ENDPOINT_ID` | `{hostname}-{uuid}` | Unique agent identifier |
| `KERNOX_BACKEND_URL` | `http://localhost:8000` | Backend API base URL |
| `KERNOX_HMAC_SECRET` | `kernox-dev-secret` | Shared secret for HMAC-SHA256 signing |
| `KERNOX_EVENT_OUTPUT` | `http` | Event output mode: `stdout` or `http` |
| `KERNOX_HEARTBEAT_INTERVAL` | `30` | Heartbeat interval in seconds |
| `KERNOX_LOG_LEVEL` | `INFO` | Log level (DEBUG/INFO/WARNING/ERROR) |
| `KERNOX_PID_FILE` | `/var/run/kernox.pid` | PID file path |

### Backend Environment Variables (`backend/.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite:///./test.db` | PostgreSQL connection string |
| `APP_ENV` | `development` | Environment (`development`/`production`) |
| `MAX_REQUEST_SIZE` | `1048576` | Max request body size in bytes (1MB) |
| `MAX_EVENTS_PER_MINUTE` | `50000` | Rate limit per endpoint |
| `MAX_TIMESTAMP_DRIFT_SECONDS` | `300` | Max allowed clock drift |
| `ENFORCE_HTTPS` | `false` | Force HTTPS in production |

---

## Event Schema

Every event emitted by the agent follows a hardened, fixed-structure JSON schema:

```json
{
  "event_id": "c2f6e8c2-9e2b-4f3c-b32a-0d2f8e4d1f91",
  "schema_version": "1.0",
  "timestamp": "2026-02-16T07:12:00Z",
  "endpoint": {
    "endpoint_id": "kernox-test-agent",
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

## API Reference

All endpoints are prefixed with `/api/v1`.

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Backend health check |

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/endpoints/register` | Register a new agent endpoint |

### Events

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/events` | Ingest a signed event from the agent |
| `GET` | `/events` | List events with pagination |

### Alerts

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/alerts` | List alerts with filtering (`status`, `severity`, `page_size`) |
| `PATCH` | `/alerts/{id}/status` | Update alert status (open → acknowledged → resolved) |

### Campaigns

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/campaigns` | List correlated alert campaigns |

### Heartbeat

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/heartbeat` | Agent heartbeat to update `last_seen` timestamp |

### Analytics

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/analytics/severity-distribution` | Alert counts grouped by severity |
| `GET` | `/analytics/trends` | Time-bucketed alert counts (`start_date`, `end_date`, `bucket`) |
| `GET` | `/analytics/endpoint-risk` | Per-endpoint risk index scores |
| `GET` | `/analytics/alerts-per-endpoint` | Alert breakdown per endpoint |
| `GET` | `/analytics/top-rules` | Most triggered detection rules |

---

## Detection Rules

### Agent-side: YAML DSL

Write custom Sigma-style detection rules in `agent/rules/`:

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

**Built-in rules:** Suspicious downloads, reverse shells, sensitive file access.

### Backend-side: Rule Registry

Server-side detection rules in `backend/app/services/rule_registry.py` use time-windowed SQL queries to detect patterns across events. See the [Detection Engine](#detection-engine) section for the full rule table.

---

## Red Team Simulations

Test detection capabilities with the included simulation pack. All simulations are **safe and non-destructive** — they use temp files, non-routable IPs, and intentionally failing syscalls.

```bash
# Comprehensive suite (runs all severity levels)
python3 simulations/sim_extended.py

# Individual simulations
python3 simulations/sim_ransomware.py        # Critical — Ransomware burst
python3 simulations/sim_c2_beacon.py          # High — C2 beaconing
python3 simulations/sim_suspicious_process.py # High — Suspicious process names
python3 simulations/sim_privesc.py            # Critical — Privilege escalation
python3 simulations/sim_bruteforce.py         # Critical — SSH brute force
python3 simulations/sim_port_scan.py          # Low — Network reconnaissance
python3 simulations/sim_log_tamper.py         # Critical — Log file tampering

# Seed alerts directly into the database (no agent required)
python3 simulations/seed_alerts.py
```

> **Note:** Simulations that trigger eBPF-based detections require the agent to be running as root in a separate terminal. The `seed_alerts.py` script works independently by inserting directly into PostgreSQL.

---

## Systemd Service

```bash
# Install the agent as a system service
sudo cp kernox.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable kernox
sudo systemctl start kernox

# Check status and logs
sudo systemctl status kernox
sudo journalctl -u kernox -f
```

---

## CI/CD Pipeline

Kernox includes a GitHub Actions CI/CD pipeline (`.github/workflows/ci.yml`) that runs on every push and PR:

| Job | Description |
|-----|-------------|
| **Lint & Test** | Python syntax check, Ruff linting, pytest with coverage |
| **Validate Configs** | YAML detection rule validation, systemd service file check |
| **Security Scan** | Bandit static analysis with artifact report |
| **Build Check** | Project structure validation, file/directory presence check |
| **Integration Test** | Simulation script syntax validation |

---

## Project Structure

```
Kernox/
├── agent/                           # eBPF Endpoint Agent
│   ├── main.py                      # Main orchestrator
│   ├── config.py                    # Environment variable configuration
│   ├── logging_config.py            # Centralized logging
│   ├── pidfile.py                   # Single-instance PID guard
│   ├── ebpf/
│   │   ├── bpf_programs/           # eBPF C programs (.c)
│   │   ├── process_monitor.py      # execve/exit hooks
│   │   ├── file_monitor.py         # openat/write/rename hooks
│   │   ├── net_monitor.py          # tcp_connect hook
│   │   ├── priv_monitor.py         # setuid/setgid hooks
│   │   ├── dns_monitor.py          # DNS + DGA detection
│   │   ├── auth_monitor.py         # SSH/sudo/brute force
│   │   └── log_tamper_monitor.py   # Log integrity monitoring
│   ├── events/
│   │   └── event_emitter.py        # Hardened JSON event schema
│   ├── tracking/
│   │   ├── process_tree.py         # Process lineage DAG
│   │   └── container_info.py       # Docker/K8s/LXC detection
│   ├── detection/
│   │   └── rule_engine.py          # Sigma-style YAML DSL engine
│   ├── transport/
│   │   └── http_transport.py       # HMAC-signed HTTP POST + retry
│   ├── response/
│   │   └── response_hook.py        # Kill/block/isolate/quarantine
│   ├── health/
│   │   └── heartbeat.py            # Periodic heartbeat
│   └── rules/                      # YAML detection rule definitions
│       ├── suspicious_download.yml
│       ├── reverse_shell.yml
│       └── sensitive_file_access.yml
│
├── backend/                         # FastAPI Backend
│   ├── app/
│   │   ├── main.py                 # FastAPI application factory
│   │   ├── api/v1/                 # API route handlers
│   │   │   ├── alerts.py           # Alert CRUD + status management
│   │   │   ├── analytics.py        # Severity, trends, risk analytics
│   │   │   ├── campaigns.py        # Correlated campaign queries
│   │   │   ├── endpoints.py        # Endpoint registration
│   │   │   ├── events.py           # Event ingestion (HMAC verified)
│   │   │   ├── health.py           # Health check
│   │   │   └── heartbeat.py        # Agent heartbeat receiver
│   │   ├── core/                   # Middleware & configuration
│   │   │   ├── config.py           # Pydantic settings from .env
│   │   │   ├── security.py         # Request ID, body size, content type
│   │   │   ├── security_headers.py # X-Frame-Options, HSTS, etc.
│   │   │   └── https_middleware.py  # HTTPS enforcement
│   │   ├── models/                 # SQLAlchemy ORM models
│   │   │   ├── endpoint.py         # Endpoint registration
│   │   │   ├── event.py            # Raw telemetry events
│   │   │   ├── alert.py            # Detection alerts
│   │   │   ├── campaign.py         # Alert correlation campaigns
│   │   │   └── alert_status_history.py
│   │   ├── services/               # Business logic engines
│   │   │   ├── detection_engine.py # Rule evaluation + cooldown
│   │   │   ├── rule_registry.py    # Detection rule definitions
│   │   │   ├── correlation_engine.py # 15-min campaign grouping
│   │   │   ├── risk_engine.py      # Deterministic risk scoring
│   │   │   ├── rate_limiter.py     # Per-endpoint sliding window
│   │   │   ├── event_guard.py      # Replay protection
│   │   │   └── endpoint_registry.py
│   │   ├── schemas/                # Pydantic request/response schemas
│   │   └── db/                     # Database session & migrations
│   ├── setup_postgres.sh           # Automated PostgreSQL setup
│   ├── setup_backend.sh            # Venv + deps + seed script
│   ├── requirements.txt            # Python dependencies
│   ├── alembic/                    # Database migrations
│   └── .env                        # Environment configuration
│
├── frontend/                        # React Security Dashboard
│   ├── src/
│   │   ├── App.tsx                 # Tab-based page router
│   │   ├── pages/
│   │   │   ├── HomePage.tsx        # Dashboard overview
│   │   │   ├── AlertsPage.tsx      # Alert management
│   │   │   ├── EndpointsPage.tsx   # Endpoint management
│   │   │   └── AnalyticsPage.tsx   # Charts & analytics
│   │   ├── components/
│   │   │   ├── AlertDrawer.tsx     # Alert detail side panel
│   │   │   ├── BackendStatusDropdown.tsx
│   │   │   ├── BottomNav.tsx       # Navigation bar
│   │   │   ├── RegisterEndpointModal.tsx
│   │   │   ├── Card.tsx            # Glassmorphism card
│   │   │   └── StatCard.tsx        # Metric card
│   │   ├── context/ThemeContext.tsx # Theme + severity color map
│   │   ├── lib/api.ts              # Typed API client
│   │   └── styles/                 # Global CSS
│   ├── vite.config.ts              # Vite + API proxy config
│   └── package.json
│
├── simulations/                     # Red Team Simulation Scripts
│   ├── sim_extended.py             # All-in-one suite
│   ├── sim_ransomware.py           # Ransomware burst
│   ├── sim_c2_beacon.py            # C2 beaconing
│   ├── sim_suspicious_process.py   # Suspicious processes
│   ├── sim_privesc.py              # Privilege escalation
│   ├── sim_bruteforce.py           # SSH brute force
│   ├── sim_port_scan.py            # Network recon
│   ├── sim_log_tamper.py           # Log tampering
│   ├── sim_full_suite.py           # Full simulation
│   └── seed_alerts.py              # Direct DB alert seeder
│
├── .github/workflows/ci.yml        # CI/CD pipeline
├── kernox.service                   # systemd unit file
└── README.md
```

---

## License

MIT
