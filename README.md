# Seraph

A self-hosted security assessment platform combining compliance auditing, penetration testing workflows, credential management, vulnerability tracking, and AI-assisted analysis in a single unified interface.

> **For authorized use only.** Seraph is designed for security professionals conducting legitimate, scoped engagements.

---

## Features

| Category | Capability |
|----------|-----------|
| **Compliance** | CIS / NIST 800-53 scan category templates, bash script generation, Lynis/OpenSCAP integration |
| **Pentest** | Phased workflows (recon → scanning → exploitation), tool-chained command templates, live terminal |
| **Playbooks** | Multi-step automated workflows with step-through, auto-run, and conditional logic |
| **Recon** | OSINT module (Whois, Subfinder, theHarvester, Searchsploit), network visualization |
| **C2** | Metasploit RPC integration — manage sessions, execute commands, harvest loot |
| **Credentials** | Vault for passwords, hashes, keys, tokens with source tracking and password auditing (Hashcat / John) |
| **Defense** | Vulnerability tracker with status workflow, AI remediation suggestions, log analysis and IOC extraction |
| **Reporting** | HTML and Markdown audit reports with executive summaries and finding tables |
| **Multi-user** | Admin / analyst roles, JWT authentication, user management |
| **Demo Mode** | Seed realistic demo data across three projects to explore the platform (admin only) |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Tailwind CSS, Vite |
| Backend | FastAPI, Python 3.11, SQLAlchemy |
| Database | SQLite (zero-config, file-based) |
| Real-time | WebSockets (terminal I/O, scan streaming) |
| Scheduling | APScheduler (recurring scan profiles) |
| Auth | JWT + bcrypt |
| Visualization | Cytoscape.js (network map), XTerm.js (terminal) |

---

## Requirements

- Python 3.11+
- Node.js 20+
- Docker + Docker Compose (optional, for containerized deployment)

**Optional security tools** (detected automatically if installed):

```
nmap  nikto  testssl.sh  lynis  openscap  masscan  gobuster
sqlmap  hydra  whois  dig  theHarvester  subfinder  enum4linux
ffuf  searchsploit  hashcat  john  metasploit
```

---

## Quick Start

### Option 1 — Dev Script

```bash
git clone <repo-url>
cd seraph
./dev.sh
```

Starts the backend on `:8000` and the Vite dev server on `:22123`. Opens the UI at `http://localhost:22123`.

### Option 2 — Manual

**Backend**

```bash
cd seraph/backend
pip install -r ../requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Frontend**

```bash
cd seraph/frontend
npm install
npm run dev          # dev server on :22123
# or
npm run build        # production build served by the backend at :8000
```

### Option 3 — Docker

```bash
cd seraph
docker compose up --build
```

| Service | URL |
|---------|-----|
| Web UI | `http://localhost:5173` |
| API | `http://localhost:8000` |
| API Docs | `http://localhost:8000/docs` |

Data is persisted in named Docker volumes (`seraph_data`, `seraph_results`).

---

## First Run

On first launch Seraph detects no users and shows a **setup screen** to create the initial admin account. Once created, log in and you are ready to go.

To explore the platform without running real scans, go to **Settings → Appearance → Load Demo Data** (admin only). This seeds three realistic demo projects — an external pentest, a web application audit, and an internal network assessment — complete with targets, scans, findings, credentials, and vulnerability records. Toggle it off to remove all demo data cleanly.

---

## Project Structure

```
seraph/
├── backend/
│   ├── main.py                 # FastAPI app entry point, router registration
│   ├── database.py             # SQLAlchemy models (18 tables)
│   ├── config.py               # App settings, tool list
│   ├── routers/                # API route handlers
│   │   ├── audit.py            # Compliance scan generation & finding parsing
│   │   ├── pentest.py          # Pentest engagement workflows
│   │   ├── playbooks.py        # Playbook CRUD & execution
│   │   ├── c2.py               # Metasploit RPC integration
│   │   ├── credentials.py      # Credential vault
│   │   ├── cracking.py         # Password cracking jobs
│   │   ├── vulns.py            # Vulnerability tracker + AI remediation
│   │   ├── logs.py             # Log analysis & IOC extraction
│   │   ├── hardening.py        # CIS / STIG hardening reports
│   │   ├── osint.py            # OSINT tool orchestration
│   │   ├── network.py          # Network discovery
│   │   ├── auth.py             # Authentication & user management
│   │   ├── projects.py         # Project & target CRUD, stats
│   │   ├── demo.py             # Demo data seeding / clearing
│   │   └── ws.py               # WebSocket terminal relay
│   ├── services/               # Core logic
│   │   ├── tool_registry.py    # Tool detection (shutil.which + version)
│   │   ├── scheduler.py        # APScheduler cron jobs
│   │   ├── playbook_runner.py  # Multi-step playbook execution engine
│   │   ├── script_generator.py # Jinja2 bash script templating
│   │   ├── output_parser.py    # Nmap / Nikto / Lynis output → Finding objects
│   │   ├── auth_service.py     # JWT creation / verification
│   │   ├── msf_client.py       # Metasploit RPC client
│   │   └── ai_client.py        # LLM integration
│   └── data/
│       ├── scan_categories.json    # Audit categories + CIS/NIST mappings
│       ├── tool_chains.json        # Pentest phase + tool definitions
│       ├── cis_controls.json       # CIS benchmark controls
│       └── nist_800_53.json        # NIST 800-53 controls
├── frontend/
│   ├── src/
│   │   ├── pages/              # One file per route (18 pages)
│   │   ├── components/         # Shared UI components
│   │   ├── api/client.ts       # Typed fetch wrapper
│   │   ├── contexts/           # AuthContext, ThemeContext
│   │   ├── stores/             # Zustand global state
│   │   └── App.tsx             # Router + auth guard
│   ├── vite.config.ts          # Dev server on :22123, proxy to :8000
│   └── tailwind.config.js
├── docker-compose.yml
├── Dockerfile.backend
├── requirements.txt
└── dev.sh
```

---

## Pages

| Route | Page | Description |
|-------|------|-------------|
| `/` | Dashboard | Project stats, findings distribution, recent scans & findings |
| `/audit` | Audit Builder | CIS/NIST scan templates, script generation, compliance scoring |
| `/pentest` | Pentest Workbench | Phased pentest workflows with live terminal execution |
| `/playbooks` | Playbooks | Automated multi-step attack/audit playbooks |
| `/osint` | OSINT Module | Whois, subdomain enum, email harvesting, exploit search |
| `/network` | Network Map | Cytoscape graph of discovered hosts and services |
| `/vault` | Credential Vault | Centralized credential storage and management |
| `/cracking` | Password Auditing | Hashcat / John hash cracking with job queuing |
| `/c2` | C2 Console | Metasploit session management and command execution |
| `/vulns` | Vuln Tracker | Vulnerability lifecycle tracking with AI remediation |
| `/logs` | Log Analysis | Log paste/upload, pattern matching, IOC extraction |
| `/reports` | Reports | HTML/Markdown report generation |
| `/scans` | All Scans | Cross-project scan history with filters |
| `/findings` | All Findings | Cross-project findings list with expandable detail |
| `/settings` | Settings | Tool detection, profiles, AI config, user management |
| `/guide` | Guide | Platform documentation and usage help |

---

## API

Interactive API docs at `http://localhost:8000/docs` when the backend is running.

| Prefix | Description |
|--------|-------------|
| `/api/v1/projects` | Projects and targets |
| `/api/v1/audit` | Scan generation, execution, findings |
| `/api/v1/pentest` | Pentest engagements and phases |
| `/api/v1/playbooks` | Playbook management and runs |
| `/api/v1/vulns` | Vulnerability tracker |
| `/api/v1/logs` | Log analysis and IOC extraction |
| `/api/v1/c2` | C2 / Metasploit integration |
| `/api/v1/credentials` | Credential vault |
| `/api/v1/cracking` | Password auditing jobs |
| `/api/v1/osint` | OSINT tools |
| `/api/v1/auth` | Authentication and user management |
| `/api/v1/stats` | Platform-wide statistics |
| `/api/v1/findings` | Cross-project findings |
| `/api/v1/scans` | Cross-project scans |
| `/api/v1/demo` | Demo data seed / clear |
| `/ws/...` | WebSocket streams (terminal, scan output) |

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SERAPH_SECRET_KEY` | `dev-secret-key` | JWT signing key — **change this in production** |

### Database

Seraph uses SQLite by default (`backend/seraph.db`), created automatically on first run. To change the path, update `database_url` in `config.py`.

### Themes

Two visual themes: **Cyber Blue** (default) and **Monochrome**. The preference is stored in the browser. Severity and status colors are always preserved regardless of theme.

---

## Security Notes

- Change `SERAPH_SECRET_KEY` before any non-local deployment
- Intended for use on private networks or over a VPN — no built-in rate limiting or IP allowlisting
- The C2 module requires a running `msfrpcd` instance
- All scan execution happens server-side; ensure the Seraph host has appropriate network access to targets in scope

---

## License

MIT
