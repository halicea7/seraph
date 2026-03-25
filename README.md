# Seraph

A self-hosted security assessment platform combining compliance auditing, penetration testing workflows, credential management, vulnerability tracking, and AI-assisted analysis in a single unified interface.

> **For authorized use only.** Seraph is designed for security professionals conducting legitimate, scoped engagements.

---

## Features

| Category | Capability |
|----------|-----------|
| **Compliance** | CIS / NIST 800-53 scan templates, bash script generation, Lynis / OpenSCAP integration |
| **Pentest** | Phased workflows (recon → scanning → exploitation), tool-chained command templates, live terminal |
| **Playbooks** | Multi-step automated workflows with step-through, auto-run, and conditional logic |
| **Recon** | OSINT module (Whois, Subfinder, theHarvester, Searchsploit), network visualization |
| **C2** | Metasploit RPC integration — manage sessions, execute commands, harvest loot |
| **Credentials** | Vault for passwords, hashes, keys, tokens with source tracking and password auditing (Hashcat / John) |
| **Defense** | Vulnerability tracker with status workflow, AI remediation suggestions, log analysis and IOC extraction |
| **Reporting** | HTML, Markdown, and PDF audit/pentest reports with executive summaries and finding tables |
| **AI Narrative** | Local LLM integration (Ollama) for AI-generated executive and technical narratives |
| **Multi-user** | Admin / analyst roles, JWT authentication, per-user profiles, user management |
| **Auto-Probe** | Automatic nmap + nikto scan triggered when a new target is added |
| **Demo Mode** | Seed realistic demo data across three projects to explore the platform (admin only) |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Tailwind CSS, Vite |
| Backend | FastAPI, Python 3.11+, SQLAlchemy |
| Database | SQLite (zero-config, file-based) |
| Real-time | WebSockets (terminal I/O, scan streaming) |
| Scheduling | APScheduler (recurring scan profiles) |
| Auth | JWT + bcrypt |
| Visualization | Cytoscape.js (network map), XTerm.js (terminal) |

---

## Requirements

### System

- **Python 3.11+**
- **Node.js 20+** and npm
- Linux or macOS (Windows via WSL)

### Python packages

Installed via `pip install -r requirements.txt`. Key dependencies:

| Package | Purpose |
|---------|---------|
| `fastapi` + `uvicorn` | API server |
| `sqlalchemy` | ORM / SQLite |
| `bcrypt` + `python-jose[cryptography]` | Auth (password hashing + JWT) |
| `jinja2` | Report and script templating |
| `apscheduler` | Scheduled scan profiles |
| `pymetasploit3` | C2 / Metasploit RPC (optional) |
| `weasyprint` | PDF report export (optional, not installed by default) |

### Optional security tools

Detected automatically at startup via `which`. Missing tools are flagged in **Settings → Tools** with an install command shown.

```
nmap       nikto      testssl.sh   lynis      openscap   masscan
gobuster   sqlmap     hydra        whois      dig        theHarvester
subfinder  enum4linux ffuf         searchsploit hashcat   john
metasploit
```

---

## Setup

### 1. Clone and configure environment

```bash
git clone https://github.com/YOURUSERNAME/Seraph.git
cd Seraph

cp .env.example .env
```

Edit `.env` and set at minimum:

```env
# Required in production — generate with:
# python3 -c "import secrets; print(secrets.token_hex(32))"
SERAPH_SECRET_KEY=your-random-secret-here

# Only needed if using the C2 / Metasploit module
MSF_RPC_PASSWORD=your-msf-password
```

> If `SERAPH_SECRET_KEY` is not set, a random key is generated per-process. This means **all sessions are invalidated on every restart**. Always set it in production.

---

### 2. Option A — Dev script (recommended for first run)

```bash
./dev.sh
```

This installs Python and Node dependencies, starts the backend on `:8000` and the Vite dev server on `:22123`, and optionally starts `msfrpcd` if Metasploit is installed.

Open **http://localhost:22123** in your browser.

---

### 2. Option B — Manual

**Backend**

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r ../requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Frontend** (separate terminal)

```bash
cd frontend
npm install
npm run dev        # dev server on :22123, proxies /api and /ws to :8000
```

Or build for production (served by the backend at `:8000`):

```bash
npm run build      # outputs to frontend/dist/
```

---

### 2. Option C — Docker

```bash
docker compose up --build
```

| Service | URL |
|---------|-----|
| Web UI + API | `http://localhost:8000` |
| API Docs | `http://localhost:8000/docs` |

Data is persisted in named Docker volumes (`seraph_data`, `seraph_results`).

---

## First Run

1. Navigate to the app URL. Seraph detects no users and shows a **First-Run Setup** screen.
2. Enter your **First Name**, **Last Name**, **username**, and a password (min 8 characters). This creates the initial admin account.
3. Log in and you're ready to go.

Your full name is used as the default **Auditor** field when generating reports. You can update it later in **Settings → Users → My Profile**.

To explore the platform without running real scans, go to **Settings → Appearance → Load Demo Data** (admin only). This seeds three realistic demo projects — an external pentest, a web application audit, and an internal network assessment — complete with targets, scans, findings, credentials, and vulnerability records. Toggle off to remove all demo data cleanly.

---

## PDF Report Export (optional)

PDF export uses [WeasyPrint](https://doc.courtbouillon.org/weasyprint/). It is not installed by default due to system library requirements.

**Ubuntu / Debian:**

```bash
sudo apt install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0
pip install weasyprint
```

**macOS:**

```bash
brew install pango
pip install weasyprint
```

Once installed, the **PDF** button in the Reports page will work.

---

## AI Narrative (optional)

Seraph integrates with local LLMs via [Ollama](https://ollama.com). Set the endpoint in **Settings → AI**. Default is `http://localhost:11434`.

```bash
# Install Ollama, then pull a model
ollama pull llama3
```

The AI Narrative feature in Reports generates executive or technical summaries of findings using the configured model.

---

## C2 / Metasploit (optional)

The C2 Console requires `msfrpcd` to be running:

```bash
# Using MSF_RPC_PASSWORD from your .env
msfrpcd -P "$MSF_RPC_PASSWORD" -S -a 127.0.0.1 -p 55553 -f
```

`dev.sh` handles this automatically if Metasploit is installed.

---

## User Management

- The first account created is always **admin**.
- Admins can create additional users at **Settings → Users → Create User** (requires First Name, Last Name, username, password, and role).
- Any user can edit their own name at **Settings → Users → My Profile** and change their password.
- Roles: `admin` (full access + user management) and `analyst` (standard access).

---

## Security Notes

- Seraph is intended for use on **private networks or over a VPN**. There is no built-in rate limiting or IP allowlisting.
- Always set `SERAPH_SECRET_KEY` to a long random value in any non-local deployment.
- The database file (`backend/seraph.db`) and scan results (`backend/seraph_results/`) are gitignored and must never be committed — they may contain sensitive target data.
- All scan execution happens server-side. Ensure the Seraph host has appropriate network access to targets in scope.

---

## API

Interactive docs available at `http://localhost:8000/docs` when the backend is running.

| Prefix | Description |
|--------|-------------|
| `/api/v1/projects` | Projects and targets |
| `/api/v1/audit` | Scan generation, finding parsing, reports |
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
| `/api/v1/diff` | Scan diff comparison |
| `/api/v1/ai` | AI narrative generation |
| `/ws/...` | WebSocket streams (terminal, scan output) |

---

## License

MIT
