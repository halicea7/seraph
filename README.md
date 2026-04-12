<p align="center">
  <img src="docs/banner.png" alt="Seraph Security Platform" width="100%">
</p>

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
| **C2** | Metasploit RPC integration — sessions, payloads, listeners, loot, post-exploitation |
| **Post-Ex** | Per-session checklist (12 items), auto-probe, credential harvesting, pivot route manager, screenshot, shell upgrade |
| **Active Directory** | Kerbrute enumeration, NetExec SMB/LDAP/WinRM, Kerberoasting, AS-REP roasting, secretsdump, psexec/wmiexec |
| **Credentials** | Vault for passwords, hashes, keys, tokens with source tracking and password auditing (Hashcat / John) |
| **Defense** | Vulnerability tracker with status workflow, AI remediation suggestions, log analysis and IOC extraction |
| **Reporting** | HTML, Markdown, and PDF audit/pentest reports with executive summaries and finding tables |
| **AI Narrative** | Local LLM integration (Ollama) for AI-generated executive and technical narratives |
| **Multi-user** | Admin / analyst roles, JWT authentication, per-user profiles, user management |
| **Auto-Probe** | Automatic nmap + nikto + searchsploit scan triggered when a new target is added |
| **Passkeys** | WebAuthn / FIDO2 passkey support per user (iCloud Keychain, Touch ID, Face ID, YubiKey) |
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
| Auth | JWT + bcrypt + WebAuthn (passkeys) |
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
| `webauthn` | Passkey / FIDO2 registration and authentication |
| `weasyprint` | PDF report export (optional, not installed by default) |

### Optional security tools

Detected automatically at startup via `which`. Missing tools are flagged in **Settings → Tools** with an install command shown.

```
nmap          nikto         testssl.sh    lynis         openscap      masscan
gobuster      sqlmap        hydra         whois         dig           theHarvester
subfinder     enum4linux    ffuf          searchsploit  hashcat       john
rustscan      nuclei        feroxbuster   kerbrute      nxc           responder
impacket      metasploit
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

## HTTPS (required for passkeys)

Passkeys (WebAuthn) require a secure context — either HTTPS or `http://localhost`. If you access Seraph over a local IP address or need passkeys in the browser, enable HTTPS with the included setup script.

### Local development (no domain needed)

Uses [mkcert](https://github.com/FiloSottile/mkcert) to generate a **locally-trusted certificate** — Brave, Chrome, and Firefox will show a green padlock with no warnings.

```bash
# One-time setup
bash setup-https.sh
```

This will:
1. Install `mkcert` and `libnss3-tools` (the latter is required for Brave/Chrome trust on Linux)
2. Run `mkcert -install` to add a local CA to the system and browser trust stores
3. Generate `seraph/certs/localhost.pem` and `seraph/certs/localhost-key.pem`

Then restart `dev.sh` — it detects the certs automatically and starts both servers over HTTPS:

```
https://localhost:22123   ← dev server
https://localhost:8000    ← production build
```

> **After running `mkcert -install`, fully quit and relaunch Brave/Chrome** for the CA trust to take effect.

> **Accessing from another machine on the LAN?** Chromium-based browsers reject `.local` mDNS hostnames as WebAuthn RP IDs. The simplest workaround is an SSH port-forward from the client machine so the browser sees `localhost`:
> ```bash
> ssh -L 8000:localhost:8000 user@seraph-host -N
> ```
> Then open `https://localhost:8000` — no `.env` changes needed, the default `rp_id = localhost` is correct.

### Production / real domain

Set these variables in your `.env`:

```env
SERAPH_RP_ID=yourdomain.com
SERAPH_RP_ORIGINS=https://yourdomain.com
```

Then run uvicorn behind a reverse proxy (nginx, Caddy) that terminates TLS with a valid certificate.

---

## Passkeys

Once HTTPS is running, each user can register passkeys (iCloud Keychain, Touch ID, Face ID, YubiKey, Windows Hello, etc.) in **Settings → Users → Passkeys**. Multiple passkeys per account are supported.

On the login page, the **Sign in with Passkey** button skips the password form entirely.

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

### Post-Exploitation

Each active session has a **Post-Ex** tab with:

- **Auto-Probe** — automatically runs platform-appropriate initial recon (sysinfo, getuid, network config, process list) when a session opens. Results stored as loot.
- **Post-Ex Checklist** — 12-item guided checklist across 6 categories (Situational Awareness, Privilege Escalation, Credential Access, Persistence, Lateral Movement, Evidence)
- **Harvest Credentials** — runs hashdump + Mimikatz kiwi (Windows) or reads /etc/shadow (Linux); parsed credentials auto-save to the Credential Vault
- **Pivot Routes** — add/remove MSF route entries to tunnel traffic through a session to internal subnets
- **Screenshot** — capture the compromised desktop inline
- **Upgrade Shell** — upgrade a plain shell session to Meterpreter with live streaming output

---

## Active Directory Assessments

Select the **Active Directory** engagement type in the Pentest Workbench for domain assessments. Required tools (install via Settings → Tools):

| Tool | Purpose | Install |
|------|---------|---------|
| `kerbrute` | Domain user enumeration and password spraying | `go install github.com/ropnop/kerbrute@latest` |
| `nxc` (NetExec) | SMB/LDAP/WinRM enumeration and credential validation | `pip3 install netexec` |
| `impacket` | Kerberoasting, AS-REP roasting, secretsdump, psexec, wmiexec | `pip3 install impacket` |
| `responder` | LLMNR/NBT-NS poisoning for NTLMv2 hash capture | git clone from GitHub |

Captured Kerberos hashes (TGS-REP / AS-REP) are saved to the Credential Vault and can be loaded directly into Password Auditing for hashcat cracking (modes 13100 / 18200).

---

## User Management

- The first account created is always **admin**.
- Admins can create additional users at **Settings → Users → Create User** (requires First Name, Last Name, username, password, and role).
- Any user can edit their own name at **Settings → Users → My Profile**, change their password, and register passkeys.
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
| `/api/v1/passkeys` | WebAuthn passkey registration and authentication |
| `/api/v1/stats` | Platform-wide statistics |
| `/api/v1/diff` | Scan diff comparison |
| `/api/v1/ai` | AI narrative generation |
| `/ws/...` | WebSocket streams (terminal, scan output) |

---

## License

MIT
