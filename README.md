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
| **Request Workbench** | Repeater/Intruder-lite — edit & replay raw HTTP requests, fuzz a `§FUZZ§` marker across payloads with live streamed results, scope-enforced |
| **Playbooks** | Multi-step automated workflows with step-through, auto-run, and conditional logic |
| **ATT&CK Navigator** | Technique-coverage heatmap scored from the engagement's findings + playbook runs; exports an importable MITRE Navigator layer |
| **Recon** | OSINT module (Whois, Subfinder, theHarvester, Searchsploit), network visualization |
| **Screenshot Gallery** | gowitness web-host capture streamed live, visual triage gallery + lightbox pinned to the project |
| **C2** | Metasploit RPC integration — sessions, payloads, listeners, loot, post-exploitation |
| **Post-Ex** | Per-session checklist (12 items), auto-probe, credential harvesting, pivot route manager, screenshot, shell upgrade |
| **Active Directory** | Kerbrute enumeration, NetExec SMB/LDAP/WinRM, Kerberoasting, AS-REP roasting, secretsdump, psexec/wmiexec |
| **AD Attack Suite** | Import a BloodHound/SharpHound collection → attack-graph + quick-win analysis (kerberoastable, AS-REP, unconstrained delegation, high-value principals) with scaffolded commands |
| **Credentials** | Vault for passwords, hashes, keys, tokens with source tracking and password auditing (Hashcat / John) |
| **Defense** | Vulnerability tracker with status workflow, AI remediation suggestions, log analysis and IOC extraction |
| **Reporting** | HTML, Markdown, and PDF audit/pentest reports with executive summaries and finding tables |
| **AI Narrative** | Local LLM integration (Ollama) for AI-generated executive and technical narratives |
| **Ask Seraph (Q&A)** | Natural-language questions answered from the engagement's own findings/loot/scans/credential-metadata via keyword RAG + the configured Ollama model, with clickable citations |
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
impacket      metasploit    gowitness     bloodhound-python
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

### 2. Option C — Docker (recommended for the desktop app)

The all-in-one image bundles the backend API **and every supported security tool**
(nmap, nuclei, nxc, impacket, responder, …) in one container, backed by SQLite. This
is the intended way to run Seraph for the **SeraphElectron** desktop app, which connects
to the backend over the network.

**One command:**

```bash
./setup.sh
```

`setup.sh` is zero-prompt and idempotent. It:

1. Verifies Docker + Compose are installed and the daemon is reachable.
2. Creates `.env` from `.env.example` (only on first run) and generates strong random
   values for `SERAPH_SECRET_KEY`, `MSF_RPC_PASSWORD`, and `POSTGRES_PASSWORD`. Existing
   values are **never** overwritten, so it's safe to re-run.
3. Builds the image and starts the container (`docker compose up -d --build`).
4. Waits for the API to become healthy, then prints the URL to connect.

> **First build takes several minutes** — it pulls and compiles the full tool suite (image
> is ~3.5 GB). Subsequent runs are cached and start in seconds.

**Connecting the SeraphElectron desktop app:** open the app's **Connect** screen and enter
the backend URL printed by `setup.sh`:

| From | URL |
|------|-----|
| Same machine as the container | `http://localhost:8000` |
| Another machine on your LAN | `http://<host-ip>:8000` |
| API docs (browser) | `http://localhost:8000/docs` |

CORS is already wide-open for the Electron app and the port binds all interfaces — no extra
configuration needed. Create your admin account on the app's First-Run screen.

> This image is **API-only** — it does not serve a browser web UI. The SeraphElectron app
> is the frontend. (For a browser-served SPA, use the dev script in Option A or a manual
> production build in Option B.)

**Without `setup.sh`** (manual, or to change the port):

```bash
cp .env.example .env          # then set SERAPH_SECRET_KEY
SERAPH_PORT=9000 docker compose up -d --build
```

**Managing the container:**

```bash
docker compose logs -f        # follow logs
docker compose down           # stop (data persists in volumes)
docker compose down -v        # stop AND wipe all data (fresh start)
```

Data is persisted in named Docker volumes (`seraph_data` for the SQLite DB, `seraph_results`,
`seraph_reports`).

**Updating an existing install** (you ran `setup.sh` before and want the latest version):

```bash
cd seraph
git pull                      # get the latest code (Dockerfile, compose, scripts)
./setup.sh                    # rebuilds the image and recreates the container
```

`setup.sh` runs `docker compose up -d --build`, so it picks up the new image and restarts the
container. Your **`.env` is preserved** (existing secrets are never overwritten) and your **data
survives** in the named volumes — schema changes are migrated automatically on startup. To enable
HTTPS at the same time, run `./setup-https.sh` first, then `./setup.sh`. Reclaim space from the old
image afterward with `docker image prune -f`.

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
3. Generate `seraph/certs/localhost.pem` and `seraph/certs/localhost-key.pem`, valid for
   `localhost`, `127.0.0.1`, **and this host's LAN IP(s) + hostname** (so it also works when a
   client connects via the host IP). The cert + key are made world-readable so the Docker
   container (which runs as a non-root user) can load them.

Then restart `dev.sh` — it detects the certs automatically and starts both servers over HTTPS:

```
https://localhost:22123   ← dev server
https://localhost:8000    ← production build
```

> **After running `mkcert -install`, fully quit and relaunch Brave/Chrome** for the CA trust to take effect.

### Docker (HTTPS for the all-in-one container)

The all-in-one image auto-detects certs — no flags to pass. Generate them once, then run setup:

```bash
./setup-https.sh      # one-time: creates seraph/certs/ (localhost + LAN SANs)
./setup.sh            # the container starts on HTTPS automatically
```

`docker-compose.yml` mounts `./certs` into the container read-only; the entrypoint enables TLS
when both files are present and falls back to plain HTTP when they aren't. `setup.sh` prints the
`https://localhost:8000` and `https://<host-ip>:8000` URLs to point the SeraphElectron app at.

> **Connecting from another machine on the LAN?** The mkcert CA is only trusted on the host where
> `setup-https.sh` ran. On each **client** machine, either trust that host's root CA or accept the
> browser warning once. Copy the CA from the Seraph host:
> ```bash
> # on the Seraph host — find and copy the root CA
> cp "$(mkcert -CAROOT)/rootCA.pem" .     # then install rootCA.pem in the client's trust store
> ```
> On the client run `mkcert -install` after placing `rootCA.pem` in its `$(mkcert -CAROOT)`, or
> import it through the OS/browser certificate manager.

> **Passkeys over a LAN IP won't work.** WebAuthn rejects bare IP addresses as RP IDs, so HTTPS via
> `https://<host-ip>:8000` gives you **encrypted transport** but not browser passkeys. Passkeys
> still work at `https://localhost:8000` on the same machine. For passkeys from another machine, use
> the SSH port-forward trick so the client sees `localhost`:
> ```bash
> ssh -L 8000:localhost:8000 user@seraph-host -N
> ```

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

### Ask Seraph (engagement Q&A)

**Ask Seraph** (Findings & Analysis) answers natural-language questions about the current
engagement — *"What are the critical findings?"*, *"Which credentials have we collected?"* —
grounded in the project's own data. It uses lightweight **keyword retrieval** (no embeddings
or vector database) over the project's findings, vulnerability records, C2 loot, scans, and
credential **metadata** (secrets are never sent to the model), assembles a grounded prompt,
and answers with the **same configured Ollama model** used for AI Narrative. Each answer
includes citation chips that deep-link back to the source finding/scan/loot.

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

### AD Attack Suite (BloodHound import)

The **AD Attack Suite** page (Offense) ingests a BloodHound/SharpHound collection
(`.zip` or `.json`) and analyzes it locally — no Neo4j required. It surfaces quick-win
attack opportunities as cards:

- **Kerberoastable** accounts (SPN set) and **AS-REP roastable** accounts (no pre-auth)
- **Unconstrained delegation** hosts/accounts
- **High-value principals** (`adminCount=1`, Domain/Enterprise Admins)

Each card lists the affected principals and a ready-to-copy command (impacket / NetExec)
to run from the Pentest Workbench or AI Operator. Collect with SharpHound or
`bloodhound-python`, then import the resulting archive.

---

## Web Application Testing — Request Workbench

The **Request Workbench** (Offense) is a Repeater/Intruder-lite built on `httpx`:

- **Repeater** — edit a raw request (method, URL, headers, body), send, and inspect the
  full response (status, headers, body, size, timing).
- **Intruder** — place a `§FUZZ§` marker in the URL, a header, or the body, supply a
  payload list, and stream per-payload results (status · length · time) into a sortable
  table for quick anomaly spotting.

All requests are **scope-enforced** against the project's include/exclude rules before
anything is sent. Frequently-used requests can be saved to a per-project collection.

---

## Screenshot Gallery

The **Screenshot Gallery** (Recon) runs [gowitness](https://github.com/sensepost/gowitness)
across a list of web hosts (auto-fillable from project targets), streams capture progress
live, and presents the results as a thumbnail grid with a click-to-zoom lightbox.
Out-of-scope URLs are dropped automatically.

---

## ATT&CK Navigator

The **ATT&CK Navigator** (Offense) renders a technique-coverage heatmap for the current
engagement, scored from how often each MITRE technique is referenced across the project's
findings and playbook runs. Cells are colored by score, and **Export layer** downloads an
ATT&CK Navigator–compatible JSON layer you can open at
[mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/).

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

## Troubleshooting

### `Docker is installed but the daemon isn't reachable`

`setup.sh` aborts here when `docker info` fails. Two common causes:

**1. The Docker daemon isn't running.** Start it (and enable it on boot so it survives a reboot):

```bash
sudo systemctl enable --now docker
sudo systemctl is-active docker      # should print: active
```

**2. Your user isn't in the `docker` group.** The Docker socket is owned by `root:docker`, so
without group membership every `docker` command is denied — which surfaces as "daemon isn't
reachable". Add yourself and re-apply the group:

```bash
sudo usermod -aG docker "$USER"
newgrp docker                        # applies the group to the current shell
docker info >/dev/null && echo OK    # verify
```

(A full log out / log back in also works, and is needed for other shells.)

**Quick check — which one is it?**

```bash
sudo systemctl is-active docker                                          # daemon up?
id -nG | tr ' ' '\n' | grep -qx docker && echo "in group" || echo "NOT" # permissions?
```

**Unblock regardless of cause:** run the script with `sudo ./setup.sh`.

### First build is slow / a tool says "skipped (optional)"

The first build compiles the full tool suite and can take several minutes. Optional third-party
tools are installed **best-effort** — if an upstream release asset is temporarily unavailable,
the build logs `[build] <tool> skipped (optional)` and continues instead of failing. Seraph
detects whatever ended up missing in **Settings → Tools**; re-run `docker compose build` later
to pick it up.

### Port 8000 is already in use

Pick a different host port — the container still listens on 8000 internally:

```bash
SERAPH_PORT=9000 ./setup.sh          # or: SERAPH_PORT=9000 docker compose up -d --build
```

Then point the SeraphElectron Connect screen at `http://<host>:9000`.

### The SeraphElectron app can't connect

1. Confirm the API is healthy from the **same machine running the container**:
   ```bash
   curl http://localhost:8000/api/v1/auth/setup-required     # → {"required": ...}
   ```
2. Connecting from another machine? Use the host's **LAN IP**, not `localhost`
   (`setup.sh` prints it), and make sure the host firewall allows inbound TCP on the port.
3. `docker compose ps` should show the `seraph` service as `healthy`. If not, check
   `docker compose logs -f`.

### Sessions reset / "logged out" on every restart

`SERAPH_SECRET_KEY` isn't set, so a random key is generated per process. `setup.sh` sets it for
you; if you bypassed it, add a fixed value to `.env`:

```bash
python3 -c "import secrets; print('SERAPH_SECRET_KEY=' + secrets.token_hex(32))" >> .env
```

### HTTPS didn't turn on (container started on HTTP)

The container enables TLS only when **both** `certs/localhost.pem` and `certs/localhost-key.pem`
exist and are readable. Check:

```bash
ls -l certs/                                  # both files present?
docker compose logs | grep entrypoint         # "TLS certs found" vs "No TLS certs"
```

If the log says the certs exist *but aren't readable*, make them world-readable (the container
runs as a non-root user) and restart:

```bash
chmod 0644 certs/*.pem
docker compose up -d
```

A browser/Electron TLS error from another machine almost always means the client doesn't trust the
mkcert root CA — see **HTTPS → Docker** above for distributing it.

### Start completely fresh

```bash
docker compose down -v               # removes containers AND the data volumes
./setup.sh                           # rebuild + recreate from scratch
```

---

## API

Interactive docs available at `http://localhost:8000/docs` when the backend is running.

| Prefix | Description |
|--------|-------------|
| `/api/v1/projects` | Projects and targets |
| `/api/v1/audit` | Scan generation, finding parsing, reports |
| `/api/v1/pentest` | Pentest engagements and phases |
| `/api/v1/http` | Request Workbench — send/replay + fuzz (`/ws/httpfuzz` stream) |
| `/api/v1/ad` | AD Attack Suite — collection import, graph, quick-wins, command scaffolds |
| `/api/v1/screenshots` | Screenshot Gallery — gowitness capture (`/ws/screenshots` stream) + image serving |
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
| `/api/v1/ai` | AI narrative, Ask Seraph Q&A (`/ai/ask`), ATT&CK coverage (`/ai/attack/coverage`) |
| `/ws/...` | WebSocket streams (terminal, scan output, screenshots, HTTP fuzz) |

---

## License

MIT
