# Seraph

A desktop pentest management platform built on Electron. Seraph connects to a self-hosted backend and gives operators a unified interface for the full engagement lifecycle — from recon and exploitation through credential management, reporting, and AI-assisted analysis.

---

## Features

### Recon
- **OSINT Module** — passive intelligence gathering against targets
- **Network Map** — interactive Cytoscape graph of discovered hosts, services, and relationships
- **Screenshot Gallery** — gowitness web-host capture with live streaming, thumbnail grid, and click-to-zoom lightbox (out-of-scope URLs dropped automatically)

### Offense
- **Pentest Workbench** — run scan modules, review raw output, and triage findings per target
- **Request Workbench** — Repeater/Intruder-lite: edit & replay raw HTTP requests, fuzz a `§FUZZ§` marker across payloads with live streamed results, scope-enforced
- **C2 Console** — Metasploit RPC integration with live session management, task execution, and loot capture
- **AD Attack Suite** — import a BloodHound/SharpHound collection and surface quick-wins (kerberoastable, AS-REP, unconstrained delegation, high-value principals) with ready-to-copy commands
- **Playbooks** — saved multi-step attack sequences with configurable scan categories
- **Attack Paths** — graph-based visualization of exploitation chains across the network
- **ATT&CK Navigator** — technique-coverage heatmap scored from findings + playbook runs; exports a MITRE Navigator layer
- **AI Operator** — LLM-backed assistant with full project context for attack planning, script generation, and technique guidance
- **Command Library** — searchable reference of offensive commands organized by category

### Credentials
- **Credential Vault** — stores passwords, hashes, keys, and tokens per project; tracks source (manual, C2 loot, OSINT, brute force)
- **Password Auditing** — hashcat/john integration for offline cracking jobs

### Defense
- **Audit Builder** — compliance-focused audit scans with control mapping (CIS, NIST, PCI)
- **Agents** — manage persistent implants and their task queues
- **Listeners** — configure and monitor reverse shell / beacon listeners
- **Vuln Tracker** — per-finding status workflow (open → in-review → remediated → accepted)
- **CVE Watch** — auto-detected services are monitored nightly against NVD; new CVEs surface as alerts
- **Engagement Timeline** — chronological event feed (targets added, scans run, findings discovered) with severity and kind filters
- **Log Analysis** — search and correlate raw scan logs across the project
- **Ask Seraph** — natural-language Q&A grounded in the engagement's own findings/loot/scans/credential-metadata (keyword RAG + the configured Ollama model), with clickable citations back to source rows

### Reporting & Settings
- **Reports** — generate structured engagement reports from findings
- **Settings** — configure the backend connection, Metasploit RPC, Auto-Probe, scan templates, and appearance
- **Guide** — built-in operator reference

---

## Architecture

Seraph-Electron is a thin desktop client. All data lives on a self-hosted [Seraph backend](https://github.com/halicea7/seraph) — a Python/FastAPI server with a PostgreSQL database. The Electron app connects over HTTP/WebSocket using a server URL configured at first launch.

```
┌─────────────────────┐        HTTP / WS        ┌──────────────────────┐
│  Seraph-Electron    │ ──────────────────────▶ │   Seraph Backend     │
│  (this repo)        │                          │  FastAPI + Postgres  │
└─────────────────────┘                          └──────────────────────┘
```

---

## Getting Started

**Prerequisites:**
- A running [Seraph backend](https://github.com/halicea7/seraph) instance
- Node.js 20+

```bash
git clone https://github.com/halicea7/seraph-electron.git
cd seraph-electron
npm install
npm run dev
```

On first launch you'll be prompted for your backend URL (e.g. `http://192.168.1.10:8000`) and credentials. The URL is saved locally and used for all subsequent sessions.

### Building a distributable

```bash
npm run build:linux   # AppImage + .deb
npm run build:win     # NSIS installer
npm run build:mac     # .dmg
```

---

## Connecting over HTTPS

If the backend is served over HTTPS with a self-signed / mkcert certificate (see the backend's
`setup-https.sh`), the app trusts that certificate **automatically for the host you enter on the
Connect screen** — no per-machine CA install. Every other origin is still verified normally. Just
enter the `https://…` URL and connect.

---

## Passkeys (WebAuthn)

Passkeys have two hard requirements that come from the OS / WebAuthn spec — the desktop app can't
work around them:

1. **Connect via a hostname or `localhost`, not a bare IP.** WebAuthn rejects IP addresses as
   Relying Party IDs, so a passkey can't be registered against e.g. `https://172.16.235.128:8000`.
   The backend's `SERAPH_RP_ID` defaults to `localhost`.
2. **macOS: launch the built app from Finder, not a terminal.** Running `npm run dev` from a shell
   makes the terminal the "responsible process," and macOS blocks Touch ID / caBLE
   (`FIDO: ... process is not self-responsible`). Build the app and open the bundle instead.

**Recommended setup when the backend is on another machine** — forward it to `localhost` and connect
there. No backend changes are needed: the mkcert cert already covers `localhost`, and
`https://localhost:8000` is an allowed origin by default.

```bash
# on the client: forward the remote backend port to localhost (leave running)
ssh -L 8000:localhost:8000 user@backend-host -N

# build + launch from Finder (macOS) so the platform authenticator is allowed
npm run build:mac
open dist/mac/Seraph.app          # 'open' launches via LaunchServices = self-responsible
```

Then point the Connect screen at `https://localhost:8000` and register your passkey in
**Settings → Passkeys**.

> Password login works over **any** URL (including a bare IP) — only passkeys require the
> hostname/`localhost` + Finder-launch conditions above.

---

## Stack

- [Electron](https://electronjs.org) + [electron-vite](https://electron-vite.org)
- [React 18](https://react.dev) + [React Router v6](https://reactrouter.com) + TypeScript
- [Zustand](https://zustand-demo.pmnd.rs) for global state
- [Cytoscape.js](https://cytoscape.org) for network graph rendering
- [xterm.js](https://xtermjs.org) for the C2 terminal
- [Tailwind CSS](https://tailwindcss.com) + Paper Dark design system (CSS variables)
- [Lucide React](https://lucide.dev) icons + custom Icon component

---

## Navigation Structure

| Section | Pages |
|---------|-------|
| **Recon** | OSINT, Network Map, Screenshot Gallery |
| **Offense** | Pentest Workbench, Request Workbench, C2 Console, AD Attack Suite, Playbooks, Attack Paths, ATT&CK Navigator, AI Operator, Command Library |
| **Credentials** | Credential Vault, Password Auditing |
| **Findings & Analysis** | Findings, CVE Watch, Timeline, Log Analysis, Scan Diff, Ask Seraph |
| **Defense** | Audit Builder, Agents, Listeners |
| **Other** | Dashboard, Reports, Settings, Guide |
