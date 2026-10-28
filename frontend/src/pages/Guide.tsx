import { useState, useEffect, useRef, ReactNode } from 'react'
import {
  BookOpen, Search, LayoutDashboard, ShieldCheck, Swords, Globe,
  Network, Lock, Terminal, KeyRound, FileText, Settings, Zap,
  BookOpen as Playbooks, ChevronRight, Info, AlertTriangle, Lightbulb,
  Bell, Command, GitCompare, Bot, Library, StickyNote,
  Cpu, GitBranch, Eye, Radio, FileSearch, History, Bug,
} from 'lucide-react'

const rule = '1px solid var(--rule)'
const ruleStrong = '1px solid var(--rule-strong)'

// ── Content types ──────────────────────────────────────────────────────────────

interface Section {
  id: string
  title: string
  icon: ReactNode
  subsections: Subsection[]
}

interface Subsection {
  id: string
  title: string
  content: ReactNode
}

// ── Reusable content components ────────────────────────────────────────────────

function Tip({ children }: { children: ReactNode }) {
  return (
    <div style={{ display: 'flex', gap: 12, borderRadius: 4, padding: '12px 16px', margin: '12px 0', background: 'rgba(240,168,58,0.06)', border: '1px solid rgba(240,168,58,0.2)' }}>
      <Lightbulb size={15} style={{ color: 'var(--accent)', flexShrink: 0, marginTop: 2 }} />
      <div style={{ fontSize: 13, color: 'var(--fg-2)' }}>{children}</div>
    </div>
  )
}

function Warning({ children }: { children: ReactNode }) {
  return (
    <div style={{ display: 'flex', gap: 12, borderRadius: 4, padding: '12px 16px', margin: '12px 0', background: 'rgba(232,64,64,0.06)', border: '1px solid rgba(232,64,64,0.2)' }}>
      <AlertTriangle size={15} style={{ color: 'var(--crit)', flexShrink: 0, marginTop: 2 }} />
      <div style={{ fontSize: 13, color: 'var(--fg-2)' }}>{children}</div>
    </div>
  )
}

function Note({ children }: { children: ReactNode }) {
  return (
    <div style={{ display: 'flex', gap: 12, borderRadius: 4, padding: '12px 16px', margin: '12px 0', background: 'rgba(100,116,139,0.08)', border: ruleStrong }}>
      <Info size={15} style={{ color: 'var(--fg-3)', flexShrink: 0, marginTop: 2 }} />
      <div style={{ fontSize: 13, color: 'var(--fg-3)' }}>{children}</div>
    </div>
  )
}

function Cmd({ children }: { children: ReactNode }) {
  return (
    <code style={{ display: 'inline-block', padding: '1px 8px', borderRadius: 4, fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent)', border: ruleStrong, background: 'var(--bg)' }}>
      {children}
    </code>
  )
}

function Block({ children }: { children: ReactNode }) {
  return (
    <pre style={{ borderRadius: 4, padding: '12px 16px', margin: '12px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--fg-2)', overflowX: 'auto', border: ruleStrong, background: 'var(--bg)', lineHeight: 1.6 }}>
      {children}
    </pre>
  )
}

function Steps({ items }: { items: string[] }) {
  return (
    <ol style={{ listStyle: 'none', padding: 0, margin: '12px 0', display: 'flex', flexDirection: 'column', gap: 8 }}>
      {items.map((item, i) => (
        <li key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <span style={{ flexShrink: 0, width: 20, height: 20, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, color: 'var(--accent)', border: '1px solid rgba(240,168,58,0.3)', background: 'rgba(240,168,58,0.08)', marginTop: 2 }}>
            {i + 1}
          </span>
          <span style={{ fontSize: 13, color: 'var(--fg-2)' }}>{item}</span>
        </li>
      ))}
    </ol>
  )
}

function Bullets({ items }: { items: (string | ReactNode)[] }) {
  return (
    <ul style={{ listStyle: 'none', padding: 0, margin: '12px 0', display: 'flex', flexDirection: 'column', gap: 6 }}>
      {items.map((item, i) => (
        <li key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: 13, color: 'var(--fg-2)' }}>
          <ChevronRight size={13} style={{ color: 'var(--accent)', flexShrink: 0, marginTop: 2 }} />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  )
}

const BADGE_STYLES: Record<string, { color: string; background: string; border: string }> = {
  cyan:   { color: 'var(--accent)',  background: 'rgba(240,168,58,0.1)',   border: '1px solid rgba(240,168,58,0.3)' },
  green:  { color: 'var(--ok)',      background: 'rgba(84,175,97,0.1)',    border: '1px solid rgba(84,175,97,0.3)' },
  amber:  { color: 'var(--accent)',  background: 'rgba(240,168,58,0.1)',   border: '1px solid rgba(240,168,58,0.3)' },
  red:    { color: 'var(--crit)',    background: 'rgba(232,64,64,0.1)',    border: '1px solid rgba(232,64,64,0.3)' },
  purple: { color: '#a78bfa',        background: 'rgba(167,139,250,0.1)', border: '1px solid rgba(167,139,250,0.3)' },
}

function Badge({ children, color = 'cyan' }: { children: ReactNode; color?: string }) {
  const bs = BADGE_STYLES[color] || BADGE_STYLES.cyan
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', padding: '1px 8px', borderRadius: 10, fontSize: 11, fontWeight: 500, color: bs.color, background: bs.background, border: bs.border }}>
      {children}
    </span>
  )
}

// ── Guide content ──────────────────────────────────────────────────────────────

const SECTIONS: Section[] = [
  {
    id: 'getting-started',
    title: 'Getting Started',
    icon: <BookOpen size={15} />,
    subsections: [
      {
        id: 'overview',
        title: 'What is Seraph?',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Seraph is a self-hosted, open-source cybersecurity platform designed for penetration testers, security engineers, and red teamers. It consolidates the most common security workflows — reconnaissance, auditing, exploitation, reporting — into a single interface that runs entirely on your machine.
            </p>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7, marginTop: 12 }}>
              No data leaves your system. No API keys required (except for optional local LLM integration via Ollama or LMStudio). Everything is stored in a local SQLite database.
            </p>
            <Note>Seraph is a wrapper and orchestrator — it requires the underlying tools (nmap, nikto, hashcat, etc.) to be installed on your system. It doesn't bundle them.</Note>
          </>
        ),
      },
      {
        id: 'first-run',
        title: 'First Login & Setup',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              On first launch, Seraph detects that no users exist and shows a setup wizard.
            </p>
            <Steps items={[
              'Start the backend: navigate to seraph/backend and run uvicorn main:app --reload --port 8000',
              'Open the frontend in your browser (usually http://localhost:22123 in dev, or the backend port if built)',
              'You\'ll be redirected to the login page — a "First-Run Setup" card appears automatically',
              'Enter a username and password (minimum 8 characters) — this creates your admin account',
              'You\'re logged in and redirected to the Dashboard',
            ]} />
            <Tip>Your admin account can create additional users with "analyst" or "admin" roles in Settings → Users.</Tip>
          </>
        ),
      },
      {
        id: 'projects',
        title: 'Projects & Targets',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Everything in Seraph is organized under <strong style={{ color: 'var(--fg)' }}>Projects</strong>. A project represents a single engagement, client, or assessment scope.
            </p>
            <Bullets items={[
              <>A project contains one or more <strong style={{ color: 'var(--fg)' }}>Targets</strong> — IP addresses or hostnames</>,
              'All scans, findings, credentials, and OSINT results are linked to a project',
              'Create a new project from the Dashboard using the "New Project" button',
              <>Target types: <Badge>linux_host</Badge> <Badge>windows_host</Badge> <Badge>web_app</Badge> <Badge color="amber">cloud_aws</Badge> <Badge color="purple">network</Badge></>,
            ]} />
            <Tip>If Auto-Probe is enabled (Settings → Auto-Probe), adding a target immediately starts a background recon — whois, nmap, and conditionally nikto/testssl.</Tip>
          </>
        ),
      },
    ],
  },
  {
    id: 'dashboard',
    title: 'Dashboard',
    icon: <LayoutDashboard size={15} />,
    subsections: [
      {
        id: 'dashboard-overview',
        title: 'Overview',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The Dashboard is your at-a-glance view of the platform state. It shows four stat counters (projects, targets, scans, findings), a findings-by-severity donut chart, a 14-day trend chart, quick actions, and recent activity panels.
            </p>
            <Bullets items={[
              'Stat counters animate on load using a count-up effect',
              'The donut chart breaks findings into critical / high / medium / low / info',
              'The 14-day trend panel shows a per-severity sparkline so you can see whether your finding count is growing or shrinking over time',
              <>A <Badge color="green">Auto-Probe running</Badge> banner appears when a background probe is active on a newly added target</>,
              'Recent Scans and Recent Findings panels are compact and scrollable — click "View All →" to open the full list pages',
            ]} />
          </>
        ),
      },
    ],
  },
  {
    id: 'audit',
    title: 'Audit Builder',
    icon: <ShieldCheck size={15} />,
    subsections: [
      {
        id: 'audit-overview',
        title: 'What it does',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The Audit Builder generates and runs compliance-oriented shell scripts based on configurable scan categories (CIS benchmarks, NIST controls, network scanning, web security, etc.).
            </p>
            <Bullets items={[
              'Select a project and target, then toggle the scan categories you want',
              'Each category has sub-options (e.g. port ranges, paths, output verbosity)',
              'Click "Generate Script" to produce a ready-to-run bash script',
              'Run it directly in the browser via the built-in terminal (WebSocket streaming)',
              'Findings are automatically parsed from tool output and stored',
            ]} />
          </>
        ),
      },
      {
        id: 'audit-ssh',
        title: 'Remote Execution via SSH',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Host-based scan categories — <strong style={{ color: 'var(--fg)' }}>Host Hardening (Lynis)</strong>, <strong style={{ color: 'var(--fg)' }}>OpenSCAP</strong>, and <strong style={{ color: 'var(--fg)' }}>Log Monitoring</strong> — need to run on the target machine itself, not locally. Seraph supports this via SSH key authentication.
            </p>
            <Steps items={[
              'Go to Credential Vault and add a credential with type "key"',
              'Set the username to the SSH user on the target (e.g. ubuntu, root)',
              'Paste the full PEM-encoded private key into the secret field',
              'Back in Audit Builder, select a host-based category — an SSH Key Credential picker appears automatically below the target selector',
              'Choose your key credential — the script will execute on the target via SSH instead of locally',
              'Leave it on "Run locally" if you want the old behaviour (runs on the Seraph host)',
            ]} />
            <Tip>The target machine must have your corresponding public key in <Cmd>~/.ssh/authorized_keys</Cmd> and the SSH user needs passwordless sudo for Lynis to run as root.</Tip>
            <Warning>Private keys are written to a temporary file (chmod 600) only for the duration of the SSH call, then deleted immediately. They are never stored on disk permanently.</Warning>
            <Note>Host verification uses <Cmd>StrictHostKeyChecking=accept-new</Cmd> — the host key is trusted on first connect and SSH will refuse to connect if it changes, protecting against MITM.</Note>
          </>
        ),
      },
      {
        id: 'audit-profiles',
        title: 'Scan Profiles & Scheduling',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Save a category configuration as a <strong style={{ color: 'var(--fg)' }}>Profile</strong> for quick reuse. Profiles can also be scheduled to run automatically on a cron expression.
            </p>
            <Steps items={[
              'Configure your scan categories',
              'Click "Save Profile" — give it a name and description',
              'In Settings → Profiles, or in the Audit Builder\'s "Load Profile" section, find your profile',
              'Click the clock icon next to a profile to set a cron schedule (e.g. 0 2 * * * for 2AM daily)',
              'The scheduler runs the profile headlessly and saves results automatically',
            ]} />
            <Block>{`Quick presets:
Daily 2AM    →  0 2 * * *
Weekly Sun   →  0 2 * * 0
Every hour   →  0 * * * *`}</Block>
          </>
        ),
      },
      {
        id: 'ciscat',
        title: 'CIS-CAT Report Import',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Import CIS-CAT benchmark assessment output directly into Seraph as findings. Supported formats: <Cmd>.xml</Cmd> (XCCDF), <Cmd>.json</Cmd> (CIS-CAT JSON), and <Cmd>.csv</Cmd>.
            </p>
            <Steps items={[
              'In Audit Builder, scroll to the "Import CIS-CAT Report" section',
              'Select the project and target to import into',
              'Choose your CIS-CAT output file (.xml / .json / .csv)',
              'Click "Import" — findings are created per failed rule with CIS-CAT metadata',
            ]} />
            <Bullets items={[
              'Each failed rule becomes a Finding with severity "medium"; passed rules become "info" findings',
              'All imported findings are tagged framework="CIS-CAT" and include the rule control_id',
              'A summary card shows pass / fail / not-applicable counts after import',
              'The created Scan is tagged scan_type="ciscat_import" so you can filter it in All Scans',
            ]} />
            <Tip>XCCDF files contain the richest metadata — descriptions and fix text are extracted automatically. For CSV files, columns Rule ID / Title / Result / Severity are expected.</Tip>
          </>
        ),
      },
    ],
  },
  {
    id: 'pentest',
    title: 'Pentest Workbench',
    icon: <Swords size={15} />,
    subsections: [
      {
        id: 'pentest-overview',
        title: 'How it works',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The Pentest Workbench structures engagements by type (external network, web application, internal, cloud AWS) and phase (recon, enumeration, exploitation, post-exploitation, reporting). Each phase exposes the relevant tools for that stage.
            </p>
            <Steps items={[
              'Select engagement type and phase',
              'Pick a tool — a command template appears pre-filled with your target',
              'Customize the command if needed, then click "Run Tool"',
              'Output streams in real time; findings are auto-parsed and saved',
            ]} />
            <Tip>All pentest scan results feed into the Reports page, where you can generate a full narrative report.</Tip>
          </>
        ),
      },
      {
        id: 'pentest-ad',
        title: 'Active Directory Engagements',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Select the <strong style={{ color: 'var(--fg)' }}>Active Directory</strong> engagement type for domain-focused assessments. The workflow walks through five phases using dedicated AD tools.
            </p>
            <Bullets items={[
              <><Badge color="amber">Phase 1 — Recon</Badge> Kerbrute user enumeration against the domain controller</>,
              <><Badge color="amber">Phase 2 — Enumeration</Badge> NetExec (nxc) SMB/LDAP/WinRM enumeration with optional credential spray</>,
              <><Badge color="amber">Phase 3 — Kerberoasting</Badge> impacket-GetUserSPNs — request service tickets for offline hash cracking</>,
              <><Badge color="amber">Phase 4 — AS-REP Roasting</Badge> impacket-GetNPUsers — find accounts with pre-auth disabled</>,
              <><Badge color="red">Phase 5 — Post-Compromise</Badge> impacket-secretsdump / psexec / wmiexec for credential extraction and lateral movement</>,
            ]} />
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7, marginTop: 12 }}>
              Template variables auto-fill from your target: <Cmd>domain</Cmd>, <Cmd>dc_ip</Cmd>, <Cmd>username</Cmd>, <Cmd>password</Cmd>, <Cmd>hash</Cmd>. Edit them inline before running.
            </p>
            <Tip>Cracked Kerberos hashes (TGS-REP / AS-REP) can be sent directly to Password Auditing — select hashcat mode 13100 for TGS-REP or 18200 for AS-REP.</Tip>
          </>
        ),
      },
      {
        id: 'pentest-tools',
        title: 'New Tools (RustScan, Nuclei, Feroxbuster)',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Several high-performance tools have been added to the pentest tool chains and auto-probe:
            </p>
            <Bullets items={[
              <><Cmd>rustscan</Cmd> — Finds all open ports in seconds, then hands off to nmap for service detection. Used in scanning phases as a fast alternative to full nmap sweeps.</>,
              <><Cmd>nuclei</Cmd> — Template-based vulnerability scanner. Runs thousands of community templates against web and network targets. Findings are auto-parsed into the database.</>,
              <><Cmd>feroxbuster</Cmd> — Recursive web directory brute-forcer, faster than gobuster for deep directory trees. Used in web enumeration phases.</>,
              <><Cmd>responder</Cmd> — LLMNR/NBT-NS/mDNS poisoner for internal network engagements. Captures NTLMv2 hashes from broadcast name resolution. Run with: <Cmd>sudo responder -I eth0 -rdwv</Cmd></>,
            ]} />
            <Note>Install these from Settings → Tools. Each has an Install button that runs the correct install command for your system.</Note>
          </>
        ),
      },
    ],
  },
  {
    id: 'osint',
    title: 'OSINT Module',
    icon: <Globe size={15} />,
    subsections: [
      {
        id: 'osint-overview',
        title: 'Gathering intelligence',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The OSINT module runs passive and semi-passive reconnaissance tools against a domain — harvesting emails, subdomains, and IP addresses without directly touching the target.
            </p>
            <Bullets items={[
              <><Cmd>theHarvester</Cmd> — emails, subdomains from search engines and public sources</>,
              <><Cmd>subfinder</Cmd> — passive subdomain enumeration using certificate transparency and APIs</>,
              <><Cmd>amass</Cmd> — comprehensive subdomain mapping (passive mode)</>,
            ]} />
            <Steps items={[
              'Select a project and target — the domain auto-fills from the target hostname',
              'Enable one or more tools and click "Run"',
              'Results stream in the terminal; emails/subdomains/IPs are extracted automatically',
              'Newly discovered subdomains are auto-created as Target records in the project',
              'Discoveries appear in the left panel summary and the Network Map',
            ]} />
          </>
        ),
      },
    ],
  },
  {
    id: 'network',
    title: 'Network Map',
    icon: <Network size={15} />,
    subsections: [
      {
        id: 'network-overview',
        title: 'Topology visualization',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The Network Map builds an interactive force-directed graph of all targets in a project, colored by their highest finding severity. Parent-child relationships between domains and subdomains are detected automatically.
            </p>
            <Bullets items={[
              'Nodes are colored: red (critical) → orange (high) → amber (medium) → green (low) → blue (info)',
              'Click any node to see its details: type, severity, finding count',
              'Use the toolbar to zoom in/out, fit all nodes, or export as PNG',
              'The root "Seraph" diamond node acts as the engagement anchor',
            ]} />
            <Tip>The map updates automatically as you add targets or run OSINT. Run OSINT first to populate subdomains before viewing the map.</Tip>
          </>
        ),
      },
    ],
  },
  {
    id: 'cracking',
    title: 'Password Auditing',
    icon: <Lock size={15} />,
    subsections: [
      {
        id: 'cracking-overview',
        title: 'Auditing hashes',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The Password Auditing module provides a GUI for <Cmd>hashcat</Cmd> and <Cmd>john</Cmd> (John the Ripper). You can paste hashes directly or load them from the Credential Vault.
            </p>
            <Bullets items={[
              <>Select tool: <Badge>hashcat</Badge> (GPU-accelerated) or <Badge color="purple">john</Badge> (CPU, format auto-detect)</>,
              <>Attack modes: <Badge color="green">Wordlist</Badge> <Badge color="amber">Brute-force mask</Badge> <Badge>Hybrid</Badge></>,
              'Hash type selection from a curated list (MD5, NTLM, bcrypt, Kerberos TGS, WPA, etc.)',
              'Wordlist: common system paths are auto-detected (rockyou, seclists, fasttrack)',
              'Command preview updates live as you configure options',
              'Cracked pairs appear in the results table — save each to the Credential Vault with one click',
            ]} />
            <Note>Mask syntax: <Cmd>?l</Cmd> lowercase, <Cmd>?u</Cmd> uppercase, <Cmd>?d</Cmd> digit, <Cmd>?s</Cmd> special, <Cmd>?a</Cmd> any. Example: <Cmd>?u?l?l?l?d?d</Cmd></Note>
          </>
        ),
      },
      {
        id: 'cracking-vault',
        title: 'Loading from Vault',
        content: (
          <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
            Use "Load from Vault" in the left panel to pull hash-type credentials from the Credential Vault into the hash input automatically. Select the project, check the credentials you want, and they're inserted ready to crack.
          </p>
        ),
      },
      {
        id: 'remote-servers',
        title: 'Remote Cracking Servers',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Offload cracking jobs to a remote GPU server over SSH. The cracking script is built locally and executed on the remote host — results stream back over the WebSocket connection and are written to the vault on completion.
            </p>
            <Steps items={[
              'In the REMOTE SERVERS section, click "Manage" to open the server panel',
              'Click "Add Server" — provide name, host/IP, SSH port, SSH user, and remote workdir',
              'Select an SSH private key from the Credential Vault (type=key) — this is required for key-based auth',
              'In the main cracking form, set "Run On" to your server instead of "Local"',
              'Enter the full path to a wordlist already present on the remote server',
              'Submit the job — the bash cracking script runs remotely; output streams in real time',
            ]} />
            <Bullets items={[
              'The remote server needs hashcat or john installed at a standard path',
              'SSH key credentials must be stored in Credential Vault before adding a server',
              'Remote workdir (default /tmp/seraph_crack) is created automatically and cleaned after the job',
              'Results after the === SERAPH_CRACKED_RESULTS === delimiter are parsed and written to vault',
            ]} />
            <Warning>Password-based SSH auth is not supported for remote cracking. You must select a private key credential from the vault.</Warning>
          </>
        ),
      },
    ],
  },
  {
    id: 'c2',
    title: 'C2 Console',
    icon: <Terminal size={15} />,
    subsections: [
      {
        id: 'c2-overview',
        title: 'Command & Control',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The C2 Console integrates with Metasploit Framework via its RPC API. It lets you generate payloads, start listeners, manage active sessions, and interact with sessions — all from the browser.
            </p>
            <Warning>The C2 module requires Metasploit Framework to be running with the msfrpc daemon active. Start it with: <Cmd>msfrpcd -P password -S -a 127.0.0.1</Cmd></Warning>
            <Bullets items={[
              'Payloads tab: select format (exe, elf, psh, python...), payload type, LHOST/LPORT, then download',
              '"Auto-start listener" checkbox fires a matching handler automatically after generating',
              'Listeners tab: view active handlers, start/stop them manually',
              'Sessions tab: all active Meterpreter/shell sessions — click to open an interactive terminal',
              'Loot tab: credentials and files captured from sessions',
            ]} />
          </>
        ),
      },
      {
        id: 'c2-postex',
        title: 'Post-Exploitation Tab',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Every active session has a <strong style={{ color: 'var(--fg)' }}>Post-Ex</strong> tab with automated and guided post-exploitation capabilities. Select a session and click the Post-Ex tab to access them.
            </p>
            <Bullets items={[
              <><strong style={{ color: 'var(--fg)' }}>Auto-Probe</strong> — runs a platform-appropriate recon set (sysinfo, getuid, ipconfig/ifconfig, ps) and stores results as loot</>,
              <><strong style={{ color: 'var(--fg)' }}>Harvest Creds</strong> — runs hashdump + kiwi on Windows Meterpreter, or reads /etc/shadow on Linux. Parsed credentials are saved to the Credential Vault automatically</>,
              <><strong style={{ color: 'var(--fg)' }}>Screenshot</strong> — captures the current desktop of the compromised machine and displays it inline</>,
              <><strong style={{ color: 'var(--fg)' }}>Upgrade Shell</strong> — upgrades a plain shell session to a Meterpreter session with streaming output</>,
            ]} />
            <Tip>Auto-Probe also fires automatically when a new session is created (if enabled in Settings). By the time you open the session, initial recon is already waiting in the Loot tab.</Tip>
          </>
        ),
      },
      {
        id: 'c2-checklist',
        title: 'Post-Ex Checklist',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Each session has a persistent 12-item post-exploitation checklist organized into six categories. Check items off as you complete them — state is saved per session.
            </p>
            <Bullets items={[
              <><Badge color="cyan">Situational Awareness</Badge> — sysinfo, current user, process list, network config</>,
              <><Badge color="amber">Privilege Escalation</Badge> — check admin rights, attempt local privesc</>,
              <><Badge color="red">Credential Access</Badge> — hashdump, Mimikatz/kiwi, /etc/shadow</>,
              <><Badge color="purple">Persistence</Badge> — establish persistence mechanism, document method</>,
              <><Badge color="green">Lateral Movement</Badge> — enumerate network neighbors, identify pivot targets</>,
              <><Badge>Evidence</Badge> — screenshot desktop, export loot to project</>,
            ]} />
            <Note>Use "Reset Checklist" to clear all checkboxes when starting a new engagement phase on the same session.</Note>
          </>
        ),
      },
      {
        id: 'c2-pivoting',
        title: 'Pivot Routes',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The Pivot Routes table lets you manage MSF route entries for tunneling traffic through a compromised host to reach otherwise inaccessible network segments.
            </p>
            <Steps items={[
              'In the Post-Ex tab, scroll to the Pivot Routes section',
              'Enter a subnet (e.g. 10.10.20.0) and netmask (e.g. 255.255.255.0)',
              'Click "Add Route" — Metasploit\'s route add command runs automatically',
              'The route appears in the table; click the trash icon to remove it',
            ]} />
            <Tip>After adding a route, tools like nmap and impacket can reach the internal subnet through the Meterpreter session without additional proxy configuration.</Tip>
          </>
        ),
      },
      {
        id: 'infra-nodes',
        title: 'C2 Node Registry',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The <strong style={{ color: 'var(--fg)' }}>Infrastructure</strong> tab in C2 Console maintains a persistent registry of Metasploit RPC and Sliver C2 server connections. Multiple nodes can be registered and switched between without re-entering credentials each session.
            </p>
            <Steps items={[
              'Open C2 Console → Infrastructure tab',
              'Click "Add Node" to expand the registration form',
              'Enter name, type (MSF or Sliver), host, port, and RPC password',
              'Click "Save" — the node is stored encrypted in the vault',
              'Click "Connect" on a node row to make it the active C2 — existing modules and sessions use this node',
              'Click "Check" to ping the node\'s health without switching the active connection',
            ]} />
            <Bullets items={[
              <>Node <Badge color="green">connected</Badge> badge marks the currently active node — shown in the tab header</>,
              <>Nodes created by EC2 provisioning appear with a <Badge color="amber">ec2</Badge> source badge</>,
              '"Check All" pings every registered node and updates their status simultaneously',
              'Passwords are AES-256-GCM encrypted at rest — never stored in plaintext',
            ]} />
            <Note>MSF nodes connect via the msfrpcd RPC endpoint. Sliver nodes connect via the gRPC multiplayer API. Make sure the correct service is running on the remote host before connecting.</Note>
          </>
        ),
      },
      {
        id: 'infra-ec2',
        title: 'AWS EC2 C2 Provisioning',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Spin up a cloud C2 node on AWS EC2 directly from the Infrastructure tab. Seraph launches an Ubuntu instance, installs and configures Metasploit or Sliver over SSH, then automatically registers it as a C2 node.
            </p>
            <Steps items={[
              'In Infrastructure → AWS EC2 section, click "Cloud Settings"',
              'Enter your AWS Access Key, Secret Key, and default region — click "Save & Verify"',
              'Click "Launch New Instance" to expand the launch form',
              'Choose region, instance type (t3.medium recommended), C2 type, and a name',
              'Click "Launch" — a CloudC2Instance record is created immediately; a provision stream opens',
              'Watch the stream: EC2 starts → SSH becomes available → install script runs → node registered',
              'The new node appears in the C2 Node Registry above when provisioning completes',
            ]} />
            <Bullets items={[
              'A dedicated EC2 key pair is generated per launch and stored encrypted in Credential Vault',
              'A security group is created with the minimum required ports (22, 55553 for MSF, 31337/8443 for Sliver)',
              'Provisioning uses Ubuntu 22.04 LTS — AMI IDs are hardcoded per region for reliability',
              'The RPC password for the installed C2 service is randomly generated and stored encrypted',
              'Provisioning timeout: 5 minutes to reach "running" state + 3 minutes for SSH availability',
            ]} />
            <Warning>AWS charges apply for running EC2 instances. Terminate instances you no longer need from the Instances table using the "Terminate" button — this calls the AWS API and updates the DB record.</Warning>
            <Tip>t3.medium (2 vCPU, 4 GB RAM) is sufficient for most engagements. Use t3.large or c5.large for heavy multi-session work.</Tip>
          </>
        ),
      },
    ],
  },
  {
    id: 'vault',
    title: 'Credential Vault',
    icon: <KeyRound size={15} />,
    subsections: [
      {
        id: 'vault-overview',
        title: 'Managing credentials',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The Credential Vault stores all discovered credentials in one place — whether harvested via C2 loot, brute-forced, found via OSINT, or added manually.
            </p>
            <Bullets items={[
              <>Types: <Badge>password</Badge> <Badge color="amber">hash</Badge> <Badge color="purple">key</Badge> <Badge color="green">token</Badge> <Badge>other</Badge></>,
              <>Sources: <Badge color="green">manual</Badge> <Badge color="red">c2_loot</Badge> <Badge>osint</Badge> <Badge color="amber">brute_force</Badge></>,
              'Secrets are masked by default — click the eye icon to reveal',
              'Filter by type, source, or search by username/host',
              'Credentials saved from password cracking appear here automatically with source "brute_force"',
              <>Credentials of type <Badge color="purple">key</Badge> are used for SSH remote execution in the Audit Builder — paste your PEM private key into the secret field</>,
            ]} />
          </>
        ),
      },
    ],
  },
  {
    id: 'playbooks',
    title: 'Playbooks',
    icon: <Playbooks size={15} />,
    subsections: [
      {
        id: 'playbooks-overview',
        title: 'Automated workflows',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Playbooks are pre-defined, multi-step tool chains that run sequentially against a target. Each step creates its own scan record and auto-parses findings.
            </p>
            <Bullets items={[
              <><Badge color="cyan">Full Recon</Badge> — whois → nmap → subfinder → theHarvester</>,
              <><Badge color="green">Web App Sweep</Badge> — nmap → nikto → gobuster → testssl</>,
              <><Badge color="amber">AD / SMB Audit</Badge> — nmap → enum4linux</>,
              <><Badge color="red">Vuln Assessment</Badge> — nmap (vuln scripts) → searchsploit → sqlmap</>,
              <><Badge color="purple">OSINT Deep Dive</Badge> — whois → theHarvester → amass → subfinder</>,
            ]} />
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7, marginTop: 12 }}>
              Conditional steps only run if their trigger conditions are met — for example, nikto only fires if nmap found an open port 80 or 443.
            </p>
          </>
        ),
      },
      {
        id: 'playbooks-modes',
        title: 'Execution modes',
        content: (
          <>
            <Bullets items={[
              <><strong style={{ color: 'var(--fg)' }}>Auto</strong> — all steps run back-to-back without interruption. Best for unattended use.</>,
              <><strong style={{ color: 'var(--fg)' }}>Step-through</strong> — pauses after each step and waits for you to click "Continue". Use this to review output before proceeding.</>,
            ]} />
            <Steps items={[
              'Open the Library tab and click "Run Playbook"',
              'Select project, target, and execution mode',
              'Click "Start Run" — you\'re taken to the Active Run view automatically',
              'Watch step progress in the left panel; full output streams in the terminal on the right',
              'In step-through mode, a "Continue" card appears when paused — review output then click Continue',
              'Completed runs appear in Run History with per-step findings counts',
            ]} />
          </>
        ),
      },
      {
        id: 'playbooks-builder',
        title: 'Custom Playbook Builder',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Build your own multi-step playbooks from scratch using the <strong style={{ color: 'var(--fg)' }}>Builder</strong> tab. Custom playbooks are stored in the database and behave exactly like built-ins.
            </p>
            <Steps items={[
              'Open Playbooks → Builder tab',
              'Enter a name and description for your playbook',
              'Add steps: each step has a name, scan type, and command. Use {target} as a placeholder for the target hostname/IP',
              'Optionally search for MITRE ATT&CK techniques to tag against the playbook (see below)',
              'Click "Save Playbook" — it appears in the Library tab immediately',
              'Custom playbooks can be edited or deleted at any time from the Library detail view',
            ]} />
            <Note>The <Cmd>{'{target}'}</Cmd> placeholder is replaced with the target's hostname or IP when a run starts. Other available placeholders: <Cmd>{'{domain}'}</Cmd>, <Cmd>{'{ports}'}</Cmd>.</Note>
          </>
        ),
      },
      {
        id: 'playbooks-mitre',
        title: 'MITRE ATT&CK Technique Tagging',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Tag playbooks with MITRE ATT&CK technique IDs to document which techniques each playbook exercises. Tags are displayed as amber <Badge color="amber">T1046</Badge> chips and link to the official ATT&CK technique page.
            </p>
            <Steps items={[
              'In the Builder tab, type a technique name or T-ID into the "Search techniques…" field',
              'Results appear in a dropdown with T-ID, name, and tactic — click any result to add it',
              'Added techniques show as amber chips below the search field — click × to remove',
              'Tags are saved with the playbook and appear on the detail view in the Library tab',
              'Clicking a T-ID chip opens the official attack.mitre.org technique page in a new tab',
            ]} />
            <Tip>Tag playbooks with the techniques they're designed to detect or test. For example, tag a Kerberoasting playbook with T1558.003 to make the intent explicit in your report.</Tip>
          </>
        ),
      },
    ],
  },
  {
    id: 'ai-operator',
    title: 'AI Operator',
    icon: <Bot size={15} />,
    subsections: [
      {
        id: 'ai-operator-overview',
        title: 'What it does',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The <strong style={{ color: 'var(--fg)' }}>AI Operator</strong> is a supervised AI agent that drives a penetration test step-by-step. It plans the next action, proposes a command, waits for your approval, runs it, reads the output, and iterates — you stay in control of every tool execution.
            </p>
            <Bullets items={[
              'Three modes: Attack (red team), Recon (enumeration only), Audit (compliance-oriented)',
              'Supports tool calling — models that expose a tools API get structured JSON responses; others fall back to JSON text parsing',
              'Every proposed command shows the tool, the exact command string, and the AI\'s rationale before you approve',
              'Confirmed attack steps are automatically added to the Attack Path graph',
              'Sessions persist across navigation — leave and return without losing state',
              'The MITRE ATT&CK index is available as a built-in tool the AI can call to look up technique IDs and detection hints',
            ]} />
            <Warning>The AI Operator requires a model that supports tool/function calling. Check the model picker — only compatible models are shown. For local Ollama, models like llama3, mistral, and qwen2.5 support tools.</Warning>
          </>
        ),
      },
      {
        id: 'ai-operator-modes',
        title: 'Modes',
        content: (
          <>
            <Bullets items={[
              <><Badge color="red">Attack</Badge> — Full red team mode. The AI aims to compromise the target, escalate privileges, and map attack paths. Exploitation and lateral movement tools are enabled.</>,
              <><Badge color="cyan">Recon</Badge> — Enumeration only. The AI maps the attack surface (ports, services, subdomains) without attempting exploitation or credential brute-force.</>,
              <><Badge color="amber">Audit</Badge> — Compliance-oriented. The AI identifies and documents vulnerabilities and misconfigurations by severity — without exploiting them. Outputs remediation recommendations.</>,
            ]} />
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7, marginTop: 12 }}>
              Each mode ships with a default set of enabled tools and a pre-written system prompt. You can toggle tools on/off in the left panel and edit the system prompt before starting a session.
            </p>
            <Tip>Prior reconnaissance already in the database (from Auto-Probe or Pentest Workbench scans) is injected into the system prompt as ground truth — the AI won't re-run tools that have already run.</Tip>
          </>
        ),
      },
      {
        id: 'ai-operator-session',
        title: 'Running a session',
        content: (
          <>
            <Steps items={[
              'Select a project and target from the left panel dropdowns',
              'Choose an operator mode (Attack / Recon / Audit)',
              'Select a model — only tool-capable models appear in the list',
              'Toggle which tools the AI is allowed to use (each tool has a description and category)',
              'Optionally review and edit the system prompt that defines the AI\'s persona and rules',
              'Click "Start Session" — the AI sends its first analysis and proposes an action',
              'Review the proposed command and rationale. Click "Approve" to run it, or "Skip" to pass',
              'Tool output streams in and the AI reads it, then plans the next step automatically',
              'The session ends when the AI returns next_action: null, or you stop it manually',
            ]} />
            <Note>Each session step appears as a card showing: the tool used, the command, the AI's rationale, and the run result. T-IDs in AI output are rendered as amber links to attack.mitre.org.</Note>
          </>
        ),
      },
      {
        id: 'ai-operator-attack-tool',
        title: 'ATT&CK lookup tool',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The AI Operator has access to a built-in <strong style={{ color: 'var(--fg)' }}>search_attack_techniques</strong> tool that queries the local MITRE ATT&CK knowledge base. The AI calls this automatically when it needs technique context — for example, to look up detection methods before proposing a command.
            </p>
            <Bullets items={[
              'No internet required — searches the local SQLite FTS5 index synced from the ATT&CK STIX bundle',
              'Returns technique ID, name, tactic, description excerpt, and detection hints',
              'T-IDs referenced by the AI in chat messages are rendered as clickable amber chips',
              'The MITRE ATT&CK index is synced on startup (auto-downloads if empty) and can be manually refreshed in Settings → AI',
            ]} />
          </>
        ),
      },
    ],
  },
  {
    id: 'command-library',
    title: 'Command Library',
    icon: <Library size={15} />,
    subsections: [
      {
        id: 'command-library-overview',
        title: 'Commands tab',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The Command Library is a searchable reference of pre-built command templates for common penetration testing tasks. It has two tabs: <strong style={{ color: 'var(--fg)' }}>Commands</strong> and <strong style={{ color: 'var(--fg)' }}>ATT&CK Techniques</strong>.
            </p>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7, marginTop: 8 }}>
              The Commands tab contains {67} templates organized by category, each with a name, description, the command, and optional variables. Every template is tagged with one or more MITRE ATT&CK T-IDs displayed as amber chips.
            </p>
            <Bullets items={[
              'Search by name, description, category, or T-ID — all fields are searched simultaneously',
              'Filter by category using the pill buttons at the top',
              'Expand any card to see the full command, variables, and usage notes',
              'Copy the command to clipboard with one click',
              'T-ID chips on each card link directly to the ATT&CK technique page',
            ]} />
            <Tip>Search by T-ID directly — type "T1046" to find all templates tagged with Network Service Discovery, or "T1110" to find all brute-force templates.</Tip>
          </>
        ),
      },
      {
        id: 'command-library-techniques',
        title: 'ATT&CK Techniques tab',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The <strong style={{ color: 'var(--fg)' }}>ATT&CK Techniques</strong> tab lets you browse all 697 techniques from the MITRE ATT&CK Enterprise matrix, paginated in a card grid.
            </p>
            <Bullets items={[
              'Filter by tactic using the pill buttons (Reconnaissance, Initial Access, Execution, Persistence, etc.)',
              'Each card shows the T-ID, technique name, tactic, and a description excerpt',
              'Click "Generate Command(s)" on any card to use AI to create command templates for that technique',
              'Generated commands can be saved to the Commands tab for future use',
            ]} />
            <Note>The ATT&CK Techniques tab requires the local ATT&CK index to be populated. It syncs automatically on startup. If empty, go to Settings → AI → ATT&CK Knowledge Base and click Sync.</Note>
          </>
        ),
      },
      {
        id: 'command-library-generate',
        title: 'Generate Command(s) with AI',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The <strong style={{ color: 'var(--fg)' }}>Generate Command(s)</strong> button on ATT&CK technique cards sends a structured prompt to an LLM asking it to produce 1–3 practical, copy-pasteable command templates for that technique.
            </p>
            <Steps items={[
              'Select a model from the model picker at the top of the ATT&CK Techniques tab',
              'Browse or search for a technique, then click "Generate Command(s)" on its card',
              'The AI produces 1–3 commands — each appears as a card with name, command, and description',
              'Click "Save to Library" on any generated command to add it to the Commands tab',
            ]} />
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7, marginTop: 8 }}>
              The model picker offers two routing options:
            </p>
            <Bullets items={[
              <><Badge color="cyan">[Local] model-name</Badge> — calls your laptop's Ollama directly (uses Electron's ollamaGetSettings to find the endpoint). Fastest for fully offline use.</>,
              <><Badge color="purple">[Server] model-name</Badge> — routes through the Seraph backend's /ai/chat endpoint, using the server's configured Ollama or LMStudio instance.</>,
            ]} />
            <Tip>Use a Local model for quick generation when offline, and a Server model when running Seraph on a remote machine with a GPU.</Tip>
          </>
        ),
      },
    ],
  },
  {
    id: 'scratchpad',
    title: 'Scratchpad',
    icon: <StickyNote size={15} />,
    subsections: [
      {
        id: 'scratchpad-overview',
        title: 'Per-project notes',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The Scratchpad is a per-project Markdown note-taking space. Use it to record observations, draft findings, paste raw tool output for later review, or keep a running log of your engagement.
            </p>
            <Bullets items={[
              'Notes are saved per-project — switching projects loads that project\'s scratchpad',
              'Supports full Markdown: headings, bold, italic, code blocks, tables, bullet lists',
              'Toggle between Edit and Preview modes using the buttons in the toolbar',
              'Auto-saves 1 second after you stop typing — no manual save needed',
              'Save status is shown in the toolbar: Saved / Saving… / Unsaved',
            ]} />
            <Note>Scratchpad content is stored in the database alongside your project data. It is included when you export project data and cleared when you delete the project.</Note>
          </>
        ),
      },
    ],
  },
  {
    id: 'autoprobe',
    title: 'Auto-Probe',
    icon: <Zap size={15} />,
    subsections: [
      {
        id: 'autoprobe-overview',
        title: 'Background recon on target creation',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Auto-Probe fires automatically when you add a new target. It runs lightweight recon tools in the background so by the time you open the target, there's already data waiting.
            </p>
            <Bullets items={[
              <><Cmd>whois</Cmd> — always runs (if installed)</>,
              <><Cmd>nmap</Cmd> — always runs (if installed)</>,
              <><Cmd>nikto</Cmd> — only if nmap found port 80, 443, 8080, or 8443 open</>,
              <><Cmd>testssl</Cmd> — only if nmap found port 443 or 8443 open</>,
            ]} />
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7, marginTop: 8 }}>
              Enable and configure it in <strong style={{ color: 'var(--fg)' }}>Settings → Auto-Probe</strong>. You can choose which tools run and set the intensity (Quick / Standard / Deep).
            </p>
            <Tip>While a probe is running, the Dashboard shows a pulsing green "Auto-Probe running" banner. Each tool's scan appears in the target's scan history with a ⚡ badge.</Tip>
          </>
        ),
      },
    ],
  },
  {
    id: 'reports',
    title: 'Reports',
    icon: <FileText size={15} />,
    subsections: [
      {
        id: 'reports-overview',
        title: 'Generating reports',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The Reports page aggregates all findings from a project and lets you export them in multiple formats or generate an AI-written narrative.
            </p>
            <Bullets items={[
              'Select a project from the dropdown — severity counts update automatically',
              '"Preview" generates a Markdown preview of the full report',
              '"HTML" downloads a styled HTML report file',
              '"Markdown" downloads a plain .md file',
              '"PDF" renders the HTML report to PDF via WeasyPrint (must be installed)',
            ]} />
          </>
        ),
      },
      {
        id: 'reports-templates',
        title: 'Report templates',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Choose between two report templates using the template picker at the top of the Reports page. The template controls which findings are shown in the preview and downloads.
            </p>
            <Bullets items={[
              <><Badge color="cyan">Technical</Badge> — all findings across all severities. Includes full technical detail, evidence, and remediation steps. Aimed at the security team.</>,
              <><Badge color="purple">Executive</Badge> — critical and high findings only. Written for stakeholders who need to understand business risk without deep technical detail. Tab counters show <Cmd>n/total</Cmd> to indicate filtering is active.</>,
            ]} />
            <Tip>Switch to Executive template before generating an AI Narrative — the LLM will receive only the high-impact findings and produce a tighter, business-focused summary.</Tip>
          </>
        ),
      },
      {
        id: 'reports-ai',
        title: 'AI Narrative',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Seraph can generate a written narrative for your report using a local LLM via Ollama or LMStudio. No internet connection or API key required.
            </p>
            <Steps items={[
              'Go to Settings → AI and configure your LLM endpoint (Ollama: port 11434, LMStudio: port 1234)',
              'Click "Test Connection" to verify — available models populate automatically',
              'Select a model and save',
              'Back in Reports, choose "Executive" or "Technical" style from the dropdown',
              'Click "AI Narrative" — the narrative appears in the AI Narrative tab',
              'Copy it or incorporate it into your exported report',
            ]} />
            <Note>Executive narratives are written in plain language for non-technical stakeholders. Technical narratives go deep on vulnerabilities and exploitation paths.</Note>
          </>
        ),
      },
    ],
  },
  {
    id: 'findings',
    title: 'Findings & CVEs',
    icon: <AlertTriangle size={15} />,
    subsections: [
      {
        id: 'findings-overview',
        title: 'Working with findings',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Findings are automatically parsed from tool output. The <strong style={{ color: 'var(--fg)' }}>All Findings</strong> page (Dashboard → "View All →" or sidebar) gives you a searchable, filterable list of every finding across all projects.
            </p>
            <Bullets items={[
              'Expand any row to see full description, remediation notes, and tags',
              'If a finding title contains a CVE ID (e.g. CVE-2021-44228), CVE enrichment fetches the CVSS score and description from NVD',
              'CVSS scores display colored badges: ≥9.0 red, ≥7.0 orange, ≥4.0 yellow, lower green',
            ]} />
          </>
        ),
      },
      {
        id: 'findings-status',
        title: 'Status workflow',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Each finding has a status that tracks its remediation progress. Click the status badge on any row to change it inline — no separate form needed.
            </p>
            <Bullets items={[
              <><Badge color="red">open</Badge> — newly discovered, not yet addressed</>,
              <><Badge color="amber">in-review</Badge> — under investigation or being reproduced</>,
              <><Badge color="green">remediated</Badge> — fix has been applied and verified</>,
              <><Badge>accepted</Badge> — risk formally accepted by the client or stakeholder</>,
            ]} />
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7, marginTop: 12 }}>
              The status filter chips at the top of All Findings let you focus on a specific stage — useful for tracking which findings still need attention.
            </p>
          </>
        ),
      },
      {
        id: 'findings-tags',
        title: 'Tags',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Tags let you add freeform labels to findings for grouping, filtering, or tracking context that doesn't fit into severity or status.
            </p>
            <Steps items={[
              'Expand a finding row in All Findings',
              'Type a tag name in the "add tag…" field at the bottom and press Enter',
              'The tag is saved immediately and appears as a pill',
              'Click the × on any tag pill to remove it',
              'Use the "Filter by tag" input at the top of All Findings to show only findings with a specific tag',
            ]} />
            <Tip>Use tags like <Cmd>needs-retest</Cmd>, <Cmd>client-confirmed</Cmd>, or <Cmd>wontfix</Cmd> to capture context that status alone can't express.</Tip>
          </>
        ),
      },
      {
        id: 'findings-export',
        title: 'Exporting findings',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The <strong style={{ color: 'var(--fg)' }}>Export</strong> button on All Findings downloads the current filtered set — whatever severity, status, tag, and search filters are active.
            </p>
            <Bullets items={[
              <><Badge color="green">CSV</Badge> — comma-separated, opens in Excel / Google Sheets. Columns: severity, status, title, target, project, CVE ID, CVSS score, tags, date, description</>,
              <><Badge>JSON</Badge> — full structured data, one object per finding</>,
            ]} />
            <Note>The export always reflects the current filter. To export all findings, clear all filters first.</Note>
          </>
        ),
      },
    ],
  },
  {
    id: 'scans',
    title: 'All Scans',
    icon: <GitCompare size={15} />,
    subsections: [
      {
        id: 'scans-overview',
        title: 'Viewing all scans',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The <strong style={{ color: 'var(--fg)' }}>All Scans</strong> page (Dashboard → Recent Scans → "View All →") shows every scan across all projects with status, finding count, scan type, and date. Filter by status or search by target, project, or scan type.
            </p>
            <Bullets items={[
              <><Badge color="green">completed</Badge> <Badge color="cyan">running</Badge> <Badge>pending</Badge> <Badge color="red">failed</Badge> — filter chips narrow the list</>,
              'Finding count shown per row — amber color indicates findings were found',
              '⚡ badge marks auto-probe scans',
            ]} />
          </>
        ),
      },
      {
        id: 'scans-diff',
        title: 'Scan Diff',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The <strong style={{ color: 'var(--fg)' }}>Scan Diff</strong> page compares two scans on the same target to identify new, resolved, and unchanged findings. Use it after a remediation cycle to verify fixes and catch regressions.
            </p>
            <Steps items={[
              'Navigate to Scan Diff from the sidebar',
              'Select a project (uses the global project selector)',
              'Pick a target from the target dropdown — only targets with at least two completed scans can be diffed',
              'Select Scan A (the baseline) and Scan B (the comparison) from the scan dropdowns',
              'Click "Run Diff" — three columns appear: New, Resolved, and Unchanged findings',
              'Expand any finding row to see its full description and remediation note',
            ]} />
            <Bullets items={[
              <><Badge color="red">New</Badge> — findings present in Scan B but not in Scan A (regressions or newly discovered issues)</>,
              <><Badge color="green">Resolved</Badge> — findings present in Scan A that are gone in Scan B (successfully fixed)</>,
              <><Badge>Unchanged</Badge> — findings that persist across both scans</>,
            ]} />
            <Tip>Diff works best when comparing two runs of the same scan type against the same target. Matching is done by finding title + severity.</Tip>
          </>
        ),
      },
    ],
  },
  {
    id: 'notifications',
    title: 'Notifications',
    icon: <Bell size={15} />,
    subsections: [
      {
        id: 'notifications-overview',
        title: 'Bell & notification panel',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The bell icon in the sidebar footer shows a count of unread notifications. Seraph generates notifications automatically for key background events.
            </p>
            <Bullets items={[
              'Scheduled scan completed — includes how many findings were parsed',
              'Scheduled scan failed — shows the error reason',
              'Red badge on the bell indicates unread count',
              'Click the bell to open the notification panel',
            ]} />
            <Steps items={[
              'Click the bell icon (sidebar footer, bottom-right of sidebar)',
              'The panel lists all notifications, newest first, with type icon and timestamp',
              'Click a notification to mark it read',
              '"Mark all read" clears the badge in one click',
              '"Delete read" removes all already-read notifications to keep the list tidy',
            ]} />
            <Note>Notifications are polled every 30 seconds. Background scan completions appear within one poll cycle of finishing.</Note>
          </>
        ),
      },
    ],
  },
  {
    id: 'command-palette',
    title: 'Command Palette',
    icon: <Command size={15} />,
    subsections: [
      {
        id: 'palette-overview',
        title: 'Keyboard navigation',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Press <Cmd>?</Cmd> anywhere in the app (outside a text field) to open the command palette — a searchable menu of all pages and actions.
            </p>
            <Bullets items={[
              <>Type to filter — results narrow instantly across all navigation destinations</>,
              <><Cmd>↑</Cmd> / <Cmd>↓</Cmd> arrow keys move the cursor through results</>,
              <><Cmd>Enter</Cmd> navigates to the highlighted item</>,
              <><Cmd>Esc</Cmd> closes the palette without navigating</>,
              'Results are grouped by section (Getting Started, Audit, Pentest, etc.)',
              'Click any result with the mouse as an alternative to keyboard navigation',
            ]} />
            <Tip>The palette is the fastest way to jump between sections. Press <Cmd>?</Cmd>, type the first letters of where you want to go, then hit <Cmd>Enter</Cmd>.</Tip>
          </>
        ),
      },
    ],
  },
  {
    id: 'settings',
    title: 'Settings',
    icon: <Settings size={15} />,
    subsections: [
      {
        id: 'settings-tools',
        title: 'Tools',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The Tools tab detects which security tools are installed on startup and shows their paths and versions. Missing tools show an install command and an <strong style={{ color: 'var(--fg)' }}>Install</strong> button.
            </p>
            <Bullets items={[
              'Green checkmark — tool detected, path and version shown',
              'Red X — tool not found; install command and Install button shown',
              <>Click <strong style={{ color: 'var(--fg)' }}>Install</strong> on any missing tool to run the install command in a live terminal — no copy/paste needed</>,
              'Tools install via the most appropriate method: apt, pip3, go install, snap, or direct binary download',
              <>Click <strong style={{ color: 'var(--fg)' }}>Refresh</strong> after installing to re-detect all tools</>,
            ]} />
            <Tip>Use the "Quick Install" banner to copy a single command that installs all missing apt/pip-compatible tools at once. For tools requiring cargo, go, or snap, use the per-tool Install button.</Tip>
          </>
        ),
      },
      {
        id: 'settings-users',
        title: 'Users',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>Admins can manage platform users from the Users tab.</p>
            <Bullets items={[
              'Change your own password at any time',
              'Create additional users with "analyst" or "admin" roles (admin only)',
              'Delete users — you cannot delete your own account',
              <>Roles: <Badge color="amber">admin</Badge> full access including user management · <Badge>analyst</Badge> all features except user management</>,
            ]} />
          </>
        ),
      },
      {
        id: 'settings-ai',
        title: 'AI Configuration',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Configure your local LLM endpoint for AI-powered features: AI Operator, AI Narrative reports, vulnerability remediation suggestions, and log triage.
            </p>
            <Bullets items={[
              <>Supports any OpenAI-compatible endpoint — works with <strong style={{ color: 'var(--fg)' }}>Ollama</strong> and <strong style={{ color: 'var(--fg)' }}>LMStudio</strong></>,
              'Provider presets auto-fill the endpoint URL',
              '"Test Connection" fetches available models and populates the model dropdown',
              'Settings are stored server-side — persist across restarts',
            ]} />
            <Block>{`Ollama default:   http://localhost:11434
LMStudio default: http://localhost:1234`}</Block>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7, marginTop: 8 }}>
              <strong style={{ color: 'var(--fg)' }}>Advanced LLM parameters</strong> (optional — leave blank to use model defaults):
            </p>
            <Bullets items={[
              <><Cmd>Temperature</Cmd> — controls response randomness (0.0 = deterministic, 1.0+ = creative). Lower values (0.2–0.4) give more consistent pentest output.</>,
              <><Cmd>Top-P / Top-K</Cmd> — nucleus and top-k sampling. Leave blank unless you have a specific reason to override.</>,
              <><Cmd>Min-P</Cmd> — minimum probability filter, useful with Ollama models that support it.</>,
              <><Cmd>Repetition Penalty</Cmd> — penalizes repeated tokens. Useful if the model tends to loop.</>,
              <><Cmd>Timeout</Cmd> — seconds to wait for an LLM response before failing. Increase for slow hardware or large models.</>,
            ]} />
          </>
        ),
      },
      {
        id: 'settings-attack',
        title: 'ATT&CK Knowledge Base',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Seraph maintains a local FTS5 full-text search index of the entire MITRE ATT&CK Enterprise matrix. This index powers the AI Operator's technique lookup tool, T-ID chips in the Command Library, and RAG context injection in the AI chat.
            </p>
            <Bullets items={[
              'Downloaded from the official MITRE CTI STIX bundle on first startup — no account or API key needed',
              'Stat cards show total techniques indexed and the last sync timestamp',
              '"Sync" re-downloads and rebuilds the index from the latest STIX bundle',
              '"Refresh" re-fetches the status without syncing',
              'Index contains: T-ID, technique name, tactic(s), description, detection hints, data sources',
            ]} />
            <Note>The ATT&CK sync downloads the full STIX bundle (~15 MB) and processes ~700 techniques. It runs in the background — the app remains usable during sync.</Note>
          </>
        ),
      },
      {
        id: 'settings-ptes',
        title: 'PTES Knowledge Base',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              The <strong style={{ color: 'var(--fg)' }}>Penetration Testing Execution Standard (PTES)</strong> knowledge base fetches methodology content from pentest-standard.org and indexes it in a local FTS5 table. This content is injected into AI Operator and chat sessions to ground AI responses in structured pentest methodology.
            </p>
            <Bullets items={[
              'Covers all 8 PTES phases: Pre-Engagement, Intelligence Gathering, Threat Modeling, Vulnerability Analysis, Exploitation, Post-Exploitation, Reporting, and Technical Guidelines',
              'Each phase is split into sections and stored as searchable plain text',
              '"Sync" re-downloads all phases from the MediaWiki API and rebuilds the index',
              'Stat card shows total sections indexed and last sync time',
            ]} />
            <Tip>PTES context is automatically appended to the AI Operator's system prompt (up to 2 relevant sections per query). This helps the AI follow standard pentest methodology steps rather than free-forming its approach.</Tip>
          </>
        ),
      },
      {
        id: 'settings-nessus',
        title: 'Nessus / Tenable.io Integration',
        content: (
          <>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7 }}>
              Connect Seraph to a self-hosted Nessus instance or Tenable.io to import scan findings. Settings → Nessus stores the credentials; importing is done from the <strong style={{ color: 'var(--fg)' }}>All Findings</strong> page.
            </p>
            <Steps items={[
              'Go to Settings → Nessus',
              'For self-hosted Nessus: enter the host IP/hostname, port (default 8834), username, and password',
              'For Tenable.io: type api.tenable.com as the host — the form switches to API key fields automatically',
              'Click "Save", then "Test Connection" to verify',
              'Navigate to All Findings → "Import from Nessus" button (top right)',
              'A modal lists all scans from your Nessus instance — select a project and click "Import" on any scan',
            ]} />
            <Bullets items={[
              'Auth is auto-detected: self-hosted uses session token (POST /session); Tenable.io uses X-ApiKeys header',
              'Each Nessus host becomes a Target in the selected project (created if it doesn\'t exist)',
              'Each vulnerability becomes a Finding with severity mapped from Nessus\'s 0–4 scale',
              'All imported findings are tagged framework="Nessus" with the plugin_id as control_id',
              'Passwords are stored encrypted in AppSettings — never in plaintext',
            ]} />
            <Note>For self-hosted Nessus with a self-signed certificate, disable "Verify SSL" in the settings form. Tenable.io always uses valid TLS.</Note>
            <Tip>Re-importing a scan from the same Nessus instance does not duplicate Targets — existing targets with matching hostnames are reused.</Tip>
          </>
        ),
      },
    ],
  },
  {
    id: 'agents',
    title: 'Agents',
    icon: <Cpu size={15} />,
    subsections: [
      {
        id: 'agents-overview',
        title: 'What agents are',
        content: (
          <>
            <p style={{ margin: '0 0 12px', fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.6 }}>
              By default every scan runs on the machine hosting the Seraph backend. <strong style={{ color: 'var(--fg)' }}>Agents</strong> let you run those same scans from a different host — an EC2 instance inside a target VPC, a VPS in a foreign ASN, a Raspberry Pi on a client's internal network, or any other machine you control.
            </p>
            <p style={{ margin: '0 0 12px', fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.6 }}>
              The model is a lightweight pull-based beacon: the agent process on the remote host polls Seraph every 60 seconds asking for pending jobs. When you dispatch a scan, the agent picks it up, executes it locally, and ships results back automatically.
            </p>
            <Bullets items={[
              'No inbound firewall rules needed on the remote host — the agent initiates all connections outbound',
              'Results (findings, scan output) are ingested into the project exactly like local scans',
              'Multiple agents can be registered simultaneously for different network vantage points',
              'Each agent authenticates via a unique bearer token generated at creation time',
            ]} />
            <Note>If all your targets are directly reachable from the Seraph server you don't need agents at all — they are only useful when you need a different network origin for your scans.</Note>
          </>
        ),
      },
      {
        id: 'agents-deploy',
        title: 'Deploying an agent',
        content: (
          <>
            <Steps items={[
              'Open Infrastructure Agents from the left nav',
              'Click "New Agent" — give it a name and optionally link it to an existing target',
              'Click "Deploy" on the new agent row to open the install instructions',
              'Copy the one-liner install command and run it as root on the remote host',
              'The installer sets up a systemd service — within 60 seconds the agent row turns Online',
            ]} />
            <Tip>The install URL uses a short-code so you don't need to paste a long token into a terminal. The same page shows an uninstall command to cleanly remove the service later.</Tip>
            <Note>The remote host must be able to reach the Seraph backend URL over the network. If you are using Tailscale, any machine on your Tailscale network can run an agent without exposing the backend to the public internet.</Note>
          </>
        ),
      },
      {
        id: 'agents-jobs',
        title: 'Dispatching scan jobs',
        content: (
          <>
            <p style={{ margin: '0 0 12px', fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.6 }}>
              Once an agent is online it appears as an available executor in scan dispatch flows. Select the agent instead of running locally and Seraph queues the job for the next poll cycle.
            </p>
            <Bullets items={[
              <>Job status progresses: <Badge color="amber">pending</Badge> → <Badge color="cyan">running</Badge> → <Badge color="green">completed</Badge> or <Badge color="red">failed</Badge></>,
              'Output and findings are returned automatically when the job completes',
              'Click any job row in the agent detail panel to expand its full terminal output',
              'Failed jobs retain their output — check it to diagnose tool errors on the remote host',
            ]} />
          </>
        ),
      },
    ],
  },
  {
    id: 'attack-paths',
    title: 'Attack Paths',
    icon: <GitBranch size={15} />,
    subsections: [
      {
        id: 'attack-paths-overview',
        title: 'What the graph shows',
        content: (
          <>
            <p style={{ margin: '0 0 12px', fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.6 }}>
              Attack Paths visualises the relationships between your attacker node, targets, active C2 sessions, and discovered findings as a directed graph. It answers the question: given what you know and what you've compromised, what are the viable paths to your objective?
            </p>
            <Bullets items={[
              <>Edges are coloured by type: <Badge color="red">C2 implant</Badge> (active session), <Badge color="amber">exploit</Badge> (finding-backed), <Badge color="purple">cred-reuse</Badge> (lateral movement via credential)</>,
              'Each edge shows the tool or username that enables the hop',
              'Nodes show compromised status and finding severity at a glance',
              'Sort chains by impact, complexity, or shortest path using the toolbar',
            ]} />
          </>
        ),
      },
      {
        id: 'attack-paths-chains',
        title: 'Attack chains',
        content: (
          <>
            <p style={{ margin: '0 0 12px', fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.6 }}>
              Below the graph, Seraph derives concrete attack chains — ordered sequences of steps from your current foothold to a target. Each chain includes the tool to use, CVSS impact score, and a copy-ready command for each step.
            </p>
            <Bullets items={[
              'Click a chain to expand its step-by-step breakdown',
              'Each step shows the specific finding or technique that enables it',
              'Commands are pre-populated with target IPs from your project data',
              'Use the sort controls to prioritise high-impact or shortest chains first',
            ]} />
            <Tip>Attack chains update as you add findings and establish new sessions — check this page after each exploitation phase to see what new paths have opened up.</Tip>
          </>
        ),
      },
    ],
  },
  {
    id: 'cve-watch',
    title: 'CVE Watch',
    icon: <Eye size={15} />,
    subsections: [
      {
        id: 'cve-watch-overview',
        title: 'Monitoring services for new CVEs',
        content: (
          <>
            <p style={{ margin: '0 0 12px', fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.6 }}>
              CVE Watch tracks a list of services and software versions you care about and surfaces new CVEs as they are published. It is primarily useful for ongoing monitoring engagements where you want to know as soon as a critical CVE drops for software running on your targets.
            </p>
            <Bullets items={[
              'Add a watched service by entering a search term (e.g. "ProFTPD 1.3.5", "Apache 2.4.51")',
              'Link the watch entry to a target in your project for context',
              'Seraph periodically queries the CVE feed and stores matched CVE IDs against each watch entry',
              <><Badge color="red">KEV</Badge> badge marks CVEs on CISA's Known Exploited Vulnerabilities catalogue — prioritise these</>,
              'CVSS score and asset match count are shown per CVE row',
            ]} />
            <Note>CVE Watch checks runs on a background schedule. New entries may take up to the next scheduled interval before results populate.</Note>
          </>
        ),
      },
    ],
  },
  {
    id: 'listeners',
    title: 'Listeners',
    icon: <Radio size={15} />,
    subsections: [
      {
        id: 'listeners-overview',
        title: 'Automated event listeners',
        content: (
          <>
            <p style={{ margin: '0 0 12px', fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.6 }}>
              Listeners are rules that trigger automated actions based on time or observed conditions. They run in the background independent of the UI, making them useful for continuous monitoring and unattended engagement automation.
            </p>
            <Bullets items={[
              <><Badge color="amber">Scheduled</Badge> — run a scan category against a target on a cron schedule (e.g. nightly recon)</>,
              <><Badge color="cyan">Threshold</Badge> — fire when the finding count for a project crosses a defined number</>,
              <><Badge color="green">Health Check</Badge> — ping a target on a schedule and record up/down state</>,
              <><Badge color="purple">Agent Audit</Badge> — alert when a registered agent stops checking in (goes offline)</>,
            ]} />
          </>
        ),
      },
      {
        id: 'listeners-create',
        title: 'Creating a listener',
        content: (
          <>
            <Steps items={[
              'Click "New Listener" and choose a type from the dropdown',
              'Fill in the required fields — project, target (if applicable), and type-specific config',
              'For Scheduled listeners: enter a cron expression and select the scan categories to run',
              'For Threshold listeners: enter the finding count that should trigger the alert',
              'Click Save — the listener starts in Running state immediately',
            ]} />
            <Bullets items={[
              'Pause a listener temporarily without deleting it using the status toggle',
              'The event log under each listener shows every time it fired, with outcome and detail message',
              'Listeners survive backend restarts — they are persisted in the database and rescheduled on startup',
            ]} />
            <Tip>Use a nightly Scheduled listener on your most critical targets to catch configuration drift between active engagement phases.</Tip>
          </>
        ),
      },
    ],
  },
  {
    id: 'log-analysis',
    title: 'Log Analysis',
    icon: <FileSearch size={15} />,
    subsections: [
      {
        id: 'log-analysis-overview',
        title: 'Analysing log files',
        content: (
          <>
            <p style={{ margin: '0 0 12px', fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.6 }}>
              Log Analysis accepts raw log text — paste it directly or upload a file — and runs two passes: pattern matching against a library of known malicious signatures, and IOC extraction to pull out every IP, domain, hash, email, and URL.
            </p>
            <Bullets items={[
              'Paste log content into the text area or click Upload to load a file',
              'Click Analyse — results appear immediately below without leaving the page',
              'Pattern matches are grouped by severity (Critical → Low) with the matching line shown in context',
              'IOCs are grouped by type: public IPs, private IPs, domains, MD5/SHA1/SHA256 hashes, emails, URLs',
              'Click any IOC pill to copy it to the clipboard',
            ]} />
          </>
        ),
      },
      {
        id: 'log-analysis-iocs',
        title: 'Using extracted IOCs',
        content: (
          <>
            <p style={{ margin: '0 0 12px', fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.6 }}>
              Extracted IOCs can be used directly in the rest of the engagement workflow.
            </p>
            <Bullets items={[
              'Copy public IPs and add them as new targets in the relevant project',
              'Feed extracted domains into the OSINT module for further enumeration',
              'Hash IOCs can be looked up via threat intel feeds externally',
              'Use the Scratchpad to build a running IOC list across multiple log files during an investigation',
            ]} />
            <Tip>Log Analysis is stateless — it does not save results. Copy or screenshot what you need before navigating away.</Tip>
          </>
        ),
      },
    ],
  },
  {
    id: 'timeline',
    title: 'Timeline',
    icon: <History size={15} />,
    subsections: [
      {
        id: 'timeline-overview',
        title: 'Engagement event history',
        content: (
          <>
            <p style={{ margin: '0 0 12px', fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.6 }}>
              The Timeline page shows a chronological log of everything that happened in an engagement: project and target creation, scan starts and completions, and findings discovered. It is useful for reconstructing the sequence of events after the fact and for including a timeline of activities in your final report.
            </p>
            <Bullets items={[
              'Events are sorted newest-first by default — use the order toggle to reverse',
              'Filter by event kind: All, Scans, Findings, or Project events',
              'Finding events are colour-coded by severity — critical and high findings stand out immediately',
              'Each event shows the associated target and a timestamp',
              'The timeline updates in real time as new scans and findings are created',
            ]} />
            <Tip>Switch to the selected engagement using the left nav engagement selector before viewing the Timeline — it only shows events for the currently active project.</Tip>
          </>
        ),
      },
    ],
  },
  {
    id: 'vuln-tracker',
    title: 'Vulnerability Tracker',
    icon: <Bug size={15} />,
    subsections: [
      {
        id: 'vuln-tracker-overview',
        title: 'Structured vulnerability management',
        content: (
          <>
            <p style={{ margin: '0 0 12px', fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.6 }}>
              The Vulnerability Tracker is a structured record of confirmed vulnerabilities with a full remediation lifecycle. It sits alongside Findings (raw scan output) and gives you a place to manage the confirmed, deduplicated set of issues through to resolution.
            </p>
            <Bullets items={[
              <>Status lifecycle: <Badge color="red">Open</Badge> → <Badge color="amber">In Progress</Badge> → <Badge color="green">Mitigated</Badge> — or close as <Badge>Accepted</Badge> / <Badge>False Positive</Badge></>,
              'Each entry has CVSS score, CVE ID, affected asset, and a free-text remediation notes field',
              'Tag entries for grouping and filtering (e.g. "web", "network", "ad")',
              'Import directly from existing scan findings using the "Import from Findings" button',
              'AI Remediation generates a specific fix recommendation for each vulnerability using the configured LLM',
            ]} />
          </>
        ),
      },
      {
        id: 'vuln-tracker-workflow',
        title: 'Tracker workflow',
        content: (
          <>
            <Steps items={[
              'After a scan run, open Vulnerability Tracker and click "Import from Findings"',
              'Select the findings you want to promote to tracked vulnerabilities',
              'Set severity, CVSS, CVE ID and affected asset for each entry',
              'During remediation, move entries to In Progress and add notes on the fix applied',
              'After the client re-tests, mark confirmed fixes as Mitigated',
              'Export the tracker state as part of your final report to show remediation progress',
            ]} />
            <Tip>Use "AI Remediation" on critical and high entries to get a tailored fix recommendation. The AI uses the vulnerability title, description, and affected asset to generate context-specific guidance.</Tip>
            <Note>The Vulnerability Tracker is separate from the Findings list. Findings are raw scan output; the tracker is your curated, deduplicated view of confirmed issues with lifecycle state.</Note>
          </>
        ),
      },
    ],
  },
  {
    id: 'tips',
    title: 'Tips & Workflow',
    icon: <Lightbulb size={15} />,
    subsections: [
      {
        id: 'workflow-typical',
        title: 'Typical engagement workflow',
        content: (
          <>
            <Steps items={[
              'Create a project and add your targets',
              'Let Auto-Probe populate initial recon data (enable in Settings → Auto-Probe)',
              'Run an OSINT Deep Dive playbook to discover subdomains and emails',
              'Check the Network Map to visualize the attack surface',
              'Run the appropriate playbook (Web App Sweep, Vuln Assessment, etc.) against key targets — tag them with MITRE T-IDs in the builder for traceability',
              'Use the AI Operator (Recon mode) to let the AI enumerate the target autonomously — approve each step before it runs',
              'Check the Command Library for manual commands — browse by category or search by T-ID for technique-specific tools',
              'Use the Scratchpad to record observations, paste raw output, and draft preliminary findings',
              'Review findings in Reports — enrich CVEs for any identified vulnerabilities',
              'Use the Pentest Workbench for targeted manual tool runs not covered by the AI',
              'Save captured credentials to the Credential Vault; run Password Auditing on captured hashes',
              'Generate an AI Narrative and export a PDF report',
            ]} />
          </>
        ),
      },
      {
        id: 'workflow-ad',
        title: 'Active Directory engagement workflow',
        content: (
          <>
            <Steps items={[
              'Install required tools: kerbrute, nxc (netexec), impacket (via Settings → Tools)',
              'Create a project and add the domain controller as target (type: windows_host)',
              'Open Pentest Workbench → Active Directory engagement type',
              'Phase 1: Run Kerbrute to enumerate valid domain usernames',
              'Phase 2: Run NetExec to enumerate SMB shares, spray credentials if you have any',
              'Phase 3: Run impacket-GetUserSPNs to request Kerberos service tickets (Kerberoasting)',
              'Phase 4: Run impacket-GetNPUsers to find AS-REP roastable accounts',
              'Take captured hashes to Password Auditing — use hashcat mode 13100 (TGS) or 18200 (AS-REP)',
              'Phase 5: With cracked credentials, run impacket-secretsdump or psexec for full domain compromise',
            ]} />
            <Tip>Captured hashes auto-save to the Credential Vault with source "c2_loot" or can be manually added. From the vault, use "Load from Vault" in Password Auditing to crack them in one step.</Tip>
          </>
        ),
      },
      {
        id: 'tips-misc',
        title: 'Useful tips',
        content: (
          <>
            <Bullets items={[
              <>Press <Cmd>?</Cmd> to open the command palette — fastest way to jump between any page</>,
              'The sidebar collapses — click the toggle button on its right edge to save screen space',
              'All terminal streams support copy-paste — select text as normal',
              'Scan output is always saved to the database, even if you close the terminal mid-run',
              'The backend status indicator in the sidebar footer (green dot) pings the API every load',
              'Scheduled profiles run even when the browser is closed — the scheduler lives in the backend process',
              'The bell icon in the sidebar shows background scan completions — check it after scheduled runs',
              'Export findings to CSV before generating a report — useful for sharing raw data with developers',
              'WeasyPrint for PDF export must be installed: pip install weasyprint',
              <>Set <Cmd>SERAPH_SECRET_KEY</Cmd> environment variable to a strong random value in production</>,
              'AI Operator sessions are persistent — navigate away and return without losing your session state',
              'Search the Command Library by T-ID (e.g. "T1558") to instantly find all templates for a given ATT&CK technique',
              'Use the Scratchpad to draft findings in Markdown during an engagement — copy directly into your report',
              <>The AI Operator injects both MITRE ATT&CK and PTES context automatically — keep those indexes synced in Settings → AI for best results</>,
              'In the ATT&CK Techniques tab, use a Local model for offline generation and a Server model when your server has a GPU',
              'Run Scan Diff after each remediation pass to verify fixes — look for findings moving from Unchanged to Resolved',
            ]} />
          </>
        ),
      },
    ],
  },
]

// ── Component ──────────────────────────────────────────────────────────────────

export default function Guide() {
  const [search, setSearch] = useState('')
  const [activeId, setActiveId] = useState('overview')
  const contentRef = useRef<HTMLDivElement>(null)
  const observerRef = useRef<IntersectionObserver | null>(null)

  // Flatten all subsection IDs for the observer
  const allSubsections = SECTIONS.flatMap(s => s.subsections)

  useEffect(() => {
    observerRef.current = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setActiveId(entry.target.id)
            break
          }
        }
      },
      { rootMargin: '-10% 0px -80% 0px', threshold: 0 }
    )
    allSubsections.forEach(sub => {
      const el = document.getElementById(sub.id)
      if (el) observerRef.current?.observe(el)
    })
    return () => observerRef.current?.disconnect()
  }, [])

  function scrollTo(id: string) {
    const el = document.getElementById(id)
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  const query = search.toLowerCase()
  const filteredSections = SECTIONS.map(s => ({
    ...s,
    subsections: s.subsections.filter(sub =>
      !query ||
      sub.title.toLowerCase().includes(query) ||
      s.title.toLowerCase().includes(query)
    ),
  })).filter(s => s.subsections.length > 0)

  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden' }}>
      {/* Sidebar nav */}
      <aside style={{ width: 224, flexShrink: 0, borderRight: rule, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: 'var(--bg-2)' }}>
        {/* Search */}
        <div style={{ padding: 12, borderBottom: rule }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', borderRadius: 4, border: ruleStrong, background: 'var(--bg)' }}>
            <Search size={13} style={{ color: 'var(--fg-3)', flexShrink: 0 }} />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search guide..."
              style={{ flex: 1, background: 'transparent', fontSize: 11, color: 'var(--fg-2)', outline: 'none', border: 'none', fontFamily: 'var(--font-sans)' }}
            />
          </div>
        </div>

        {/* Nav links */}
        <nav style={{ flex: 1, overflowY: 'auto', padding: '12px 8px' }}>
          {filteredSections.map(section => (
            <div key={section.id}>
              {/* Section header */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 8px', marginTop: 8, marginBottom: 2 }}>
                <span style={{ color: 'var(--fg-4)' }}>{section.icon}</span>
                <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{section.title}</span>
              </div>
              {/* Subsection links */}
              {section.subsections.map(sub => (
                <button
                  key={sub.id}
                  onClick={() => scrollTo(sub.id)}
                  style={{
                    width: '100%', textAlign: 'left', display: 'flex', alignItems: 'center', gap: 8,
                    padding: '6px 12px', borderRadius: 4, fontSize: 11, border: 'none', cursor: 'pointer',
                    background: activeId === sub.id ? 'rgba(240,168,58,0.1)' : 'none',
                    color: activeId === sub.id ? 'var(--accent)' : 'var(--fg-3)',
                    fontFamily: 'var(--font-sans)',
                  }}
                >
                  {activeId === sub.id && <span style={{ width: 4, height: 4, borderRadius: '50%', background: 'var(--accent)', flexShrink: 0 }} />}
                  <span style={{ paddingLeft: activeId === sub.id ? 0 : 12 }}>{sub.title}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>
      </aside>

      {/* Main content */}
      <div ref={contentRef} style={{ flex: 1, overflowY: 'auto', padding: '32px 40px', background: 'var(--bg)' }}>
        {/* Page header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 32, paddingBottom: 24, borderBottom: rule }}>
          <div style={{ width: 40, height: 40, borderRadius: 4, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(240,168,58,0.1)', border: '1px solid rgba(240,168,58,0.2)' }}>
            <BookOpen size={18} style={{ color: 'var(--accent)' }} />
          </div>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 700, color: 'var(--fg)', margin: 0 }}>Seraph Guide</h1>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', marginTop: 2 }}>Everything you need to use the platform effectively</p>
          </div>
        </div>

        {/* Sections */}
        <div style={{ maxWidth: 768, display: 'flex', flexDirection: 'column', gap: 64 }}>
          {filteredSections.map(section => (
            <div key={section.id}>
              {/* Section title */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 24 }}>
                <span style={{ color: 'var(--accent)' }}>{section.icon}</span>
                <h2 style={{ fontSize: 17, fontWeight: 700, color: 'var(--fg)', margin: 0 }}>{section.title}</h2>
                <div style={{ flex: 1, height: 1, marginLeft: 8, background: 'rgba(240,168,58,0.15)' }} />
              </div>

              {/* Subsections */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 40 }}>
                {section.subsections.map(sub => (
                  <div key={sub.id} id={sub.id} style={{ scrollMarginTop: 24 }}>
                    <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg-2)', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                      <ChevronRight size={13} style={{ color: 'var(--accent)' }} />
                      {sub.title}
                    </h3>
                    <div style={{ paddingLeft: 16, borderLeft: rule }}>
                      {sub.content}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}

          <div style={{ paddingBottom: 64 }} />
        </div>
      </div>
    </div>
  )
}
