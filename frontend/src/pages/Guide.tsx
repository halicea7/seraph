import { useState, useEffect, useRef, ReactNode } from 'react'
import {
  BookOpen, Search, LayoutDashboard, ShieldCheck, Swords, Globe,
  Network, Lock, Terminal, KeyRound, FileText, Settings, Zap,
  BookOpen as Playbooks, ChevronRight, Info, AlertTriangle, Lightbulb,
  Bell, Command, GitCompare,
} from 'lucide-react'

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
    <div className="flex gap-3 rounded-lg px-4 py-3 my-3 border border-cyan-700/30" style={{ background: 'rgba(6,182,212,0.06)' }}>
      <Lightbulb size={15} className="text-cyan-400 shrink-0 mt-0.5" />
      <div className="text-sm text-slate-300">{children}</div>
    </div>
  )
}

function Warning({ children }: { children: ReactNode }) {
  return (
    <div className="flex gap-3 rounded-lg px-4 py-3 my-3 border border-amber-700/30" style={{ background: 'rgba(120,53,15,0.12)' }}>
      <AlertTriangle size={15} className="text-amber-400 shrink-0 mt-0.5" />
      <div className="text-sm text-slate-300">{children}</div>
    </div>
  )
}

function Note({ children }: { children: ReactNode }) {
  return (
    <div className="flex gap-3 rounded-lg px-4 py-3 my-3 border border-slate-700/30" style={{ background: 'rgba(71,85,105,0.12)' }}>
      <Info size={15} className="text-slate-400 shrink-0 mt-0.5" />
      <div className="text-sm text-slate-400">{children}</div>
    </div>
  )
}

function Cmd({ children }: { children: ReactNode }) {
  return (
    <code className="inline-block px-2 py-0.5 rounded text-xs font-mono text-cyan-300 border border-cyan-900/30" style={{ background: '#0a1018' }}>
      {children}
    </code>
  )
}

function Block({ children }: { children: ReactNode }) {
  return (
    <pre className="rounded-lg px-4 py-3 my-3 text-xs font-mono text-slate-300 overflow-x-auto border border-cyan-900/20 leading-relaxed" style={{ background: '#05080d' }}>
      {children}
    </pre>
  )
}

function Steps({ items }: { items: string[] }) {
  return (
    <ol className="space-y-2 my-3">
      {items.map((item, i) => (
        <li key={i} className="flex items-start gap-3">
          <span className="flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold text-cyan-400 border border-cyan-500/30 mt-0.5" style={{ background: 'rgba(6,182,212,0.08)' }}>
            {i + 1}
          </span>
          <span className="text-sm text-slate-300">{item}</span>
        </li>
      ))}
    </ol>
  )
}

function Bullets({ items }: { items: (string | ReactNode)[] }) {
  return (
    <ul className="space-y-1.5 my-3">
      {items.map((item, i) => (
        <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
          <ChevronRight size={13} className="text-cyan-600 shrink-0 mt-0.5" />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  )
}

function Badge({ children, color = 'cyan' }: { children: ReactNode; color?: string }) {
  const styles: Record<string, string> = {
    cyan: 'text-cyan-300 border-cyan-500/30 bg-cyan-500/10',
    green: 'text-green-300 border-green-500/30 bg-green-500/10',
    amber: 'text-amber-300 border-amber-500/30 bg-amber-500/10',
    red: 'text-red-300 border-red-500/30 bg-red-500/10',
    purple: 'text-purple-300 border-purple-500/30 bg-purple-500/10',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border ${styles[color] || styles.cyan}`}>
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
            <p className="text-sm text-slate-300 leading-relaxed">
              Seraph is a self-hosted, open-source cybersecurity platform designed for penetration testers, security engineers, and red teamers. It consolidates the most common security workflows — reconnaissance, auditing, exploitation, reporting — into a single interface that runs entirely on your machine.
            </p>
            <p className="text-sm text-slate-300 leading-relaxed mt-3">
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
              Everything in Seraph is organized under <strong className="text-white">Projects</strong>. A project represents a single engagement, client, or assessment scope.
            </p>
            <Bullets items={[
              <>A project contains one or more <strong className="text-white">Targets</strong> — IP addresses or hostnames</>,
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
              Host-based scan categories — <strong className="text-white">Host Hardening (Lynis)</strong>, <strong className="text-white">OpenSCAP</strong>, and <strong className="text-white">Log Monitoring</strong> — need to run on the target machine itself, not locally. Seraph supports this via SSH key authentication.
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
            <p className="text-sm text-slate-300 leading-relaxed">
              Save a category configuration as a <strong className="text-white">Profile</strong> for quick reuse. Profiles can also be scheduled to run automatically on a cron expression.
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
              Select the <strong className="text-white">Active Directory</strong> engagement type for domain-focused assessments. The workflow walks through five phases using dedicated AD tools.
            </p>
            <Bullets items={[
              <><Badge color="amber">Phase 1 — Recon</Badge> Kerbrute user enumeration against the domain controller</>,
              <><Badge color="amber">Phase 2 — Enumeration</Badge> NetExec (nxc) SMB/LDAP/WinRM enumeration with optional credential spray</>,
              <><Badge color="amber">Phase 3 — Kerberoasting</Badge> impacket-GetUserSPNs — request service tickets for offline hash cracking</>,
              <><Badge color="amber">Phase 4 — AS-REP Roasting</Badge> impacket-GetNPUsers — find accounts with pre-auth disabled</>,
              <><Badge color="red">Phase 5 — Post-Compromise</Badge> impacket-secretsdump / psexec / wmiexec for credential extraction and lateral movement</>,
            ]} />
            <p className="text-sm text-slate-300 leading-relaxed mt-3">
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
          <p className="text-sm text-slate-300 leading-relaxed">
            Use "Load from Vault" in the left panel to pull hash-type credentials from the Credential Vault into the hash input automatically. Select the project, check the credentials you want, and they're inserted ready to crack.
          </p>
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
              Every active session has a <strong className="text-white">Post-Ex</strong> tab with automated and guided post-exploitation capabilities. Select a session and click the Post-Ex tab to access them.
            </p>
            <Bullets items={[
              <><strong className="text-white">Auto-Probe</strong> — runs a platform-appropriate recon set (sysinfo, getuid, ipconfig/ifconfig, ps) and stores results as loot</>,
              <><strong className="text-white">Harvest Creds</strong> — runs hashdump + kiwi on Windows Meterpreter, or reads /etc/shadow on Linux. Parsed credentials are saved to the Credential Vault automatically</>,
              <><strong className="text-white">Screenshot</strong> — captures the current desktop of the compromised machine and displays it inline</>,
              <><strong className="text-white">Upgrade Shell</strong> — upgrades a plain shell session to a Meterpreter session with streaming output</>,
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
              Playbooks are pre-defined, multi-step tool chains that run sequentially against a target. Each step creates its own scan record and auto-parses findings.
            </p>
            <Bullets items={[
              <><Badge color="cyan">Full Recon</Badge> — whois → nmap → subfinder → theHarvester</>,
              <><Badge color="green">Web App Sweep</Badge> — nmap → nikto → gobuster → testssl</>,
              <><Badge color="amber">AD / SMB Audit</Badge> — nmap → enum4linux</>,
              <><Badge color="red">Vuln Assessment</Badge> — nmap (vuln scripts) → searchsploit → sqlmap</>,
              <><Badge color="purple">OSINT Deep Dive</Badge> — whois → theHarvester → amass → subfinder</>,
            ]} />
            <p className="text-sm text-slate-300 leading-relaxed mt-3">
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
              <><strong className="text-white">Auto</strong> — all steps run back-to-back without interruption. Best for unattended use.</>,
              <><strong className="text-white">Step-through</strong> — pauses after each step and waits for you to click "Continue". Use this to review output before proceeding.</>,
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
            <p className="text-sm text-slate-300 leading-relaxed">
              Auto-Probe fires automatically when you add a new target. It runs lightweight recon tools in the background so by the time you open the target, there's already data waiting.
            </p>
            <Bullets items={[
              <><Cmd>whois</Cmd> — always runs (if installed)</>,
              <><Cmd>nmap</Cmd> — always runs (if installed)</>,
              <><Cmd>nikto</Cmd> — only if nmap found port 80, 443, 8080, or 8443 open</>,
              <><Cmd>testssl</Cmd> — only if nmap found port 443 or 8443 open</>,
            ]} />
            <p className="text-sm text-slate-300 leading-relaxed mt-2">
              Enable and configure it in <strong className="text-white">Settings → Auto-Probe</strong>. You can choose which tools run and set the intensity (Quick / Standard / Deep).
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
              Findings are automatically parsed from tool output. The <strong className="text-white">All Findings</strong> page (Dashboard → "View All →" or sidebar) gives you a searchable, filterable list of every finding across all projects.
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
            <p className="text-sm text-slate-300 leading-relaxed">
              Each finding has a status that tracks its remediation progress. Click the status badge on any row to change it inline — no separate form needed.
            </p>
            <Bullets items={[
              <><Badge color="red">open</Badge> — newly discovered, not yet addressed</>,
              <><Badge color="amber">in-review</Badge> — under investigation or being reproduced</>,
              <><Badge color="green">remediated</Badge> — fix has been applied and verified</>,
              <><Badge>accepted</Badge> — risk formally accepted by the client or stakeholder</>,
            ]} />
            <p className="text-sm text-slate-300 leading-relaxed mt-3">
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
              The <strong className="text-white">Export</strong> button on All Findings downloads the current filtered set — whatever severity, status, tag, and search filters are active.
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
            <p className="text-sm text-slate-300 leading-relaxed">
              The <strong className="text-white">All Scans</strong> page (Dashboard → Recent Scans → "View All →") shows every scan across all projects with status, finding count, scan type, and date. Filter by status or search by target, project, or scan type.
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
            <p className="text-sm text-slate-300 leading-relaxed">
              Compare two scans to see what changed between them — useful after a remediation cycle to verify fixes and spot regressions.
            </p>
            <Steps items={[
              'Open All Scans',
              'Click any row to select it (shows a numbered checkbox — 1)',
              'Click a second row to select it (shows 2)',
              'Click "Diff Scans" in the header — a panel opens below',
              'Three columns show: New findings, Resolved findings, and Unchanged findings',
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
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
            <p className="text-sm text-slate-300 leading-relaxed">
              The Tools tab detects which security tools are installed on startup and shows their paths and versions. Missing tools show an install command and an <strong className="text-white">Install</strong> button.
            </p>
            <Bullets items={[
              'Green checkmark — tool detected, path and version shown',
              'Red X — tool not found; install command and Install button shown',
              <>Click <strong className="text-white">Install</strong> on any missing tool to run the install command in a live terminal — no copy/paste needed</>,
              'Tools install via the most appropriate method: apt, pip3, go install, snap, or direct binary download',
              <>Click <strong className="text-white">Refresh</strong> after installing to re-detect all tools</>,
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
            <p className="text-sm text-slate-300 leading-relaxed">Admins can manage platform users from the Users tab.</p>
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
            <Bullets items={[
              <>Supports any OpenAI-compatible endpoint — works with <strong className="text-white">Ollama</strong> and <strong className="text-white">LMStudio</strong></>,
              'Presets auto-fill the endpoint URL for each provider',
              '"Test Connection" fetches available models and auto-selects the first one',
              'Settings are stored server-side — persist across restarts',
            ]} />
            <Block>{`Ollama default:   http://localhost:11434
LMStudio default: http://localhost:1234`}</Block>
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
              'Run the appropriate playbook (Web App Sweep, Vuln Assessment, etc.) against key targets',
              'Review findings in Reports — enrich CVEs for any identified vulnerabilities',
              'Use the Pentest Workbench for manual, targeted tool runs',
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
    <div className="flex h-full overflow-hidden">
      {/* Sidebar nav */}
      <aside className="w-56 shrink-0 border-r border-cyan-900/20 flex flex-col overflow-hidden" style={{ background: '#090d14' }}>
        {/* Search */}
        <div className="p-3 border-b border-cyan-900/20">
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-cyan-900/20" style={{ background: '#05080d' }}>
            <Search size={13} className="text-slate-500 shrink-0" />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search guide..."
              className="flex-1 bg-transparent text-xs text-slate-300 placeholder:text-slate-600 focus:outline-none"
            />
          </div>
        </div>

        {/* Nav links */}
        <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-0.5">
          {filteredSections.map(section => (
            <div key={section.id}>
              {/* Section header */}
              <div className="flex items-center gap-2 px-2 py-1.5 mt-2 mb-0.5">
                <span className="text-slate-600">{section.icon}</span>
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{section.title}</span>
              </div>
              {/* Subsection links */}
              {section.subsections.map(sub => (
                <button
                  key={sub.id}
                  onClick={() => scrollTo(sub.id)}
                  className={`w-full text-left flex items-center gap-2 px-3 py-1.5 rounded text-xs transition-colors ${
                    activeId === sub.id
                      ? 'text-cyan-300 bg-cyan-500/10'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                  }`}
                >
                  {activeId === sub.id && <span className="w-1 h-1 rounded-full bg-cyan-400 shrink-0" />}
                  <span className={activeId === sub.id ? '' : 'pl-3'}>{sub.title}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>
      </aside>

      {/* Main content */}
      <div ref={contentRef} className="flex-1 overflow-y-auto px-10 py-8" style={{ background: '#05080d' }}>
        {/* Page header */}
        <div className="flex items-center gap-3 mb-8 pb-6 border-b border-cyan-900/20">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ background: 'rgba(6,182,212,0.1)', border: '1px solid rgba(6,182,212,0.2)' }}>
            <BookOpen size={18} className="text-cyan-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Seraph Guide</h1>
            <p className="text-sm text-slate-400 mt-0.5">Everything you need to use the platform effectively</p>
          </div>
        </div>

        {/* Sections */}
        <div className="max-w-3xl space-y-16">
          {filteredSections.map(section => (
            <div key={section.id}>
              {/* Section title */}
              <div className="flex items-center gap-2 mb-6">
                <span className="text-cyan-400">{section.icon}</span>
                <h2 className="text-lg font-bold text-white">{section.title}</h2>
                <div className="flex-1 h-px ml-2" style={{ background: 'rgba(6,182,212,0.15)' }} />
              </div>

              {/* Subsections */}
              <div className="space-y-10">
                {section.subsections.map(sub => (
                  <div key={sub.id} id={sub.id} className="scroll-mt-6">
                    <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
                      <ChevronRight size={13} className="text-cyan-600" />
                      {sub.title}
                    </h3>
                    <div className="pl-4 border-l border-cyan-900/20">
                      {sub.content}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}

          <div className="pb-16" />
        </div>
      </div>
    </div>
  )
}
