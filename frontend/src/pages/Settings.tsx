import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  RefreshCw, CheckCircle, XCircle, Copy, Check,
  Trash2, Package, Terminal, Brain, Wifi, WifiOff, Save, Loader,
  Users, ShieldCheck, UserPlus, Eye, EyeOff, KeyRound,
  Zap, Gauge, Palette, Monitor, FlaskConical, Download, X, Info, ExternalLink, Fingerprint,
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { useTheme } from '../contexts/ThemeContext'

interface ToolInfo {
  available: boolean
  path: string | null
  version: string | null
  label: string
  install_hint: string | null
  url: string | null
}

interface Profile {
  id: string
  name: string
  description: string
  scan_categories: string  // JSON string
  created_at: string
}

interface HostInfo {
  os: string
  distro_id: string
  distro_name: string
  pkg_manager: string
}

// Per-tool package names keyed by package manager
const TOOL_PKGS: Record<string, Partial<Record<string, string>>> = {
  nmap:         { apt: 'nmap',             dnf: 'nmap',           pacman: 'nmap',        brew: 'nmap',          apk: 'nmap',       zypper: 'nmap' },
  nikto:        { apt: 'nikto',            dnf: 'nikto',          pacman: 'nikto',       brew: 'nikto',         apk: 'nikto',      zypper: 'nikto' },
  testssl:      { apt: 'testssl.sh',       pacman: 'testssl.sh',  brew: 'testssl' },
  lynis:        { apt: 'lynis',            dnf: 'lynis',          pacman: 'lynis',       brew: 'lynis',         zypper: 'lynis' },
  oscap:        { apt: 'libopenscap8 openscap-scanner', dnf: 'openscap-scanner', zypper: 'openscap' },
  masscan:      { apt: 'masscan',          dnf: 'masscan',        pacman: 'masscan',     brew: 'masscan' },
  gobuster:     { apt: 'gobuster',         brew: 'gobuster',      go: 'github.com/OJ/gobuster/v3@latest' },
  sqlmap:       { apt: 'sqlmap',           dnf: 'sqlmap',         pacman: 'sqlmap',      brew: 'sqlmap' },
  hydra:        { apt: 'hydra',            dnf: 'hydra',          pacman: 'hydra',       brew: 'hydra' },
  whois:        { apt: 'whois',            dnf: 'whois',          pacman: 'whois',       brew: 'whois' },
  dig:          { apt: 'dnsutils',         dnf: 'bind-utils',     pacman: 'bind',        brew: 'bind',          apk: 'bind-tools', zypper: 'bind-utils' },
  theHarvester: { apt: 'theharvester',     brew: 'theharvester' },
  subfinder:    { brew: 'subfinder',       go: 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest' },
  enum4linux:   { apt: 'enum4linux',       pacman: 'enum4linux' },
  ffuf:         { brew: 'ffuf',            go: 'github.com/ffuf/ffuf/v2@latest' },
  searchsploit: { apt: 'exploitdb',        pacman: 'exploitdb',   brew: 'exploitdb' },
  aws:          { pip: 'awscli',                                                        brew: 'awscli' },
  hashcat:      { apt: 'hashcat',          dnf: 'hashcat',        pacman: 'hashcat',     brew: 'hashcat' },
  john:         { apt: 'john',             dnf: 'john',           pacman: 'john',        brew: 'john' },
  go:           { apt: 'golang-go',        dnf: 'golang',         pacman: 'go',          brew: 'go',            apk: 'go',         zypper: 'go' },
  rustscan:     { brew: 'rustscan' },
  nuclei:       { brew: 'nuclei',          go: 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' },
  feroxbuster:  { brew: 'feroxbuster' },
  kerbrute:                { go: 'github.com/ropnop/kerbrute@latest' },
  nxc:                     { apt: 'netexec',          pip: 'netexec' },
  'impacket-GetUserSPNs':  { apt: 'python3-impacket', pip: 'impacket' },
  'impacket-GetNPUsers':   { apt: 'python3-impacket', pip: 'impacket' },
  'impacket-secretsdump':  { apt: 'python3-impacket', pip: 'impacket' },
  'impacket-psexec':       { apt: 'python3-impacket', pip: 'impacket' },
  'impacket-wmiexec':      { apt: 'python3-impacket', pip: 'impacket' },
  responder:               { apt: 'responder' },
}

interface ToolUsage { feature: string; detail: string }
interface ToolInfoData { description: string; usedIn: ToolUsage[] }

const TOOL_INFO: Record<string, ToolInfoData> = {
  nmap: {
    description: 'Industry-standard network scanner. Discovers open ports, identifies running services, detects OS fingerprints, and runs NSE vulnerability scripts.',
    usedIn: [
      { feature: 'Auto-Probe', detail: 'Runs automatically on every new target for initial reconnaissance' },
      { feature: 'Tool Chains', detail: 'Port scanning phase for external, internal, and web target types' },
      { feature: 'Playbooks', detail: 'Core step in 11 built-in playbooks (Full Recon, Web Sweep, AD Audit, Vuln Assessment, and more)' },
      { feature: 'Scan Templates', detail: 'nmap_discovery and nmap_vuln templates for custom scans' },
    ],
  },
  nikto: {
    description: 'Web server scanner that checks for dangerous files, outdated server software, and common misconfigurations across HTTP/HTTPS.',
    usedIn: [
      { feature: 'Auto-Probe', detail: 'Conditionally runs when ports 80, 443, 8080, 8443, or 8000 are open' },
      { feature: 'Tool Chains', detail: 'Web application scanning phase' },
      { feature: 'Playbooks', detail: 'Web Sweep, Web App Audit, REST API Assessment, Wireless AP Recon' },
      { feature: 'Scan Templates', detail: 'nikto_web scan template' },
    ],
  },
  testssl: {
    description: 'Comprehensive TLS/SSL configuration tester. Checks cipher suites, certificate validity, protocol versions, and known vulnerabilities (BEAST, POODLE, Heartbleed, etc.).',
    usedIn: [
      { feature: 'Auto-Probe', detail: 'Conditionally runs when port 443 or 8443 is open' },
      { feature: 'Tool Chains', detail: 'Web application TLS/SSL analysis phase' },
      { feature: 'Playbooks', detail: 'Web Sweep, Web App Audit, REST API Assessment' },
      { feature: 'Scan Templates', detail: 'Integrated in nikto_web scan template' },
    ],
  },
  lynis: {
    description: 'Host-based security auditing tool. Scans the local system for hardening gaps, misconfigurations, and compliance issues, producing a hardening score.',
    usedIn: [
      { feature: 'Hardening Module', detail: 'Drives the full hardening audit — score, warnings, and improvement suggestions' },
      { feature: 'Scan Templates', detail: 'lynis_audit scan template for local host assessments' },
    ],
  },
  oscap: {
    description: 'OpenSCAP scanner that evaluates systems against SCAP datastreams and XCCDF compliance profiles (CIS, STIG, PCI-DSS, etc.).',
    usedIn: [
      { feature: 'Scan Templates', detail: 'openscap_check template for compliance profile evaluation' },
    ],
  },
  masscan: {
    description: 'Extremely fast TCP port scanner capable of scanning the entire internet in under 6 minutes. Used for large-scale initial port discovery.',
    usedIn: [
      { feature: 'Tool Chains', detail: 'High-speed port discovery for external and internal network target types' },
    ],
  },
  gobuster: {
    description: 'Directory and file brute-forcer for web servers. Also supports DNS subdomain enumeration and virtual host discovery.',
    usedIn: [
      { feature: 'Tool Chains', detail: 'Enumeration phase for external and web application targets' },
      { feature: 'Playbooks', detail: 'Web Sweep, Web App Audit, REST API Assessment' },
    ],
  },
  sqlmap: {
    description: 'Automated SQL injection detection and exploitation tool. Fingerprints databases, extracts data, and tests injection points across HTTP parameters.',
    usedIn: [
      { feature: 'Tool Chains', detail: 'Exploitation phase for external and web application targets' },
      { feature: 'Playbooks', detail: 'Vuln Assessment, Web App Audit, REST API Assessment, Database Discovery' },
    ],
  },
  hydra: {
    description: 'Fast and flexible online password brute-forcer supporting 50+ protocols including SSH, FTP, HTTP, SMB, LDAP, and more.',
    usedIn: [
      { feature: 'Tool Chains', detail: 'Exploitation phase for external and internal network targets' },
      { feature: 'Playbooks', detail: 'Credential Spraying playbook (SSH and SMB password spray)' },
    ],
  },
  whois: {
    description: 'Queries domain registration data including registrar, creation/expiry dates, name servers, and registrant contact information.',
    usedIn: [
      { feature: 'Auto-Probe', detail: 'Always runs on every new target for initial OSINT' },
      { feature: 'Tool Chains', detail: 'Reconnaissance phase for external and internal targets' },
      { feature: 'Playbooks', detail: 'Full Recon, OSINT Deep Dive' },
    ],
  },
  dig: {
    description: 'DNS lookup utility for querying DNS records (A, MX, NS, TXT, CNAME, SOA). Used for mapping a target\'s DNS infrastructure.',
    usedIn: [
      { feature: 'Tool Chains', detail: 'Reconnaissance phase for external network targets' },
    ],
  },
  theHarvester: {
    description: 'OSINT tool that gathers emails, subdomains, hosts, employee names, and open ports from public sources like search engines, DNS, and certificate transparency logs.',
    usedIn: [
      { feature: 'OSINT Module', detail: 'Dedicated OSINT tool with command templates for email and subdomain harvesting' },
      { feature: 'Tool Chains', detail: 'Reconnaissance phase for external network targets' },
      { feature: 'Playbooks', detail: 'Full Recon, OSINT Deep Dive' },
    ],
  },
  subfinder: {
    description: 'Passive subdomain discovery tool using 40+ sources including certificate transparency logs, DNS aggregators, and public APIs. Fast and low-noise.',
    usedIn: [
      { feature: 'OSINT Module', detail: 'Dedicated OSINT tool for rapid passive subdomain enumeration' },
      { feature: 'Tool Chains', detail: 'Reconnaissance phase for external network targets' },
      { feature: 'Playbooks', detail: 'Full Recon, OSINT Deep Dive' },
    ],
  },
  amass: {
    description: 'In-depth attack surface mapping tool using 50+ passive sources. Goes beyond subfinder with graph-based analysis and ASN/IP range enumeration.',
    usedIn: [
      { feature: 'OSINT Module', detail: 'Dedicated OSINT tool for comprehensive attack surface mapping' },
      { feature: 'Playbooks', detail: 'OSINT Deep Dive' },
    ],
  },
  hashcat: {
    description: 'World\'s fastest GPU-accelerated password cracker. Supports 300+ hash types and attack modes including dictionary, brute-force, combinator, and rule-based.',
    usedIn: [
      { feature: 'Cracking Module', detail: 'Primary GPU cracking engine — MD5, SHA1, SHA256, NTLM, bcrypt, and more' },
      { feature: 'Database', detail: 'CrackingJob model tracks jobs, results, and cracked hashes' },
    ],
  },
  john: {
    description: 'John the Ripper — CPU-based password hash cracker with auto-detection of hash formats. Useful when a GPU is unavailable or for formats hashcat doesn\'t support.',
    usedIn: [
      { feature: 'Cracking Module', detail: 'CPU cracking fallback — NT, MD5, SHA1, bcrypt, Kerberos TGS, and more' },
      { feature: 'Database', detail: 'CrackingJob model tracks jobs and cracked results' },
    ],
  },
  enum4linux: {
    description: 'SMB/NetBIOS enumeration tool wrapping smbclient, rpcclient, and net. Extracts users, groups, shares, policies, and OS info from Windows/Samba hosts.',
    usedIn: [
      { feature: 'Tool Chains', detail: 'Enumeration phase for internal and external network targets (Windows hosts)' },
      { feature: 'Playbooks', detail: 'AD Audit, Full AD Attack Path, Windows Post-Exploitation' },
    ],
  },
  ffuf: {
    description: 'Fast web fuzzer written in Go. Used for directory brute-forcing, parameter fuzzing, virtual host discovery, and API endpoint enumeration.',
    usedIn: [
      { feature: 'Tool Chains', detail: 'Enumeration phase for external and web application targets' },
    ],
  },
  searchsploit: {
    description: 'Command-line search tool for the Exploit-DB database. Finds public exploits and shellcode matching detected software versions and CVEs.',
    usedIn: [
      { feature: 'Tool Chains', detail: 'Exploitation research phase for external and internal targets' },
      { feature: 'Playbooks', detail: 'Vuln Assessment — matches discovered services to known exploits' },
    ],
  },
  aws: {
    description: 'AWS Command Line Interface for interacting with Amazon Web Services APIs. Used for cloud security auditing, IAM analysis, and S3 bucket assessments.',
    usedIn: [
      { feature: 'Tool Chains', detail: 'All phases of cloud_aws target type: recon, scanning, enumeration, exploitation, post-exploitation' },
      { feature: 'Scan Templates', detail: 'aws_security_check template for IAM, S3, EC2, and CloudTrail audits' },
    ],
  },
  go: {
    description: 'Go programming language runtime. Not a security tool itself — required to run Go-based tools installed via `go install`.',
    usedIn: [
      { feature: 'Runtime Dependency', detail: 'Required to install and run subfinder, ffuf, gobuster, nuclei (go install method)' },
    ],
  },
  rustscan: {
    description: 'Ultra-fast port scanner written in Rust. Scans all 65535 TCP ports in seconds then hands discovered ports to Nmap for targeted service/version detection — dramatically faster than Nmap\'s --top-ports 1000.',
    usedIn: [
      { feature: 'Auto-Probe', detail: 'Pre-nmap port discovery pass — open ports feed directly into nmap -sV -p <ports>' },
    ],
  },
  nuclei: {
    description: 'Fast, template-based vulnerability scanner from ProjectDiscovery with 7000+ community templates covering CVEs, misconfigurations, exposed panels, default credentials, and more.',
    usedIn: [
      { feature: 'Auto-Probe', detail: 'Runs after nmap on web ports (80, 443, 8080, 8443) with medium/high/critical severity templates' },
    ],
  },
  feroxbuster: {
    description: 'Fast, recursive web directory and file fuzzer written in Rust. Finds hidden paths, admin panels, backup files, and APIs through brute-force enumeration.',
    usedIn: [
      { feature: 'Auto-Probe', detail: 'Runs on HTTP ports (80, 8080, 8000) to discover hidden paths and sensitive endpoints' },
    ],
  },
  kerbrute: {
    description: 'Kerberos user enumeration and password spraying tool. Validates AD usernames via Kerberos pre-authentication — generates no failed-login events, avoiding NTLM lockout noise.',
    usedIn: [
      { feature: 'Pentest Workbench', detail: 'Active Directory engagement — scanning phase (user enumeration) and exploitation phase (password spray)' },
    ],
  },
  nxc: {
    description: 'NetExec (successor to CrackMapExec). Swiss-army knife for Active Directory: SMB/LDAP/WinRM enumeration, credential spraying, pass-the-hash, NTDS dumping, and lateral movement.',
    usedIn: [
      { feature: 'Pentest Workbench', detail: 'Active Directory engagement — all phases: anonymous SMB recon, user enumeration, credentialed enumeration, exploitation, NTDS dump' },
    ],
  },
  'impacket-GetUserSPNs': {
    description: 'Impacket tool for Kerberoasting — requests TGS tickets for all AD service accounts (SPNs). Returned tickets can be cracked offline to recover service account passwords.',
    usedIn: [
      { feature: 'Pentest Workbench', detail: 'Active Directory engagement — enumeration phase (Kerberoasting)' },
    ],
  },
  'impacket-GetNPUsers': {
    description: 'Impacket tool for AS-REP roasting — retrieves Kerberos AS-REP hashes for accounts with "Do not require Kerberos preauthentication" enabled. Hashcat-ready output.',
    usedIn: [
      { feature: 'Pentest Workbench', detail: 'Active Directory engagement — enumeration phase (AS-REP roasting)' },
    ],
  },
  'impacket-secretsdump': {
    description: 'Impacket tool for dumping SAM, LSA secrets, cached domain credentials, and NTDS.dit hashes. Supports DCSync to pull all NTLM hashes from a domain controller without touching disk.',
    usedIn: [
      { feature: 'Pentest Workbench', detail: 'Active Directory engagement — post-exploitation phase (secretsdump and DCSync)' },
    ],
  },
  'impacket-psexec': {
    description: 'Impacket implementation of PsExec — remote execution on Windows hosts via SMB service pipes. Returns a SYSTEM-level shell. Noisier than wmiexec (creates a service).',
    usedIn: [
      { feature: 'Pentest Workbench', detail: 'Active Directory engagement — exploitation phase (remote execution)' },
    ],
  },
  'impacket-wmiexec': {
    description: 'Impacket WMI-based remote execution. Provides a semi-interactive shell using WMI without creating services — lower EDR footprint than psexec.',
    usedIn: [
      { feature: 'Pentest Workbench', detail: 'Active Directory engagement — exploitation phase (stealthier remote execution)' },
    ],
  },
  responder: {
    description: 'LLMNR/NBT-NS/mDNS poisoner. Intercepts broadcast name resolution queries on internal networks and returns forged responses, capturing NTLMv2 challenge/response hashes. Hashes can be cracked offline (hashcat -m 5600) or relayed (ntlmrelayx).',
    usedIn: [
      { feature: 'Pentest Workbench', detail: 'Internal Network engagement — exploitation phase (NTLMv2 hash capture via poisoning)' },
    ],
  },
}


function getBulkInstallCmd(toolNames: string[], hostInfo: HostInfo | null): string {
  const mgr = hostInfo?.pkg_manager || 'apt'
  const pkgSet = new Set(
    toolNames.map(n => TOOL_PKGS[n]?.[mgr]).filter(Boolean) as string[]
  )
  const pkgList = Array.from(pkgSet)

  const pipSet = new Set(
    toolNames.map(n => TOOL_PKGS[n]?.['pip']).filter(Boolean) as string[]
  )
  const pipList = Array.from(pipSet)

  const parts: string[] = []
  if (pkgList.length) {
    if (mgr === 'apt') parts.push(`sudo apt-get update && sudo apt-get install -y ${pkgList.join(' ')}`)
    else if (mgr === 'dnf' || mgr === 'yum') parts.push(`sudo ${mgr} install -y ${pkgList.join(' ')}`)
    else if (mgr === 'pacman') parts.push(`sudo pacman -S --noconfirm ${pkgList.join(' ')}`)
    else if (mgr === 'apk') parts.push(`sudo apk add ${pkgList.join(' ')}`)
    else if (mgr === 'zypper') parts.push(`sudo zypper install -y ${pkgList.join(' ')}`)
    else if (mgr === 'brew') parts.push(`brew install ${pkgList.join(' ')}`)
  }
  if (pipList.length) parts.push(`pip install ${pipList.join(' ')}`)
  return parts.join(' && ')
}

const PKG_MANAGER_LABELS: Record<string, string> = {
  apt: 'Debian / Ubuntu', dnf: 'Fedora / RHEL', yum: 'CentOS / RHEL',
  pacman: 'Arch Linux', apk: 'Alpine', zypper: 'openSUSE', brew: 'macOS (Homebrew)',
}

interface AIConfig {
  endpoint: string
  model: string
  provider: string
  temperature: number | null
  top_p: number | null
  top_k: number | null
  min_p: number | null
  presence_penalty: number | null
  repetition_penalty: number | null
  timeout: number | null
}

interface AIStatus {
  online: boolean
  endpoint: string
  model_count?: number
  error?: string
}

export default function Settings() {
  const [activeTab, setActiveTab] = useState<'tools' | 'profiles' | 'ai' | 'users' | 'autoprobe' | 'appearance' | 'webhooks'>('tools')
  const { user: currentUser, token: authToken, refreshUser } = useAuth()
  const { theme, setTheme } = useTheme()
  const navigate = useNavigate()
  const [toolStatus, setToolStatus] = useState<Record<string, ToolInfo>>({})
  const [hostInfo, setHostInfo] = useState<HostInfo | null>(null)
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState('')
  const [profiles, setProfiles] = useState<Profile[]>([])

  // Tool info modal state
  const [infoTool, setInfoTool] = useState<string | null>(null)

  // Install modal state
  const [installTool, setInstallTool] = useState<string | null>(null)
  const [installLines, setInstallLines] = useState<string[]>([])
  const [installDone, setInstallDone] = useState(false)

  function startInstall(toolName: string) {
    setInstallTool(toolName)
    setInstallLines([])
    setInstallDone(false)
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${wsProto}//${window.location.host}/ws/install/${toolName}`)
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data)
      if (msg.type === 'stdout' || msg.type === 'stderr' || msg.type === 'error') {
        setInstallLines(prev => [...prev, msg.data])
      } else if (msg.type === 'exit') {
        setInstallDone(true)
        if (msg.code === 0) loadTools()
      }
    }
    ws.onerror = () => setInstallLines(prev => [...prev, '\nWebSocket error — check server logs.\n'])
  }

  // Auto-probe state
  const [probeEnabled, setProbeEnabled] = useState(false)
  const [probeTools, setProbeTools] = useState<string[]>(['whois', 'rustscan', 'nmap', 'nikto', 'testssl', 'nuclei', 'feroxbuster'])
  const [probeIntensity, setProbeIntensity] = useState<'quick' | 'standard' | 'deep'>('standard')
  const [probeSaving, setProbeSaving] = useState(false)
  const [probeLoading, setProbeLoading] = useState(false)

  // Edit profile state
  const [profileFirstName, setProfileFirstName] = useState(() => {
    const parts = (currentUser?.full_name || '').split(' ')
    return parts.slice(0, -1).join(' ') || parts[0] || ''
  })
  const [profileLastName, setProfileLastName] = useState(() => {
    const parts = (currentUser?.full_name || '').split(' ')
    return parts.length > 1 ? parts[parts.length - 1] : ''
  })
  const [profileSaving, setProfileSaving] = useState(false)
  const [profileOk, setProfileOk] = useState(false)
  const [profileError, setProfileError] = useState('')

  // User management state
  interface UserRow { id: string; username: string; role: string; is_active: boolean; full_name: string; created_at: string }
  const [userList, setUserList] = useState<UserRow[]>([])
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState<'admin' | 'analyst'>('analyst')
  const [newFirstName, setNewFirstName] = useState('')
  const [newLastName, setNewLastName] = useState('')
  const [showNewPw, setShowNewPw] = useState(false)
  const [userError, setUserError] = useState('')
  const [userSaving, setUserSaving] = useState(false)
  // Change password
  const [curPw, setCurPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [pwError, setPwError] = useState('')
  const [pwSaving, setPwSaving] = useState(false)
  const [pwOk, setPwOk] = useState(false)

  // Passkey state
  interface PasskeyRow { id: string; name: string; created_at: string }
  const [passkeys, setPasskeys] = useState<PasskeyRow[]>([])
  const [passkeyRegLoading, setPasskeyRegLoading] = useState(false)
  const [passkeyError, setPasskeyError] = useState('')
  const [newPasskeyName, setNewPasskeyName] = useState('iCloud Keychain')

  // Webhook state
  interface WebhookRow { id: string; name: string; url: string; events: string[]; active: boolean; created_at: string }
  const [webhooks, setWebhooks] = useState<WebhookRow[]>([])
  const [webhookForm, setWebhookForm] = useState({ name: '', url: '', events: ['critical', 'warning'], active: true })
  const [webhookSaving, setWebhookSaving] = useState(false)
  const [webhookError, setWebhookError] = useState('')
  const [webhookTestId, setWebhookTestId] = useState<string | null>(null)

  // Demo mode state
  const [demoActive, setDemoActive] = useState(false)
  const [demoLoading, setDemoLoading] = useState(false)
  const [demoError, setDemoError] = useState('')

  // AI config state
  const [aiConfig, setAiConfig] = useState<AIConfig>({ endpoint: 'http://localhost:11434', model: '', provider: 'ollama', temperature: null, top_p: null, top_k: null, min_p: null, presence_penalty: null, repetition_penalty: null, timeout: null })
  const [aiStatus, setAiStatus] = useState<AIStatus | null>(null)
  const [aiModels, setAiModels] = useState<string[]>([])
  const [aiSaving, setAiSaving] = useState(false)
  const [aiTesting, setAiTesting] = useState(false)

  useEffect(() => {
    loadTools()
    loadProfiles()
    loadAiConfig()
    loadProbeConfig()
    loadPasskeys()
    loadWebhooks()
    if (currentUser?.role === 'admin') {
      loadUsers()
      loadDemoStatus()
    }
  }, [])

  async function loadPasskeys() {
    try {
      const res = await fetch('/api/v1/passkeys/', { headers: { Authorization: `Bearer ${authToken}` } })
      if (res.ok) setPasskeys(await res.json())
    } catch { /* ignore */ }
  }

  async function handleRegisterPasskey() {
    if (!window.isSecureContext) {
      setPasskeyError('Passkeys require a secure context. Access Seraph via http://localhost:8000 or enable HTTPS.')
      return
    }
    if (!window.PublicKeyCredential) {
      setPasskeyError('Passkeys are not available in this browser.')
      return
    }
    setPasskeyError('')
    setPasskeyRegLoading(true)
    try {
      // 1. Begin
      const beginRes = await fetch('/api/v1/passkeys/register/begin', {
        method: 'POST',
        headers: { Authorization: `Bearer ${authToken}` },
      })
      if (!beginRes.ok) throw new Error('Failed to start passkey registration')
      const opts = await beginRes.json()
      const { _challenge_key: challengeKey, ...pubKeyOpts } = opts

      // 2. Decode for browser API
      const createOpts: PublicKeyCredentialCreationOptions = {
        ...pubKeyOpts,
        challenge: _b64urlToBuffer(pubKeyOpts.challenge),
        user: { ...pubKeyOpts.user, id: _b64urlToBuffer(pubKeyOpts.user.id) },
        excludeCredentials: (pubKeyOpts.excludeCredentials || []).map((c: any) => ({
          ...c, id: _b64urlToBuffer(c.id),
        })),
      }

      // 3. Prompt authenticator
      const cred = await navigator.credentials.create({ publicKey: createOpts }) as PublicKeyCredential | null
      if (!cred) throw new Error('No credential created')
      const ar = cred.response as AuthenticatorAttestationResponse

      // 4. Complete
      const completeRes = await fetch('/api/v1/passkeys/register/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
        body: JSON.stringify({
          challenge_key: challengeKey,
          name: newPasskeyName.trim() || 'Passkey',
          credential: {
            id: cred.id,
            rawId: _bufferToB64url(cred.rawId),
            response: {
              clientDataJSON: _bufferToB64url(ar.clientDataJSON),
              attestationObject: _bufferToB64url(ar.attestationObject),
              transports: ar.getTransports ? ar.getTransports() : [],
            },
            type: cred.type,
          },
        }),
      })
      const data = await completeRes.json()
      if (!completeRes.ok) throw new Error(data.detail || 'Registration failed')
      setNewPasskeyName('iCloud Keychain')
      await loadPasskeys()
    } catch (err: any) {
      if (err.name === 'NotAllowedError') {
        setPasskeyError('Passkey prompt was cancelled.')
      } else {
        setPasskeyError(err.message || 'Registration failed')
      }
    } finally {
      setPasskeyRegLoading(false)
    }
  }

  async function handleDeletePasskey(id: string) {
    await fetch(`/api/v1/passkeys/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${authToken}` },
    })
    setPasskeys(prev => prev.filter(p => p.id !== id))
  }

  function _b64urlToBuffer(b64url: string): ArrayBuffer {
    const padded = b64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(
      b64url.length + (4 - (b64url.length % 4)) % 4, '=',
    )
    const bin = atob(padded)
    const buf = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i)
    return buf.buffer
  }

  function _bufferToB64url(buf: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  }

  async function loadWebhooks() {
    try {
      const res = await fetch('/api/v1/webhooks', { headers: { Authorization: `Bearer ${authToken}` } })
      if (res.ok) setWebhooks(await res.json())
    } catch { /* ignore */ }
  }

  async function handleCreateWebhook(e: React.FormEvent) {
    e.preventDefault()
    setWebhookError('')
    if (!webhookForm.name.trim() || !webhookForm.url.trim()) { setWebhookError('Name and URL are required.'); return }
    setWebhookSaving(true)
    try {
      const res = await fetch('/api/v1/webhooks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
        body: JSON.stringify(webhookForm),
      })
      if (!res.ok) { const d = await res.json(); setWebhookError(d.detail || 'Failed to create webhook'); return }
      setWebhookForm({ name: '', url: '', events: ['critical', 'warning'], active: true })
      await loadWebhooks()
    } catch { setWebhookError('Request failed') }
    finally { setWebhookSaving(false) }
  }

  async function handleDeleteWebhook(id: string) {
    await fetch(`/api/v1/webhooks/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${authToken}` } })
    setWebhooks(w => w.filter(x => x.id !== id))
  }

  async function handleToggleWebhook(id: string, active: boolean) {
    const res = await fetch(`/api/v1/webhooks/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
      body: JSON.stringify({ active }),
    })
    if (res.ok) setWebhooks(w => w.map(x => x.id === id ? { ...x, active } : x))
  }

  async function handleTestWebhook(id: string) {
    setWebhookTestId(id)
    try {
      await fetch(`/api/v1/webhooks/${id}/test`, { method: 'POST', headers: { Authorization: `Bearer ${authToken}` } })
    } finally { setTimeout(() => setWebhookTestId(null), 1500) }
  }

  function toggleWebhookEvent(event: string) {
    setWebhookForm(f => ({
      ...f,
      events: f.events.includes(event) ? f.events.filter(e => e !== event) : [...f.events, event],
    }))
  }

  async function loadDemoStatus() {
    try {
      const res = await fetch('/api/v1/demo/status')
      if (res.ok) setDemoActive((await res.json()).active)
    } catch { /* backend offline */ }
  }

  async function handleDemoToggle() {
    setDemoLoading(true)
    setDemoError('')
    try {
      const res = await fetch(`/api/v1/demo/${demoActive ? 'clear' : 'seed'}`, {
        method: demoActive ? 'DELETE' : 'POST',
      })
      if (res.ok) {
        setDemoActive(!demoActive)
        navigate('/')
      } else {
        setDemoError(`Failed to ${demoActive ? 'clear' : 'seed'} demo data (${res.status})`)
      }
    } catch {
      setDemoError('Could not reach the backend.')
    } finally {
      setDemoLoading(false)
    }
  }

  async function loadTools() {
    setLoading(true)
    try {
      const [toolRes, hostRes] = await Promise.all([
        fetch('/api/v1/settings/tools'),
        fetch('/api/v1/settings/host-info'),
      ])
      setToolStatus(await toolRes.json())
      if (hostRes.ok) setHostInfo(await hostRes.json())
    } finally {
      setLoading(false)
    }
  }

  async function loadProfiles() {
    const res = await fetch('/api/v1/profiles')
    if (res.ok) setProfiles(await res.json())
  }

  async function deleteProfile(id: string) {
    await fetch(`/api/v1/profiles/${id}`, { method: 'DELETE' })
    loadProfiles()
  }

  async function loadProbeConfig() {
    setProbeLoading(true)
    try {
      const res = await fetch('/api/v1/settings/auto-probe')
      if (res.ok) {
        const data = await res.json()
        setProbeEnabled(data.enabled)
        setProbeTools(data.tools)
        setProbeIntensity(data.intensity)
      }
    } finally {
      setProbeLoading(false)
    }
  }

  async function saveProbeConfig() {
    setProbeSaving(true)
    try {
      await fetch('/api/v1/settings/auto-probe', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: probeEnabled, tools: probeTools, intensity: probeIntensity }),
      })
    } finally {
      setProbeSaving(false)
    }
  }

  function toggleProbeTool(name: string) {
    setProbeTools(prev =>
      prev.includes(name) ? prev.filter(t => t !== name) : [...prev, name]
    )
  }

  async function handleUpdateProfile(e: React.FormEvent) {
    e.preventDefault()
    setProfileError('')
    setProfileOk(false)
    setProfileSaving(true)
    try {
      const fullName = `${profileFirstName.trim()} ${profileLastName.trim()}`.trim()
      const res = await fetch('/api/v1/auth/me', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
        body: JSON.stringify({ full_name: fullName || null }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed to update profile')
      await refreshUser()
      setProfileOk(true)
      setTimeout(() => setProfileOk(false), 3000)
    } catch (err: any) {
      setProfileError(err.message)
    } finally {
      setProfileSaving(false)
    }
  }

  async function loadUsers() {
    const res = await fetch('/api/v1/auth/users')
    if (res.ok) setUserList(await res.json())
  }

  async function handleCreateUser(e: React.FormEvent) {
    e.preventDefault()
    setUserError('')
    setUserSaving(true)
    try {
      const res = await fetch('/api/v1/auth/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: newUsername.trim(),
          password: newPassword,
          role: newRole,
          full_name: `${newFirstName.trim()} ${newLastName.trim()}`.trim() || undefined,
        }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed to create user')
      setNewUsername('')
      setNewPassword('')
      setNewFirstName('')
      setNewLastName('')
      loadUsers()
    } catch (err: any) {
      setUserError(err.message)
    } finally {
      setUserSaving(false)
    }
  }

  async function handleDeleteUser(id: string) {
    await fetch(`/api/v1/auth/users/${id}`, { method: 'DELETE' })
    loadUsers()
  }

  async function handleChangePassword(e: React.FormEvent) {
    e.preventDefault()
    setPwError('')
    setPwOk(false)
    setPwSaving(true)
    try {
      const res = await fetch('/api/v1/auth/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: curPw, new_password: newPw }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed to change password')
      setCurPw('')
      setNewPw('')
      setPwOk(true)
    } catch (err: any) {
      setPwError(err.message)
    } finally {
      setPwSaving(false)
    }
  }

  async function loadAiConfig() {
    try {
      const res = await fetch('/api/v1/ai/config')
      if (res.ok) setAiConfig(await res.json())
    } catch { /* backend offline */ }
  }

  async function saveAiConfig() {
    setAiSaving(true)
    try {
      await fetch('/api/v1/ai/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(aiConfig),
      })
    } finally {
      setAiSaving(false)
    }
  }

  async function testAiConnection() {
    setAiTesting(true)
    setAiStatus(null)
    setAiModels([])
    try {
      // Save first so status check uses new endpoint
      await fetch('/api/v1/ai/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(aiConfig),
      })
      const [statusRes, modelsRes] = await Promise.all([
        fetch('/api/v1/ai/status'),
        fetch('/api/v1/ai/models'),
      ])
      if (statusRes.ok) setAiStatus(await statusRes.json())
      if (modelsRes.ok) {
        const data = await modelsRes.json()
        setAiModels(data.models || [])
        // Auto-select first model if none selected
        if (!aiConfig.model && data.models?.length > 0) {
          setAiConfig(c => ({ ...c, model: data.models[0] }))
        }
      }
    } finally {
      setAiTesting(false)
    }
  }

  function copyText(text: string, key: string) {
    navigator.clipboard.writeText(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 2000)
  }

  const available = Object.entries(toolStatus).filter(([, v]) => v.available)
  const missing = Object.entries(toolStatus).filter(([, v]) => !v.available)

  const mgr = hostInfo?.pkg_manager || 'apt'
  const missingNames = missing.map(([name]) => name)
  // Exclude 'go' from bulk install (it's a runtime, handled separately)
  const pkgMgrMissing = missingNames.filter(n => n !== 'go' && TOOL_PKGS[n]?.[mgr])
  const goRuntimeMissing = !toolStatus['go']?.available && toolStatus['go'] !== undefined
  // Tools that install via `go install` but Go itself is missing
  const blockedByGo = missing.filter(([name]) => {
    const hint = toolStatus[name]?.install_hint
    return hint?.startsWith('go install') && goRuntimeMissing
  })
  const bulkInstallCmd = getBulkInstallCmd(pkgMgrMissing, hostInfo)

  return (
    <div className="p-8 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-slate-400 text-sm mt-1">Tool detection, scan profiles, and platform configuration</p>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 glass rounded-lg p-1 w-fit">
        <button
          onClick={() => setActiveTab('tools')}
          className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${activeTab === 'tools' ? 'bg-blue-600 text-white shadow-glow-blue' : 'text-slate-400 hover:text-slate-200'}`}
        >
          Tools ({available.length}/{Object.keys(toolStatus).length})
        </button>
        <button
          onClick={() => setActiveTab('profiles')}
          className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${activeTab === 'profiles' ? 'bg-blue-600 text-white shadow-glow-blue' : 'text-slate-400 hover:text-slate-200'}`}
        >
          Profiles ({profiles.length})
        </button>
        <button
          onClick={() => setActiveTab('ai')}
          className={`flex items-center gap-1.5 px-4 py-1.5 rounded text-sm font-medium transition-colors ${activeTab === 'ai' ? 'bg-blue-600 text-white shadow-glow-blue' : 'text-slate-400 hover:text-slate-200'}`}
        >
          <Brain size={13} /> AI
        </button>
        <button
          onClick={() => setActiveTab('users')}
          className={`flex items-center gap-1.5 px-4 py-1.5 rounded text-sm font-medium transition-colors ${activeTab === 'users' ? 'bg-blue-600 text-white shadow-glow-blue' : 'text-slate-400 hover:text-slate-200'}`}
        >
          <Users size={13} /> Users
        </button>
        <button
          onClick={() => setActiveTab('autoprobe')}
          className={`flex items-center gap-1.5 px-4 py-1.5 rounded text-sm font-medium transition-colors ${activeTab === 'autoprobe' ? 'bg-blue-600 text-white shadow-glow-blue' : 'text-slate-400 hover:text-slate-200'}`}
        >
          <Zap size={13} /> Auto-Probe
          {probeEnabled && <span className="w-1.5 h-1.5 rounded-full bg-green-400 ml-0.5" style={{ boxShadow: '0 0 4px rgba(34,197,94,0.8)' }} />}
        </button>
        <button
          onClick={() => setActiveTab('appearance')}
          className={`flex items-center gap-1.5 px-4 py-1.5 rounded text-sm font-medium transition-colors ${activeTab === 'appearance' ? 'bg-blue-600 text-white shadow-glow-blue' : 'text-slate-400 hover:text-slate-200'}`}
        >
          <Palette size={13} /> Appearance
        </button>
        <button
          onClick={() => setActiveTab('webhooks')}
          className={`flex items-center gap-1.5 px-4 py-1.5 rounded text-sm font-medium transition-colors ${activeTab === 'webhooks' ? 'bg-blue-600 text-white shadow-glow-blue' : 'text-slate-400 hover:text-slate-200'}`}
        >
          <Zap size={13} /> Webhooks
        </button>
      </div>

      {activeTab === 'tools' && (
        <div className="space-y-6">
          {/* Refresh */}
          <button
            onClick={loadTools}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 rounded-lg glass glass-hover text-sm text-slate-300 transition-all"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin text-cyan-400' : ''} />
            {loading ? 'Detecting...' : 'Refresh Tool Detection'}
          </button>

          {/* Quick Install Banner */}
          {missing.length > 0 && (
            <div className="rounded-xl p-5 space-y-4 border border-amber-700/30" style={{ background: 'rgba(120,53,15,0.15)' }}>
              <div className="flex items-center gap-2 flex-wrap">
                <Package size={16} className="text-amber-400" />
                <h3 className="text-sm font-semibold text-amber-300">{missing.length} tools not installed</h3>
                {hostInfo && (
                  <span className="ml-auto text-xs text-slate-500 font-mono px-2 py-0.5 rounded border border-slate-700/40" style={{ background: '#0d1520' }}>
                    {hostInfo.distro_name} · {PKG_MANAGER_LABELS[mgr] || mgr}
                  </span>
                )}
              </div>

              {bulkInstallCmd && (
                <div>
                  <div className="text-xs text-slate-400 mb-2">
                    Install all {pkgMgrMissing.length} missing tools at once:
                  </div>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 rounded px-3 py-2 text-xs font-mono text-slate-300 overflow-x-auto border border-cyan-900/20" style={{ background: '#05080d' }}>
                      {bulkInstallCmd}
                    </code>
                    <button
                      onClick={() => copyText(bulkInstallCmd, 'bulk-all')}
                      className="flex-shrink-0 flex items-center gap-1.5 px-3 py-2 rounded text-xs text-amber-300 transition-colors border border-amber-700/30 hover:border-amber-600/50"
                      style={{ background: 'rgba(120,53,15,0.3)' }}
                    >
                      {copied === 'bulk-all' ? <Check size={12} /> : <Copy size={12} />}
                      {copied === 'bulk-all' ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                </div>
              )}

              {goRuntimeMissing && blockedByGo.length > 0 && (
                <div className="rounded-lg p-3 space-y-2 border border-amber-700/40" style={{ background: 'rgba(120,53,15,0.2)' }}>
                  <div className="text-xs text-amber-300 font-medium">
                    Go Runtime required for: {blockedByGo.map(([n]) => toolStatus[n]?.label || n).join(', ')}
                  </div>
                  <button
                    onClick={() => startInstall('go')}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs bg-amber-600/20 text-amber-300 border border-amber-600/30 hover:bg-amber-600/30 transition-colors"
                  >
                    <Download size={11} /> Install Go Runtime
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Tool Grid */}
          <div>
            <h3 className="text-sm font-semibold text-slate-300 mb-3">
              All Tools — {available.length} available, {missing.length} missing
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {Object.entries(toolStatus).map(([name, info]) => {
                const isGoRuntime = name === 'go'
                const needsGo = !isGoRuntime && !info.available && info.install_hint?.startsWith('go install')
                const goMissing = needsGo && toolStatus['go'] && !toolStatus['go'].available
                return (
                <div
                  key={name}
                  className={`glass glass-hover rounded-xl p-4 border-l-4 transition-all ${
                    info.available ? 'border-l-green-500' : isGoRuntime ? 'border-l-amber-400' : 'border-l-red-500'
                  }`}
                >
                  <div className="flex items-center gap-3 mb-2">
                    {info.available
                      ? <CheckCircle size={16} className="text-green-500 flex-shrink-0" style={{ filter: 'drop-shadow(0 0 4px rgba(34,197,94,0.5))' }} />
                      : <XCircle size={16} className={`flex-shrink-0 ${isGoRuntime ? 'text-amber-400' : 'text-red-500'}`} style={{ filter: isGoRuntime ? 'drop-shadow(0 0 4px rgba(251,191,36,0.5))' : 'drop-shadow(0 0 4px rgba(239,68,68,0.5))' }} />
                    }
                    <span className="font-mono text-sm font-semibold text-slate-200">{info.label || name}</span>
                    <div className="ml-auto flex items-center gap-1.5">
                      {isGoRuntime && !info.available && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-900/30 text-amber-400 border border-amber-700/30">runtime</span>
                      )}
                      {TOOL_INFO[name] && (
                        <button
                          onClick={() => setInfoTool(name)}
                          className="text-slate-500 hover:text-cyan-400 transition-colors"
                          title="About this tool"
                        >
                          <Info size={14} />
                        </button>
                      )}
                    </div>
                  </div>
                  {info.available ? (
                    <div className="space-y-1">
                      {isGoRuntime && (
                        <div className="text-xs text-slate-500">Required by subfinder, ffuf, gobuster</div>
                      )}
                      {info.path && (
                        <div className="text-xs font-mono text-slate-400 truncate">{info.path}</div>
                      )}
                      {info.version && (
                        <div className="text-xs text-slate-500 truncate">{info.version.slice(0, 60)}</div>
                      )}
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {isGoRuntime
                        ? <div className="text-xs text-amber-400">Required by subfinder, ffuf, gobuster</div>
                        : <div className="text-xs text-red-400">Not installed</div>
                      }
                      {goMissing && (
                        <div className="text-xs text-amber-400/80">⚠ Install Go Runtime first</div>
                      )}
                      {info.install_hint && !goMissing && (
                        <div className="flex items-center gap-2">
                          <code className="flex-1 text-xs font-mono text-slate-400 truncate" title={info.install_hint}>
                            {info.install_hint}
                          </code>
                          <button
                            onClick={() => copyText(info.install_hint!, `tool-${name}`)}
                            className="flex-shrink-0 text-slate-500 hover:text-slate-300"
                          >
                            {copied === `tool-${name}` ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
                          </button>
                        </div>
                      )}
                      <div className="flex items-center gap-2 flex-wrap">
                        {!goMissing && (
                          <button
                            onClick={() => startInstall(name)}
                            className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs border transition-colors ${
                              isGoRuntime
                                ? 'bg-amber-600/15 text-amber-400 border-amber-600/25 hover:bg-amber-600/25'
                                : 'bg-cyan-600/15 text-cyan-400 border-cyan-600/25 hover:bg-cyan-600/25'
                            }`}
                          >
                            <Download size={11} /> Install
                          </button>
                        )}
                        {info.url && (
                          <a
                            href={info.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs text-slate-500 hover:text-cyan-400 underline transition-colors"
                          >
                            Instructions ↗
                          </a>
                        )}
                      </div>
                    </div>
                  )}
                </div>
                )
              })}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'autoprobe' && (
        <div className="space-y-6 max-w-2xl">
          {probeLoading ? (
            <div className="flex items-center gap-2 text-slate-400 text-sm">
              <Loader size={14} className="animate-spin" /> Loading...
            </div>
          ) : (
            <>
              <p className="text-sm text-slate-400">
                When enabled, Seraph automatically runs a lightweight recon against any newly added target.
                Results appear in the target's scan history within minutes.
              </p>

              {/* Master toggle */}
              <div className="glass rounded-xl p-5 flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <Zap size={15} className={probeEnabled ? 'text-green-400' : 'text-slate-500'} />
                    <span className="text-sm font-semibold text-slate-200">Auto-Probe</span>
                    <span className={`text-xs px-2 py-0.5 rounded font-medium ${probeEnabled ? 'text-green-300 border border-green-700/40' : 'text-slate-500 border border-slate-700/40'}`}
                      style={{ background: probeEnabled ? 'rgba(34,197,94,0.1)' : 'rgba(100,116,139,0.1)' }}>
                      {probeEnabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 mt-1">Fires automatically on every new target</p>
                </div>
                <button
                  onClick={() => setProbeEnabled(v => !v)}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${probeEnabled ? 'bg-green-500' : 'bg-slate-700'}`}
                >
                  <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${probeEnabled ? 'translate-x-6' : 'translate-x-1'}`} />
                </button>
              </div>

              {/* Tool selection */}
              <div className="space-y-3">
                <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Tools to Run</label>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { name: 'whois',        label: 'whois',        desc: 'Domain registration & ASN info',                          always: true  },
                    { name: 'rustscan',     label: 'rustscan',     desc: 'Full 65k port scan — feeds open ports to nmap (faster)',   always: false },
                    { name: 'nmap',         label: 'nmap',         desc: 'Service & version detection',                             always: true  },
                    { name: 'nikto',        label: 'nikto',        desc: 'Web server scan (port 80/443)',                           always: false },
                    { name: 'testssl',      label: 'testssl',      desc: 'TLS/SSL audit (port 443)',                                always: false },
                    { name: 'nuclei',       label: 'nuclei',       desc: 'Template-based vuln scan (port 80/443/8080)',             always: false },
                    { name: 'feroxbuster',  label: 'feroxbuster',  desc: 'Directory fuzzing (port 80/8080)',                        always: false },
                    { name: 'searchsploit', label: 'searchsploit', desc: 'Exploit-DB lookup (runs last)',                          always: false },
                  ].map(tool => {
                    const checked = probeTools.includes(tool.name)
                    const available = Object.keys(toolStatus).includes(tool.name) ? toolStatus[tool.name]?.available : null
                    return (
                      <button
                        key={tool.name}
                        onClick={() => toggleProbeTool(tool.name)}
                        className={`text-left rounded-xl p-4 border transition-all ${checked ? 'border-cyan-500/40 bg-cyan-500/5' : 'border-cyan-900/20 glass'}`}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <div className={`w-4 h-4 rounded border flex items-center justify-center flex-shrink-0 transition-colors ${checked ? 'bg-cyan-500 border-cyan-500' : 'border-slate-600'}`}>
                            {checked && <Check size={10} className="text-white" />}
                          </div>
                          <span className="font-mono text-sm font-semibold text-slate-200">{tool.label}</span>
                          {available === false && (
                            <span className="text-[10px] text-red-400">not installed</span>
                          )}
                          {!tool.always && (
                            <span className="text-[10px] text-slate-500 ml-auto">conditional</span>
                          )}
                        </div>
                        <p className="text-xs text-slate-500 pl-6">{tool.desc}</p>
                      </button>
                    )
                  })}
                </div>
              </div>

              {/* Intensity */}
              <div className="space-y-3">
                <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Gauge size={12} /> Intensity
                </label>
                <div className="flex gap-2">
                  {([
                    { value: 'quick', label: 'Quick', desc: '2 min · serial (low noise)' },
                    { value: 'standard', label: 'Standard', desc: '5 min · 2 tools parallel' },
                    { value: 'deep', label: 'Deep', desc: '10 min · fully parallel' },
                  ] as const).map(opt => (
                    <button
                      key={opt.value}
                      onClick={() => setProbeIntensity(opt.value)}
                      className={`flex-1 rounded-xl px-3 py-3 text-center border transition-all ${probeIntensity === opt.value ? 'border-cyan-500/50 bg-cyan-500/10' : 'border-cyan-900/20 glass'}`}
                    >
                      <div className={`text-sm font-semibold ${probeIntensity === opt.value ? 'text-cyan-300' : 'text-slate-300'}`}>{opt.label}</div>
                      <div className="text-[10px] text-slate-500 mt-0.5">{opt.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              <button
                onClick={saveProbeConfig}
                disabled={probeSaving}
                className="flex items-center gap-2 px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-sm text-white font-medium transition-all hover:shadow-glow-blue"
              >
                {probeSaving ? <Loader size={14} className="animate-spin" /> : <Save size={14} />}
                Save Auto-Probe Settings
              </button>
            </>
          )}
        </div>
      )}

      {activeTab === 'ai' && (
        <div className="space-y-6 max-w-2xl">
          <p className="text-sm text-slate-400">
            Connect Seraph to a local LLM (Ollama or LMStudio) for AI-generated report narratives.
            Both expose an OpenAI-compatible API — no internet or API key required.
          </p>

          {/* Provider presets */}
          <div className="space-y-3">
            <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Provider Preset</label>
            <div className="flex gap-2">
              {[
                { label: 'Ollama', value: 'ollama', url: 'http://localhost:11434' },
                { label: 'LMStudio', value: 'lmstudio', url: 'http://localhost:1234' },
                { label: 'Custom', value: 'custom', url: '' },
              ].map(p => (
                <button
                  key={p.value}
                  onClick={() => setAiConfig(c => ({ ...c, provider: p.value, ...(p.url ? { endpoint: p.url } : {}) }))}
                  className={`px-4 py-2 rounded-lg text-sm font-medium border transition-colors ${
                    aiConfig.provider === p.value
                      ? 'border-cyan-500/60 text-cyan-300 bg-cyan-500/10'
                      : 'border-cyan-900/20 text-slate-400 hover:text-slate-200 glass'
                  }`}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          {/* Endpoint URL */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">API Endpoint</label>
            <input
              type="text"
              value={aiConfig.endpoint}
              onChange={e => setAiConfig(c => ({ ...c, endpoint: e.target.value, provider: 'custom' }))}
              placeholder="http://localhost:11434"
              className="w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none font-mono"
              style={{ background: '#090d14' }}
            />
            <p className="text-xs text-slate-500">Ollama: port 11434 · LMStudio: port 1234 · Both expose /v1/models and /v1/chat/completions</p>
          </div>

          {/* Connection test + status */}
          <div className="flex items-center gap-3">
            <button
              onClick={testAiConnection}
              disabled={aiTesting}
              className="flex items-center gap-2 px-4 py-2 rounded-lg glass glass-hover text-sm text-slate-300 disabled:opacity-50 transition-all"
            >
              {aiTesting ? <Loader size={14} className="animate-spin text-cyan-400" /> : <Wifi size={14} />}
              Test Connection
            </button>
            {aiStatus && (
              <div className={`flex items-center gap-2 text-sm ${aiStatus.online ? 'text-green-400' : 'text-red-400'}`}>
                {aiStatus.online
                  ? <><CheckCircle size={14} /> Connected · {aiStatus.model_count} model{aiStatus.model_count !== 1 ? 's' : ''} available</>
                  : <><WifiOff size={14} /> Offline — {aiStatus.error}</>
                }
              </div>
            )}
          </div>

          {/* Model selector */}
          {aiModels.length > 0 && (
            <div className="space-y-2">
              <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Model</label>
              <select
                value={aiConfig.model}
                onChange={e => setAiConfig(c => ({ ...c, model: e.target.value }))}
                className="w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                style={{ background: '#090d14' }}
              >
                <option value="">Select a model...</option>
                {aiModels.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
            </div>
          )}

          {/* Manual model input (when models not loaded yet) */}
          {aiModels.length === 0 && (
            <div className="space-y-2">
              <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Model Name</label>
              <input
                type="text"
                value={aiConfig.model}
                onChange={e => setAiConfig(c => ({ ...c, model: e.target.value }))}
                placeholder="e.g. llama3.2, mistral, deepseek-r1:8b"
                className="w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none font-mono"
                style={{ background: '#090d14' }}
              />
              <p className="text-xs text-slate-500">Click "Test Connection" to auto-populate models from the endpoint.</p>
            </div>
          )}

          {/* Generation parameters */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Generation Parameters</label>
              <span className="text-xs text-slate-500">Leave blank to use model defaults</span>
            </div>
            <div className="grid grid-cols-2 gap-3">
              {([
                { key: 'temperature', label: 'Temperature', min: 0, max: 2, step: 0.01, placeholder: 'e.g. 1.0' },
                { key: 'top_p', label: 'Top P', min: 0, max: 1, step: 0.01, placeholder: 'e.g. 0.95' },
                { key: 'top_k', label: 'Top K', min: 0, max: 200, step: 1, placeholder: 'e.g. 20' },
                { key: 'min_p', label: 'Min P', min: 0, max: 1, step: 0.01, placeholder: 'e.g. 0.0' },
                { key: 'presence_penalty', label: 'Presence Penalty', min: -2, max: 2, step: 0.1, placeholder: 'e.g. 1.5' },
                { key: 'repetition_penalty', label: 'Repetition Penalty', min: 0.1, max: 2, step: 0.01, placeholder: 'e.g. 1.0' },
                { key: 'timeout', label: 'Timeout (seconds)', min: 30, max: 1800, step: 30, placeholder: 'default: 300' },
              ] as { key: keyof AIConfig; label: string; min: number; max: number; step: number; placeholder: string }[]).map(({ key, label, min, max, step, placeholder }) => (
                <div key={key} className="space-y-1">
                  <div className="flex items-center justify-between">
                    <label className="text-xs text-slate-400">{label}</label>
                    {aiConfig[key] !== null && (
                      <button
                        onClick={() => setAiConfig(c => ({ ...c, [key]: null }))}
                        className="text-[10px] text-slate-500 hover:text-red-400 transition-colors"
                      >reset</button>
                    )}
                  </div>
                  <input
                    type="number"
                    min={min}
                    max={max}
                    step={step}
                    value={aiConfig[key] ?? ''}
                    onChange={e => setAiConfig(c => ({ ...c, [key]: e.target.value === '' ? null : Number(e.target.value) }))}
                    placeholder={placeholder}
                    className="w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none font-mono"
                    style={{ background: '#090d14' }}
                  />
                </div>
              ))}
            </div>
          </div>

          {/* Save */}
          <button
            onClick={saveAiConfig}
            disabled={aiSaving}
            className="flex items-center gap-2 px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-sm text-white font-medium transition-all hover:shadow-glow-blue"
          >
            {aiSaving ? <Loader size={14} className="animate-spin" /> : <Save size={14} />}
            Save AI Settings
          </button>
        </div>
      )}

      {activeTab === 'users' && (
        <div className="space-y-8 max-w-2xl">
          {/* Edit own profile */}
          <div className="glass rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2 text-slate-300">
              <UserPlus size={15} className="text-cyan-400" />
              <h3 className="text-sm font-semibold">My Profile</h3>
              <span className="text-xs text-slate-500 font-mono ml-1">@{currentUser?.username}</span>
            </div>
            <form onSubmit={handleUpdateProfile} className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs text-slate-400">First Name</label>
                  <input
                    type="text"
                    value={profileFirstName}
                    onChange={e => setProfileFirstName(e.target.value)}
                    placeholder="Jane"
                    className="w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                    style={{ background: '#090d14' }}
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs text-slate-400">Last Name</label>
                  <input
                    type="text"
                    value={profileLastName}
                    onChange={e => setProfileLastName(e.target.value)}
                    placeholder="Doe"
                    className="w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                    style={{ background: '#090d14' }}
                  />
                </div>
              </div>
              {profileError && <p className="text-xs text-red-400">{profileError}</p>}
              {profileOk && <p className="text-xs text-green-400">Profile updated.</p>}
              <button
                type="submit"
                disabled={profileSaving}
                className="flex items-center gap-2 px-4 py-2 rounded-lg glass glass-hover text-sm text-slate-300 disabled:opacity-50"
              >
                {profileSaving ? <Loader size={13} className="animate-spin" /> : <Save size={13} />}
                Save Profile
              </button>
            </form>
          </div>

          {/* Change own password */}
          <div className="glass rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2 text-slate-300">
              <KeyRound size={15} className="text-cyan-400" />
              <h3 className="text-sm font-semibold">Change Password</h3>
            </div>
            <form onSubmit={handleChangePassword} className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs text-slate-400">Current password</label>
                  <input
                    type="password"
                    value={curPw}
                    onChange={e => setCurPw(e.target.value)}
                    required
                    className="w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                    style={{ background: '#090d14' }}
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs text-slate-400">New password (min 8)</label>
                  <input
                    type="password"
                    value={newPw}
                    onChange={e => setNewPw(e.target.value)}
                    required
                    className="w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                    style={{ background: '#090d14' }}
                  />
                </div>
              </div>
              {pwError && <p className="text-xs text-red-400">{pwError}</p>}
              {pwOk && <p className="text-xs text-green-400">Password changed successfully.</p>}
              <button
                type="submit"
                disabled={pwSaving}
                className="flex items-center gap-2 px-4 py-2 rounded-lg glass glass-hover text-sm text-slate-300 disabled:opacity-50"
              >
                {pwSaving ? <Loader size={13} className="animate-spin" /> : <Save size={13} />}
                Update Password
              </button>
            </form>
          </div>

          {/* Passkeys */}
          <div className="glass rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2 text-slate-300">
              <Fingerprint size={15} className="text-cyan-400" />
              <h3 className="text-sm font-semibold">Passkeys</h3>
              <span className="text-xs text-slate-500 ml-auto">iCloud Keychain, Touch ID, Face ID, YubiKey…</span>
            </div>

            {/* Registered passkeys list */}
            {passkeys.length > 0 && (
              <div className="space-y-2">
                {passkeys.map(pk => (
                  <div key={pk.id} className="flex items-center gap-3 px-3 py-2.5 rounded-lg border border-cyan-900/15" style={{ background: '#0d1520' }}>
                    <Fingerprint size={14} className="text-cyan-500 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <span className="text-sm text-slate-200">{pk.name}</span>
                      <span className="ml-2 text-xs text-slate-500">added {new Date(pk.created_at).toLocaleDateString()}</span>
                    </div>
                    <button
                      onClick={() => handleDeletePasskey(pk.id)}
                      className="text-slate-600 hover:text-red-400 transition-colors"
                      title="Remove passkey"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                ))}
              </div>
            )}

            {/* Register new passkey */}
            <div className="space-y-3">
              <div className="space-y-1">
                <label className="text-xs text-slate-400">Passkey name (optional)</label>
                <input
                  type="text"
                  value={newPasskeyName}
                  onChange={e => setNewPasskeyName(e.target.value)}
                  placeholder="iCloud Keychain"
                  className="w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                  style={{ background: '#090d14' }}
                />
              </div>
              {passkeyError && <p className="text-xs text-red-400">{passkeyError}</p>}
              <button
                type="button"
                onClick={handleRegisterPasskey}
                disabled={passkeyRegLoading}
                className="flex items-center gap-2 px-4 py-2 rounded-lg glass glass-hover text-sm text-slate-300 disabled:opacity-50"
              >
                {passkeyRegLoading ? <Loader size={13} className="animate-spin" /> : <Fingerprint size={13} />}
                {passkeys.length > 0 ? 'Add Another Passkey' : 'Register Passkey'}
              </button>
            </div>
          </div>

          {/* User management (admin only) */}
          {currentUser?.role === 'admin' ? (
            <>
              {/* Create user */}
              <div className="glass rounded-xl p-5 space-y-4">
                <div className="flex items-center gap-2 text-slate-300">
                  <UserPlus size={15} className="text-cyan-400" />
                  <h3 className="text-sm font-semibold">Create User</h3>
                </div>
                <form onSubmit={handleCreateUser} className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label className="text-xs text-slate-400">First Name</label>
                      <input
                        type="text"
                        value={newFirstName}
                        onChange={e => setNewFirstName(e.target.value)}
                        required
                        placeholder="Jane"
                        className="w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                        style={{ background: '#090d14' }}
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="text-xs text-slate-400">Last Name</label>
                      <input
                        type="text"
                        value={newLastName}
                        onChange={e => setNewLastName(e.target.value)}
                        required
                        placeholder="Doe"
                        className="w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                        style={{ background: '#090d14' }}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-3">
                    <div className="space-y-1">
                      <label className="text-xs text-slate-400">Username</label>
                      <input
                        type="text"
                        value={newUsername}
                        onChange={e => setNewUsername(e.target.value)}
                        required
                        className="w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                        style={{ background: '#090d14' }}
                      />
                    </div>
                    <div className="space-y-1 relative">
                      <label className="text-xs text-slate-400">Password</label>
                      <input
                        type={showNewPw ? 'text' : 'password'}
                        value={newPassword}
                        onChange={e => setNewPassword(e.target.value)}
                        required
                        className="w-full rounded-lg px-3 py-2 pr-8 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                        style={{ background: '#090d14' }}
                      />
                      <button type="button" onClick={() => setShowNewPw(v => !v)}
                        className="absolute right-2 top-7 text-slate-500 hover:text-slate-300">
                        {showNewPw ? <EyeOff size={12} /> : <Eye size={12} />}
                      </button>
                    </div>
                    <div className="space-y-1">
                      <label className="text-xs text-slate-400">Role</label>
                      <select
                        value={newRole}
                        onChange={e => setNewRole(e.target.value as 'admin' | 'analyst')}
                        className="w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:outline-none"
                        style={{ background: '#090d14' }}
                      >
                        <option value="analyst">Analyst</option>
                        <option value="admin">Admin</option>
                      </select>
                    </div>
                  </div>
                  {userError && <p className="text-xs text-red-400">{userError}</p>}
                  <button
                    type="submit"
                    disabled={userSaving}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-sm text-white transition-all"
                  >
                    {userSaving ? <Loader size={13} className="animate-spin" /> : <UserPlus size={13} />}
                    Create User
                  </button>
                </form>
              </div>

              {/* User list */}
              <div className="glass rounded-xl p-5 space-y-3">
                <div className="flex items-center gap-2 text-slate-300">
                  <Users size={15} className="text-cyan-400" />
                  <h3 className="text-sm font-semibold">All Users ({userList.length})</h3>
                </div>
                {userList.map(u => (
                  <div key={u.id} className="flex items-center gap-3 px-4 py-3 rounded-lg border border-cyan-900/10" style={{ background: '#0d1520' }}>
                    <div className="w-8 h-8 rounded-full flex items-center justify-center shrink-0"
                      style={{ background: 'rgba(6,182,212,0.1)', border: '1px solid rgba(6,182,212,0.2)' }}>
                      <span className="text-xs font-bold text-cyan-400">{(u.full_name || u.username)[0].toUpperCase()}</span>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-slate-200">{u.full_name || u.username}</span>
                        {u.full_name && <span className="text-xs text-slate-500 font-mono">@{u.username}</span>}
                        {u.id === currentUser?.id && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded text-cyan-400 border border-cyan-500/30" style={{ background: 'rgba(6,182,212,0.1)' }}>you</span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded capitalize ${u.role === 'admin' ? 'text-amber-400 border border-amber-500/30' : 'text-slate-400 border border-slate-600/30'}`}
                          style={{ background: u.role === 'admin' ? 'rgba(245,158,11,0.1)' : 'rgba(100,116,139,0.1)' }}>
                          <ShieldCheck size={9} className="inline mr-0.5" />{u.role}
                        </span>
                        <span className="text-[10px] text-slate-500">joined {new Date(u.created_at).toLocaleDateString()}</span>
                      </div>
                    </div>
                    {u.id !== currentUser?.id && (
                      <button
                        onClick={() => handleDeleteUser(u.id)}
                        className="text-slate-500 hover:text-red-400 transition-colors flex-shrink-0"
                        title="Delete user"
                      >
                        <Trash2 size={14} />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="text-sm text-slate-400 glass rounded-xl p-5">
              User management is only available to administrators.
            </div>
          )}
        </div>
      )}

      {activeTab === 'profiles' && (
        <div className="space-y-4">
          <p className="text-sm text-slate-400">
            Scan profiles save your preferred audit configurations for quick reuse in the Audit Builder.
          </p>
          {profiles.length === 0 ? (
            <div className="text-center text-slate-400 py-12 glass rounded-xl">
              <Terminal size={36} className="mx-auto mb-3 opacity-30 text-cyan-500" />
              <p className="text-sm">No saved profiles yet.</p>
              <p className="text-xs mt-1 text-slate-500">Generate a script in Audit Builder and save the configuration as a profile.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {profiles.map(profile => {
                let cats: any[] = []
                try { cats = JSON.parse(profile.scan_categories) } catch {}
                return (
                  <div key={profile.id} className="glass glass-hover rounded-xl p-4 flex items-center gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-semibold text-slate-200">{profile.name}</div>
                      {profile.description && (
                        <div className="text-xs text-slate-400 mt-0.5">{profile.description}</div>
                      )}
                      <div className="flex gap-1 mt-2 flex-wrap">
                        {cats.map((c: any) => (
                          <span key={c.category_id} className="text-xs px-2 py-0.5 rounded text-slate-400 border border-cyan-900/20" style={{ background: '#0d1520' }}>
                            {c.category_id?.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>
                    <button
                      onClick={() => deleteProfile(profile.id)}
                      className="text-slate-500 hover:text-red-400 transition-colors flex-shrink-0"
                      title="Delete profile"
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
      {/* ── Appearance ─────────────────────────────────────────────────── */}
      {activeTab === 'appearance' && (
        <div className="space-y-6 max-w-2xl">
          <div className="glass rounded-xl p-6 space-y-5">
            <div className="flex items-center gap-2">
              <Monitor size={16} className="text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">Color Theme</h3>
            </div>
            <p className="text-xs text-slate-400">
              Choose a visual theme for the platform. Functional colors (severity indicators, status badges, terminal output) are preserved in both themes.
            </p>

            <div className="grid grid-cols-2 gap-4">
              {/* Cyber Blue */}
              <button
                onClick={() => setTheme('blue')}
                className={`rounded-xl border-2 overflow-hidden text-left transition-all ${
                  theme === 'blue'
                    ? 'border-cyan-500/70 shadow-glow-cyan'
                    : 'border-slate-700/40 hover:border-slate-600/60'
                }`}
              >
                {/* Mini preview */}
                <div className="h-28 relative" style={{ background: '#05080d' }}>
                  {/* Dot grid */}
                  <div className="absolute inset-0" style={{
                    backgroundImage: 'radial-gradient(rgba(6,182,212,0.06) 1px, transparent 1px)',
                    backgroundSize: '12px 12px',
                  }} />
                  {/* Sidebar strip */}
                  <div className="absolute left-0 top-0 bottom-0 w-10" style={{ background: '#090d14', borderRight: '1px solid rgba(6,182,212,0.15)' }}>
                    {[0,1,2,3].map(i => (
                      <div key={i} className="mx-1.5 my-1 h-1.5 rounded" style={{ background: i === 0 ? 'rgba(6,182,212,0.4)' : 'rgba(148,163,184,0.15)' }} />
                    ))}
                  </div>
                  {/* Cards */}
                  <div className="absolute left-12 top-2 right-2 space-y-1.5">
                    <div className="h-5 rounded" style={{ background: 'rgba(9,13,20,0.8)', border: '1px solid rgba(6,182,212,0.12)' }} />
                    <div className="flex gap-1">
                      <div className="flex-1 h-12 rounded" style={{ background: 'rgba(9,13,20,0.8)', border: '1px solid rgba(6,182,212,0.12)' }}>
                        <div className="h-1.5 w-1/2 m-1.5 rounded" style={{ background: '#06b6d4', opacity: 0.5 }} />
                      </div>
                      <div className="flex-1 h-12 rounded" style={{ background: 'rgba(9,13,20,0.8)', border: '1px solid rgba(6,182,212,0.12)' }}>
                        <div className="h-1.5 w-1/3 m-1.5 rounded" style={{ background: '#3b82f6', opacity: 0.5 }} />
                      </div>
                    </div>
                  </div>
                </div>
                {/* Label */}
                <div className={`px-4 py-3 flex items-center justify-between ${theme === 'blue' ? 'bg-cyan-950/30' : ''}`} style={{ background: '#090d14' }}>
                  <div>
                    <div className="text-sm font-semibold text-white">Cyber Blue</div>
                    <div className="text-[10px] text-slate-400">Cyan + dark blue accents</div>
                  </div>
                  {theme === 'blue' && <CheckCircle size={16} className="text-cyan-400 shrink-0" />}
                </div>
              </button>

              {/* Monochrome */}
              <button
                onClick={() => setTheme('mono')}
                className={`rounded-xl border-2 overflow-hidden text-left transition-all ${
                  theme === 'mono'
                    ? 'border-white/30 shadow-[0_0_12px_rgba(255,255,255,0.08)]'
                    : 'border-slate-700/40 hover:border-slate-600/60'
                }`}
              >
                {/* Mini preview */}
                <div className="h-28 relative" style={{ background: '#080808' }}>
                  {/* Dot grid */}
                  <div className="absolute inset-0" style={{
                    backgroundImage: 'radial-gradient(rgba(255,255,255,0.025) 1px, transparent 1px)',
                    backgroundSize: '12px 12px',
                  }} />
                  {/* Sidebar strip */}
                  <div className="absolute left-0 top-0 bottom-0 w-10" style={{ background: '#111', borderRight: '1px solid rgba(255,255,255,0.08)' }}>
                    {[0,1,2,3].map(i => (
                      <div key={i} className="mx-1.5 my-1 h-1.5 rounded" style={{ background: i === 0 ? 'rgba(212,212,216,0.6)' : 'rgba(148,163,184,0.12)' }} />
                    ))}
                  </div>
                  {/* Cards */}
                  <div className="absolute left-12 top-2 right-2 space-y-1.5">
                    <div className="h-5 rounded" style={{ background: 'rgba(17,17,17,0.88)', border: '1px solid rgba(255,255,255,0.07)' }} />
                    <div className="flex gap-1">
                      <div className="flex-1 h-12 rounded" style={{ background: 'rgba(17,17,17,0.88)', border: '1px solid rgba(255,255,255,0.07)' }}>
                        <div className="h-1.5 w-1/2 m-1.5 rounded" style={{ background: '#d4d4d8', opacity: 0.4 }} />
                      </div>
                      <div className="flex-1 h-12 rounded" style={{ background: 'rgba(17,17,17,0.88)', border: '1px solid rgba(255,255,255,0.07)' }}>
                        <div className="h-1.5 w-1/3 m-1.5 rounded" style={{ background: '#a1a1aa', opacity: 0.4 }} />
                      </div>
                    </div>
                  </div>
                  {/* Functional color dots (kept in mono) */}
                  <div className="absolute bottom-2 right-2 flex gap-1">
                    <div className="w-2 h-2 rounded-full bg-green-400" />
                    <div className="w-2 h-2 rounded-full bg-amber-400" />
                    <div className="w-2 h-2 rounded-full bg-red-400" />
                  </div>
                </div>
                {/* Label */}
                <div className={`px-4 py-3 flex items-center justify-between`} style={{ background: '#111' }}>
                  <div>
                    <div className="text-sm font-semibold text-white">Monochrome</div>
                    <div className="text-[10px] text-slate-400">Black, white, and gray — status colors preserved</div>
                  </div>
                  {theme === 'mono' && <CheckCircle size={16} className="text-white shrink-0" />}
                </div>
              </button>
            </div>

            <p className="text-[11px] text-slate-500">
              Theme preference is saved locally. Green, amber, red, and orange are always kept — they indicate severity and status across the platform.
            </p>
          </div>

          {/* Demo Mode — admin only */}
          {currentUser?.role === 'admin' && (
            <div className="glass rounded-xl p-6 space-y-4 border border-amber-700/20">
              <div className="flex items-center gap-2">
                <FlaskConical size={16} className="text-amber-400" />
                <h3 className="text-sm font-semibold text-white">Demo Data</h3>
                <span className="text-[10px] px-1.5 py-0.5 rounded text-amber-400 border border-amber-500/30 ml-1" style={{ background: 'rgba(245,158,11,0.1)' }}>
                  Admin only
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Populate the platform with three realistic demo projects — an external pentest, a web application audit, and an internal network assessment — complete with targets, scan findings, credentials, and vulnerability records. Turning this off removes all demo data cleanly.
              </p>

              {demoError && (
                <p className="text-xs text-red-400">{demoError}</p>
              )}

              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {demoActive ? (
                    <span className="flex items-center gap-1.5 text-xs text-amber-400">
                      <span className="w-1.5 h-1.5 rounded-full bg-amber-400" style={{ boxShadow: '0 0 6px rgba(245,158,11,0.8)' }} />
                      Demo mode active — 3 projects seeded
                    </span>
                  ) : (
                    <span className="text-xs text-slate-500">Demo mode off</span>
                  )}
                </div>

                <button
                  onClick={handleDemoToggle}
                  disabled={demoLoading}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all disabled:opacity-50 ${
                    demoActive
                      ? 'border border-red-700/40 text-red-400 hover:bg-red-900/20'
                      : 'border border-amber-700/40 text-amber-400 hover:bg-amber-900/20'
                  }`}
                  style={{ background: demoActive ? 'rgba(127,29,29,0.15)' : 'rgba(120,53,15,0.15)' }}
                >
                  {demoLoading
                    ? <Loader size={13} className="animate-spin" />
                    : <FlaskConical size={13} />
                  }
                  {demoLoading
                    ? demoActive ? 'Clearing...' : 'Seeding...'
                    : demoActive ? 'Clear Demo Data' : 'Load Demo Data'
                  }
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Webhooks ────────────────────────────────────────────────────── */}
      {activeTab === 'webhooks' && (
        <div className="space-y-6 max-w-2xl">
          {/* Add webhook form */}
          <div className="glass rounded-xl p-6 space-y-4">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <Zap size={15} className="text-cyan-400" /> Add Webhook
            </h3>
            <p className="text-xs text-slate-400">
              Send HTTP POST notifications to Slack, Discord, or any custom endpoint when events occur.
            </p>
            {webhookError && <p className="text-xs text-red-400">{webhookError}</p>}
            <form onSubmit={handleCreateWebhook} className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Name</label>
                  <input
                    className="w-full bg-slate-900/60 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
                    placeholder="Slack alerts"
                    value={webhookForm.name}
                    onChange={e => setWebhookForm(f => ({ ...f, name: e.target.value }))}
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">URL</label>
                  <input
                    className="w-full bg-slate-900/60 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
                    placeholder="https://hooks.slack.com/..."
                    value={webhookForm.url}
                    onChange={e => setWebhookForm(f => ({ ...f, url: e.target.value }))}
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-2">Events</label>
                <div className="flex gap-2">
                  {(['critical', 'warning', 'info', 'all'] as const).map(ev => (
                    <button
                      key={ev}
                      type="button"
                      onClick={() => toggleWebhookEvent(ev)}
                      className={`px-3 py-1 rounded text-xs font-medium border transition-colors ${
                        webhookForm.events.includes(ev)
                          ? ev === 'critical' ? 'bg-red-900/40 border-red-500/50 text-red-300'
                          : ev === 'warning'  ? 'bg-amber-900/40 border-amber-500/50 text-amber-300'
                          : ev === 'info'     ? 'bg-blue-900/40 border-blue-500/50 text-blue-300'
                          : 'bg-cyan-900/40 border-cyan-500/50 text-cyan-300'
                          : 'bg-transparent border-slate-700/40 text-slate-500 hover:text-slate-300'
                      }`}
                    >
                      {ev}
                    </button>
                  ))}
                </div>
              </div>
              <button
                type="submit"
                disabled={webhookSaving}
                className="px-4 py-2 rounded-lg bg-cyan-600/20 border border-cyan-500/30 text-cyan-300 text-sm hover:bg-cyan-600/30 transition-colors disabled:opacity-50"
              >
                {webhookSaving ? 'Saving...' : 'Add Webhook'}
              </button>
            </form>
          </div>

          {/* Existing webhooks */}
          {webhooks.length === 0 ? (
            <p className="text-sm text-slate-500 text-center py-8">No webhooks configured.</p>
          ) : (
            <div className="space-y-3">
              {webhooks.map(wh => (
                <div key={wh.id} className="glass rounded-xl p-4 flex items-start gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-medium text-white truncate">{wh.name}</span>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border ${wh.active ? 'text-green-400 border-green-500/30 bg-green-900/20' : 'text-slate-500 border-slate-600/30'}`}>
                        {wh.active ? 'active' : 'paused'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 truncate font-mono">{wh.url}</p>
                    <div className="flex gap-1 mt-1.5">
                      {wh.events.map(ev => (
                        <span key={ev} className={`text-[10px] px-1.5 py-0.5 rounded border ${
                          ev === 'critical' ? 'text-red-400 border-red-500/30 bg-red-900/20'
                          : ev === 'warning' ? 'text-amber-400 border-amber-500/30 bg-amber-900/20'
                          : ev === 'info'    ? 'text-blue-400 border-blue-500/30 bg-blue-900/20'
                          : 'text-cyan-400 border-cyan-500/30 bg-cyan-900/20'
                        }`}>{ev}</span>
                      ))}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => handleTestWebhook(wh.id)}
                      disabled={webhookTestId === wh.id}
                      className="px-2 py-1 rounded text-xs border border-slate-700/40 text-slate-400 hover:text-cyan-300 hover:border-cyan-500/30 transition-colors disabled:opacity-50"
                    >
                      {webhookTestId === wh.id ? '✓ Sent' : 'Test'}
                    </button>
                    <button
                      onClick={() => handleToggleWebhook(wh.id, !wh.active)}
                      className="px-2 py-1 rounded text-xs border border-slate-700/40 text-slate-400 hover:text-amber-300 hover:border-amber-500/30 transition-colors"
                    >
                      {wh.active ? 'Pause' : 'Resume'}
                    </button>
                    <button onClick={() => handleDeleteWebhook(wh.id)} className="text-slate-600 hover:text-red-400 transition-colors p-1">
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tool info modal */}
      {infoTool && (() => {
        const data = TOOL_INFO[infoTool]
        const toolStatus_entry = toolStatus[infoTool]
        if (!data) return null
        const featureColors: Record<string, string> = {
          'Auto-Probe':         'bg-green-900/30 text-green-300 border-green-700/30',
          'Tool Chains':        'bg-blue-900/30 text-blue-300 border-blue-700/30',
          'Playbooks':          'bg-purple-900/30 text-purple-300 border-purple-700/30',
          'Hardening Module':   'bg-orange-900/30 text-orange-300 border-orange-700/30',
          'Cracking Module':    'bg-red-900/30 text-red-300 border-red-700/30',
          'OSINT Module':       'bg-cyan-900/30 text-cyan-300 border-cyan-700/30',
          'Scan Templates':     'bg-slate-700/40 text-slate-300 border-slate-600/30',
          'Database':           'bg-slate-700/40 text-slate-300 border-slate-600/30',
          'Runtime Dependency': 'bg-amber-900/30 text-amber-300 border-amber-700/30',
        }
        return (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setInfoTool(null)}>
            <div
              className="w-[520px] max-h-[80vh] flex flex-col rounded-xl border border-cyan-900/30 shadow-2xl overflow-hidden"
              style={{ background: '#070d17' }}
              onClick={e => e.stopPropagation()}
            >
              {/* Header */}
              <div className="flex items-center gap-3 px-5 py-4 border-b border-cyan-900/20 shrink-0">
                <Info size={16} className="text-cyan-400" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-semibold text-white">{toolStatus_entry?.label || infoTool}</span>
                    {toolStatus_entry?.available
                      ? <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-900/30 text-green-400 border border-green-700/30">installed</span>
                      : <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-900/30 text-red-400 border border-red-700/30">not installed</span>
                    }
                  </div>
                  {toolStatus_entry?.version && (
                    <div className="text-xs text-slate-500 mt-0.5 truncate">{toolStatus_entry.version}</div>
                  )}
                </div>
                {data.usedIn.length > 0 && toolStatus_entry?.url && (
                  <a href={toolStatus_entry.url} target="_blank" rel="noopener noreferrer"
                    className="text-slate-500 hover:text-cyan-400 transition-colors"
                    title="Official website">
                    <ExternalLink size={14} />
                  </a>
                )}
                <button onClick={() => setInfoTool(null)} className="text-slate-500 hover:text-slate-200 transition-colors ml-1">
                  <X size={16} />
                </button>
              </div>

              {/* Body */}
              <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
                {/* Description */}
                <p className="text-sm text-slate-300 leading-relaxed">{data.description}</p>

                {/* Used in Seraph */}
                {data.usedIn.length > 0 && (
                  <div className="space-y-3">
                    <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Used in Seraph</h4>
                    <div className="space-y-2">
                      {data.usedIn.map((u, i) => (
                        <div key={i} className="flex gap-3 items-start">
                          <span className={`shrink-0 text-[11px] font-medium px-2 py-0.5 rounded border ${featureColors[u.feature] ?? 'bg-slate-700/40 text-slate-300 border-slate-600/30'}`}>
                            {u.feature}
                          </span>
                          <span className="text-xs text-slate-400 leading-relaxed">{u.detail}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Install hint when not installed */}
                {!toolStatus_entry?.available && toolStatus_entry?.install_hint && (
                  <div className="space-y-2">
                    <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Install</h4>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 rounded px-3 py-2 text-xs font-mono text-slate-300 border border-cyan-900/20 break-all" style={{ background: '#05080d' }}>
                        {toolStatus_entry.install_hint}
                      </code>
                      <button
                        onClick={() => copyText(toolStatus_entry.install_hint!, `info-${infoTool}`)}
                        className="shrink-0 text-slate-500 hover:text-slate-300 transition-colors"
                      >
                        {copied === `info-${infoTool}` ? <Check size={13} className="text-green-400" /> : <Copy size={13} />}
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Footer */}
              <div className="px-5 py-3 border-t border-cyan-900/20 flex items-center justify-between shrink-0">
                {toolStatus_entry?.url ? (
                  <a href={toolStatus_entry.url} target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-cyan-400 transition-colors">
                    <ExternalLink size={12} /> Official website
                  </a>
                ) : <div />}
                {!toolStatus_entry?.available && (
                  <button
                    onClick={() => { setInfoTool(null); startInstall(infoTool) }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs bg-cyan-600/15 text-cyan-400 border border-cyan-600/25 hover:bg-cyan-600/25 transition-colors"
                  >
                    <Download size={11} /> Install now
                  </button>
                )}
              </div>
            </div>
          </div>
        )
      })()}

      {/* Install modal */}
      {installTool && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-[640px] max-h-[80vh] flex flex-col rounded-xl border border-cyan-900/30 shadow-2xl" style={{ background: '#070d17' }}>
            {/* Header */}
            <div className="flex items-center gap-3 px-5 py-4 border-b border-cyan-900/20 shrink-0">
              <Terminal size={16} className="text-cyan-400" />
              <span className="text-sm font-semibold text-white">Installing <span className="font-mono text-cyan-300">{toolStatus[installTool]?.label || installTool}</span></span>
              {installDone && (
                <span className="ml-2 text-xs px-2 py-0.5 rounded bg-green-500/15 text-green-400 border border-green-500/25">Done</span>
              )}
              <button
                onClick={() => setInstallTool(null)}
                className="ml-auto text-slate-500 hover:text-slate-200 transition-colors"
              >
                <X size={16} />
              </button>
            </div>
            {/* Terminal output */}
            <div className="flex-1 overflow-y-auto px-5 py-4 min-h-[200px]" style={{ background: '#05080d' }}>
              {installLines.length === 0 ? (
                <div className="flex items-center gap-2 text-slate-500 text-sm">
                  <Loader size={14} className="animate-spin" /> Connecting…
                </div>
              ) : (
                <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed">{installLines.join('')}</pre>
              )}
            </div>
            {/* Footer */}
            {installDone && (
              <div className="px-5 py-3 border-t border-cyan-900/20 flex justify-end shrink-0">
                <button
                  onClick={() => setInstallTool(null)}
                  className="px-4 py-1.5 rounded text-sm bg-cyan-600 hover:bg-cyan-500 text-white transition-colors"
                >
                  Close
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
