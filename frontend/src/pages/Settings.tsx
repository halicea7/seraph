import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  CheckCircle, XCircle, Brain, WifiOff, Save, Loader,
  UserPlus, Palette, Monitor, FlaskConical, ExternalLink, Info, Package,
} from 'lucide-react'
import Icon from '../components/Icon'
import { useAuth } from '../contexts/AuthContext'
import { useTheme } from '../contexts/ThemeContext'
import { getApiBase, wsUrl } from '@/lib/config'

// ── Types ─────────────────────────────────────────────────────────────────────

interface ToolInfo {
  available: boolean
  path: string | null
  version: string | null
  label: string
  tier?: 'required' | 'recommended' | 'optional'
  install_hint: string | null
  url: string | null
}

interface Profile {
  id: string
  name: string
  description: string
  scan_categories: string
  created_at: string
}

interface HostInfo {
  os: string
  distro_id: string
  distro_name: string
  pkg_manager: string
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

// ── Static tool data ──────────────────────────────────────────────────────────

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
  amass:                   { brew: 'amass' },
  wafw00f:                 { pip: 'wafw00f' },
  sherlock:                { pip: 'sherlock-project' },
}

interface ToolUsage { feature: string; detail: string }
interface ToolInfoData { description: string; usedIn: ToolUsage[] }

const TOOL_INFO: Record<string, ToolInfoData> = {
  nmap: { description: 'Industry-standard network scanner. Discovers open ports, identifies running services, detects OS fingerprints, and runs NSE vulnerability scripts.', usedIn: [{ feature: 'Auto-Probe', detail: 'Runs automatically on every new target for initial reconnaissance' }, { feature: 'Tool Chains', detail: 'Port scanning phase for external, internal, and web target types' }] },
  nikto: { description: 'Web server scanner that checks for dangerous files, outdated server software, and common misconfigurations.', usedIn: [{ feature: 'Auto-Probe', detail: 'Conditionally runs when ports 80, 443, 8080, 8443, or 8000 are open' }] },
  testssl: { description: 'Comprehensive TLS/SSL configuration tester. Checks cipher suites, certificate validity, protocol versions, and known vulnerabilities.', usedIn: [{ feature: 'Auto-Probe', detail: 'Conditionally runs when port 443 or 8443 is open' }] },
  lynis: { description: 'Host-based security auditing tool. Scans the local system for hardening gaps, misconfigurations, and compliance issues.', usedIn: [{ feature: 'Hardening Module', detail: 'Drives the full hardening audit' }] },
  hashcat: { description: "World's fastest GPU-accelerated password cracker. Supports 300+ hash types.", usedIn: [{ feature: 'Cracking Module', detail: 'Primary GPU cracking engine' }] },
  john: { description: 'John the Ripper — CPU-based password hash cracker with auto-detection of hash formats.', usedIn: [{ feature: 'Cracking Module', detail: 'CPU cracking fallback' }] },
  nuclei: { description: 'Fast, template-based vulnerability scanner with 7000+ community templates.', usedIn: [{ feature: 'Auto-Probe', detail: 'Runs after nmap on web ports with medium/high/critical severity templates' }] },
  rustscan: { description: 'Ultra-fast port scanner written in Rust. Scans all 65535 TCP ports in seconds.', usedIn: [{ feature: 'Auto-Probe', detail: 'Pre-nmap port discovery pass' }] },
  feroxbuster: { description: 'Fast, recursive web directory and file fuzzer written in Rust.', usedIn: [{ feature: 'Auto-Probe', detail: 'Runs on HTTP ports to discover hidden paths' }] },
  gobuster: { description: 'Directory and file brute-forcer for web servers.', usedIn: [{ feature: 'Tool Chains', detail: 'Enumeration phase for external and web application targets' }] },
  sqlmap: { description: 'Automated SQL injection detection and exploitation tool.', usedIn: [{ feature: 'Tool Chains', detail: 'Exploitation phase for external and web application targets' }] },
  hydra: { description: 'Fast and flexible online password brute-forcer supporting 50+ protocols.', usedIn: [{ feature: 'Tool Chains', detail: 'Exploitation phase for external and internal network targets' }] },
  masscan: { description: 'Extremely fast TCP port scanner capable of scanning the entire internet.', usedIn: [{ feature: 'Tool Chains', detail: 'High-speed port discovery for external and internal network target types' }] },
  whois: { description: 'Queries domain registration data.', usedIn: [{ feature: 'Auto-Probe', detail: 'Always runs on every new target for initial OSINT' }] },
  dig: { description: 'DNS lookup utility for querying DNS records.', usedIn: [{ feature: 'Tool Chains', detail: 'Reconnaissance phase for external network targets' }] },
  theHarvester: { description: 'OSINT tool that gathers emails, subdomains, hosts from public sources.', usedIn: [{ feature: 'OSINT Module', detail: 'Dedicated OSINT tool' }] },
  subfinder: { description: 'Passive subdomain discovery tool using 40+ sources.', usedIn: [{ feature: 'OSINT Module', detail: 'Rapid passive subdomain enumeration' }] },
  enum4linux: { description: 'SMB/NetBIOS enumeration tool.', usedIn: [{ feature: 'Tool Chains', detail: 'Enumeration phase for internal and external network targets (Windows hosts)' }] },
  ffuf: { description: 'Fast web fuzzer written in Go.', usedIn: [{ feature: 'Tool Chains', detail: 'Enumeration phase for external and web application targets' }] },
  searchsploit: { description: 'Command-line search tool for the Exploit-DB database.', usedIn: [{ feature: 'Tool Chains', detail: 'Exploitation research phase' }] },
  aws: { description: 'AWS Command Line Interface for cloud security auditing.', usedIn: [{ feature: 'Tool Chains', detail: 'All phases of cloud_aws target type' }] },
  go: { description: 'Go programming language runtime. Required to run Go-based tools.', usedIn: [{ feature: 'Runtime Dependency', detail: 'Required to install subfinder, ffuf, gobuster, nuclei' }] },
  kerbrute: { description: 'Kerberos user enumeration and password spraying tool.', usedIn: [{ feature: 'Pentest Workbench', detail: 'Active Directory engagement' }] },
  nxc: { description: 'NetExec (successor to CrackMapExec). Swiss-army knife for Active Directory.', usedIn: [{ feature: 'Pentest Workbench', detail: 'Active Directory engagement — all phases' }] },
  'impacket-GetUserSPNs': { description: 'Impacket tool for Kerberoasting.', usedIn: [{ feature: 'Pentest Workbench', detail: 'Active Directory engagement — enumeration phase' }] },
  'impacket-GetNPUsers': { description: 'Impacket tool for AS-REP roasting.', usedIn: [{ feature: 'Pentest Workbench', detail: 'Active Directory engagement — enumeration phase' }] },
  'impacket-secretsdump': { description: 'Impacket tool for dumping SAM, LSA secrets, and NTDS.dit hashes.', usedIn: [{ feature: 'Pentest Workbench', detail: 'Active Directory engagement — post-exploitation phase' }] },
  'impacket-psexec': { description: 'Impacket implementation of PsExec — remote execution via SMB.', usedIn: [{ feature: 'Pentest Workbench', detail: 'Active Directory engagement — exploitation phase' }] },
  'impacket-wmiexec': { description: 'Impacket WMI-based remote execution.', usedIn: [{ feature: 'Pentest Workbench', detail: 'Active Directory engagement — exploitation phase' }] },
  responder: { description: 'LLMNR/NBT-NS/mDNS poisoner. Captures NTLMv2 challenge/response hashes.', usedIn: [{ feature: 'Pentest Workbench', detail: 'Internal Network engagement — exploitation phase' }] },
  oscap: { description: 'OpenSCAP — SCAP-based compliance scanner. Audits system configuration against CIS, DISA STIG, and PCI-DSS baselines.', usedIn: [{ feature: 'Hardening Module', detail: 'CIS-CAT style compliance scanning' }] },
  amass: { description: 'OWASP Amass — in-depth DNS enumeration and network mapping using 20+ data sources.', usedIn: [{ feature: 'OSINT Module', detail: 'Deep subdomain enumeration and DNS graph mapping' }] },
  wafw00f: { description: 'Web Application Firewall detection tool. Identifies the WAF product protecting a target web application.', usedIn: [{ feature: 'Tool Chains', detail: 'Reconnaissance phase for web application targets' }] },
  sherlock: { description: 'Username OSINT tool. Searches 300+ social networks for a given username.', usedIn: [{ feature: 'OSINT Module', detail: 'Social media presence enumeration' }] },
}

const FEATURE_STYLES: Record<string, { color: string; background: string; border: string }> = {
  'Auto-Probe':         { color: 'var(--ok)',     background: 'rgba(84,175,97,0.1)',    border: '1px solid rgba(84,175,97,0.25)' },
  'Tool Chains':        { color: 'var(--accent)',  background: 'rgba(240,168,58,0.1)',   border: '1px solid rgba(240,168,58,0.25)' },
  'Playbooks':          { color: '#a855f7',       background: 'rgba(168,85,247,0.1)',   border: '1px solid rgba(168,85,247,0.25)' },
  'Hardening Module':   { color: '#f97316',       background: 'rgba(249,115,22,0.1)',   border: '1px solid rgba(249,115,22,0.25)' },
  'Cracking Module':    { color: 'var(--crit)',   background: 'rgba(232,64,64,0.1)',    border: '1px solid rgba(232,64,64,0.25)' },
  'OSINT Module':       { color: 'var(--med)',     background: 'rgba(212,196,90,0.1)',   border: '1px solid rgba(212,196,90,0.25)' },
  'Scan Templates':     { color: 'var(--fg-3)',   background: 'rgba(100,116,139,0.1)',  border: '1px solid rgba(100,116,139,0.2)' },
  'Database':           { color: 'var(--fg-3)',   background: 'rgba(100,116,139,0.1)',  border: '1px solid rgba(100,116,139,0.2)' },
  'Runtime Dependency': { color: 'var(--accent)', background: 'rgba(240,168,58,0.1)',   border: '1px solid rgba(240,168,58,0.25)' },
  'Pentest Workbench':  { color: '#a855f7',       background: 'rgba(168,85,247,0.1)',   border: '1px solid rgba(168,85,247,0.25)' },
}

const PKG_MANAGER_LABELS: Record<string, string> = {
  apt: 'Debian / Ubuntu', dnf: 'Fedora / RHEL', yum: 'CentOS / RHEL',
  pacman: 'Arch Linux', apk: 'Alpine', zypper: 'openSUSE', brew: 'macOS (Homebrew)',
}

function getBulkInstallCmd(toolNames: string[], hostInfo: HostInfo | null): string {
  const mgr = hostInfo?.pkg_manager || 'apt'
  const pkgSet = new Set(toolNames.map(n => TOOL_PKGS[n]?.[mgr]).filter(Boolean) as string[])
  const pkgList = Array.from(pkgSet)
  const pipSet = new Set(toolNames.map(n => TOOL_PKGS[n]?.['pip']).filter(Boolean) as string[])
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

const TOOL_CACHE_KEY = 'seraph_tool_cache'

// ── Helpers ───────────────────────────────────────────────────────────────────

const rule = '1px solid var(--rule)'
const ruleStrong = '1px solid var(--rule-strong)'

function Section({ title, right, children }: { title: string; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="rule">
      <div className="sec-h" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span className="title">{title}</span>
        {right && <span>{right}</span>}
      </div>
      {children}
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label style={{ display: 'block', marginBottom: 6, fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: 'var(--font-mono)' }}>{label}</label>
      {children}
    </div>
  )
}

function Pill({ tone, children }: { tone: 'pass' | 'fail' | 'warn' | 'info'; children: React.ReactNode }) {
  const map = {
    pass: { color: 'var(--ok)',     bg: 'rgba(84,175,97,0.1)',   border: 'rgba(84,175,97,0.3)' },
    fail: { color: 'var(--crit)',   bg: 'rgba(232,64,64,0.1)',   border: 'rgba(232,64,64,0.3)' },
    warn: { color: 'var(--accent)', bg: 'rgba(240,168,58,0.08)', border: 'rgba(240,168,58,0.25)' },
    info: { color: 'var(--fg-3)',   bg: 'rgba(100,116,139,0.1)', border: 'rgba(100,116,139,0.2)' },
  }
  const s = map[tone]
  return (
    <span className="mono" style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.12em', padding: '1px 6px', color: s.color, background: s.bg, border: `1px solid ${s.border}` }}>
      {children}
    </span>
  )
}

const inputStyle: React.CSSProperties = {
  background: 'var(--bg)', border: ruleStrong, borderRadius: 3,
  padding: '6px 10px', fontSize: 12, color: 'var(--fg)',
  fontFamily: 'var(--font-sans)', outline: 'none', width: '100%', boxSizing: 'border-box',
}

const NAV_ITEMS: { id: string; label: string }[] = [
  { id: 'users',      label: 'Users' },
  { id: 'appearance', label: 'Variants' },
  { id: 'tools',      label: 'Tools' },
  { id: 'ai',         label: 'AI' },
  { id: 'msf',        label: 'Metasploit RPC' },
  { id: 'nessus',     label: 'Nessus' },
  { id: 'hermes',     label: 'Hermes' },
  { id: 'env',        label: 'Environment' },
  { id: 'passkeys',   label: 'Access & Integrations' },
  { id: 'demo',       label: 'Demo Data' },
]

type NavId = 'users' | 'appearance' | 'tools' | 'ai' | 'msf' | 'nessus' | 'hermes' | 'env' | 'passkeys' | 'demo'

// ── Main ──────────────────────────────────────────────────────────────────────

export default function Settings() {
  const [activeNav, setActiveNav] = useState<NavId>('users')
  const { user: currentUser, token: authToken, refreshUser } = useAuth()
  const { accent, bg, density, setAccent, setBg, setDensity } = useTheme()
  const navigate = useNavigate()

  // Tools state
  const [toolStatus, setToolStatus] = useState<Record<string, ToolInfo>>({})
  const [hostInfo, setHostInfo] = useState<HostInfo | null>(null)
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState('')
  const [, setProfiles] = useState<Profile[]>([])
  const [infoTool, setInfoTool] = useState<string | null>(null)
  const [installTool, setInstallTool] = useState<string | null>(null)
  const [installLines, setInstallLines] = useState<string[]>([])
  const [installDone, setInstallDone] = useState(false)

  // Auto-probe state
  const [probeEnabled, setProbeEnabled] = useState(false)
  const [probeTools, setProbeTools] = useState<string[]>(['whois', 'rustscan', 'nmap', 'nikto', 'testssl', 'nuclei', 'feroxbuster'])
  const [probeIntensity, setProbeIntensity] = useState<'quick' | 'standard' | 'deep'>('standard')
  const [probeSaving, setProbeSaving] = useState(false)
  const [, setProbeLoading] = useState(false)

  // Profile state
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

  // User management
  interface UserRow { id: string; username: string; role: string; is_active: boolean; full_name: string; created_at: string; last_login?: string | null }
  const [userList, setUserList] = useState<UserRow[]>([])
  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState<'admin' | 'analyst'>('analyst')
  const [newFirstName, setNewFirstName] = useState('')
  const [newLastName, setNewLastName] = useState('')
  const [showNewPw, setShowNewPw] = useState(false)
  const [userError, setUserError] = useState('')
  const [userSaving, setUserSaving] = useState(false)
  const [curPw, setCurPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [pwError, setPwError] = useState('')
  const [pwSaving, setPwSaving] = useState(false)
  const [pwOk, setPwOk] = useState(false)

  // Passkeys
  interface PasskeyRow { id: string; name: string; created_at: string }
  const [passkeys, setPasskeys] = useState<PasskeyRow[]>([])
  const [passkeyRegLoading, setPasskeyRegLoading] = useState(false)
  const [passkeyError, setPasskeyError] = useState('')
  const [newPasskeyName, setNewPasskeyName] = useState('iCloud Keychain')

  // API Tokens
  interface ApiTokenRow { id: string; name: string; prefix: string; created_at: string; last_used_at: string | null }
  const [apiTokens, setApiTokens] = useState<ApiTokenRow[]>([])
  const [newTokenName, setNewTokenName] = useState('')
  const [tokenGenerating, setTokenGenerating] = useState(false)
  const [revealedToken, setRevealedToken] = useState<string | null>(null)
  const [tokenCopied, setTokenCopied] = useState(false)

  // Webhooks
  interface WebhookRow { id: string; name: string; url: string; events: string[]; active: boolean; created_at: string }
  const [webhooks, setWebhooks] = useState<WebhookRow[]>([])
  const [webhookForm, setWebhookForm] = useState({ name: '', url: '', events: ['critical', 'warning'], active: true })
  const [webhookSaving, setWebhookSaving] = useState(false)
  const [webhookError, setWebhookError] = useState('')
  const [webhookTestId, setWebhookTestId] = useState<string | null>(null)

  // Nessus integration
  const [nessusHost, setNessusHost] = useState('')
  const [nessusPort, setNessusPort] = useState('8834')
  const [nessusUsername, setNessusUsername] = useState('')
  const [nessusPassword, setNessusPassword] = useState('')
  const [nessusVerifySsl, setNessusVerifySsl] = useState(false)
  const [nessusApiAccessKey, setNessusApiAccessKey] = useState('')
  const [nessusApiSecretKey, setNessusApiSecretKey] = useState('')
  const [nessusSaving, setNessusSaving] = useState(false)
  const [nessusTesting, setNessusTesting] = useState(false)
  const [nessusStatus, setNessusStatus] = useState<{ configured: boolean; connected: boolean; error: string | null } | null>(null)

  // Hermes
  const [hermesStatus, setHermesStatus] = useState<{ installed: boolean; version: string; ollama_url: string; ollama_reachable: boolean } | null>(null)
  const [hermesAllowPrivate, setHermesAllowPrivate] = useState(true)
  const [hermesSandbox, setHermesSandbox] = useState(false)
  const [hermesDefaultModel, setHermesDefaultModel] = useState('')
  const [hermesSaving, setHermesSaving] = useState(false)

  // Demo
  const [demoActive, setDemoActive] = useState(false)
  const [demoLoading, setDemoLoading] = useState(false)
  const [demoError, setDemoError] = useState('')

  // AI config
  const [aiConfig, setAiConfig] = useState<AIConfig>({ endpoint: 'http://localhost:11434', model: '', provider: 'ollama', temperature: null, top_p: null, top_k: null, min_p: null, presence_penalty: null, repetition_penalty: null, timeout: null })
  const [aiStatus, setAiStatus] = useState<AIStatus | null>(null)
  const [aiModels, setAiModels] = useState<string[]>([])
  const [aiSaving, setAiSaving] = useState(false)
  const [aiTesting, setAiTesting] = useState(false)

  // ATT&CK index
  const [attackStatus, setAttackStatus] = useState<{ count: number; last_sync: string | null; state: string; error: string | null } | null>(null)
  const [attackSyncing, setAttackSyncing] = useState(false)

  // PTES index
  const [ptesStatus, setPtesStatus] = useState<{ count: number; last_sync: string | null; syncing: boolean } | null>(null)
  const [ptesSyncing, setPtesSyncing] = useState(false)

  // Local Ollama
  const [localOllamaSettings, setLocalOllamaSettings] = useState({ useLocalOllama: false, localOllamaUrl: 'http://localhost:11434', localOllamaModel: '' })
  const [localOllamaModels, setLocalOllamaModels] = useState<string[]>([])
  const [localOllamaTesting, setLocalOllamaTesting] = useState(false)
  const [localOllamaSaving, setLocalOllamaSaving] = useState(false)
  const [localOllamaStatus, setLocalOllamaStatus] = useState<{ online: boolean; error?: string } | null>(null)

  // MSF (static placeholders — no API endpoint shown in original)

  // Environment vars
  const [envVars, setEnvVars] = useState<Record<string, string>>({})

  useEffect(() => {
    const cached = localStorage.getItem(TOOL_CACHE_KEY)
    if (cached) { try { setToolStatus(JSON.parse(cached)) } catch {} }
    loadProfiles()
    loadAiConfig()
    loadAttackStatus()
    loadPtesStatus()
    loadProbeConfig()
    loadPasskeys()
    loadApiTokens()
    loadWebhooks()
    loadLocalOllamaSettings()
    loadEnvVars()
    if (currentUser?.role === 'admin') {
      loadUsers()
      loadDemoStatus()
    }
  }, [])

  useEffect(() => {
    if (activeNav === 'nessus') loadNessusConfig()
    if (activeNav === 'hermes') loadHermesData()
    // Always refresh tool detection when the Tools tab opens so we don't show
    // a stale localStorage cache (e.g. one saved before tools gained tiers).
    if (activeNav === 'tools') loadTools()
  }, [activeNav])

  // ── API functions ─────────────────────────────────────────────────────────

  async function loadHermesData() {
    try {
      const [s, c] = await Promise.all([
        fetch(`${getApiBase()}/hermes/status`).then(r => r.json()),
        fetch(`${getApiBase()}/hermes/config`).then(r => r.json()),
      ])
      setHermesStatus(s)
      setHermesAllowPrivate(c.allow_private_urls ?? true)
      setHermesSandbox(c.sandbox ?? false)
      setHermesDefaultModel(c.default_model ?? '')
    } catch { /* offline */ }
  }

  async function saveHermesConfigSettings() {
    setHermesSaving(true)
    try {
      await fetch(`${getApiBase()}/hermes/config`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          allow_private_urls: hermesAllowPrivate,
          sandbox: hermesSandbox,
          default_model: hermesDefaultModel.trim(),
        }),
      })
    } finally {
      setHermesSaving(false)
    }
  }

  async function loadPasskeys() {
    try {
      const res = await fetch(`${getApiBase()}/passkeys/`, { headers: { Authorization: `Bearer ${authToken}` } })
      if (res.ok) setPasskeys(await res.json())
    } catch { /* ignore */ }
  }

  async function loadApiTokens() {
    try {
      const res = await fetch(`${getApiBase()}/auth/tokens`, { headers: { Authorization: `Bearer ${authToken}` } })
      if (res.ok) setApiTokens(await res.json())
    } catch { /* ignore */ }
  }

  async function handleGenerateToken() {
    if (!newTokenName.trim()) return
    setTokenGenerating(true)
    setRevealedToken(null)
    try {
      const res = await fetch(`${getApiBase()}/auth/tokens`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
        body: JSON.stringify({ name: newTokenName.trim() }),
      })
      if (!res.ok) return
      const data = await res.json()
      setRevealedToken(data.token)
      setNewTokenName('')
      await loadApiTokens()
    } finally { setTokenGenerating(false) }
  }

  async function handleRevokeToken(id: string) {
    await fetch(`${getApiBase()}/auth/tokens/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${authToken}` } })
    setApiTokens(prev => prev.filter(t => t.id !== id))
  }

  function handleCopyToken() {
    if (!revealedToken) return
    navigator.clipboard.writeText(revealedToken)
    setTokenCopied(true)
    setTimeout(() => setTokenCopied(false), 2000)
  }

  async function handleRegisterPasskey() {
    if (!window.isSecureContext) { setPasskeyError('Passkeys require a secure context.'); return }
    if (!window.PublicKeyCredential) { setPasskeyError('Passkeys are not available in this browser.'); return }
    setPasskeyError('')
    setPasskeyRegLoading(true)
    try {
      const beginRes = await fetch(`${getApiBase()}/passkeys/register/begin`, { method: 'POST', headers: { Authorization: `Bearer ${authToken}` } })
      if (!beginRes.ok) throw new Error('Failed to start passkey registration')
      const opts = await beginRes.json()
      const { _challenge_key: challengeKey, ...pubKeyOpts } = opts
      const createOpts: PublicKeyCredentialCreationOptions = {
        ...pubKeyOpts,
        challenge: _b64urlToBuffer(pubKeyOpts.challenge),
        user: { ...pubKeyOpts.user, id: _b64urlToBuffer(pubKeyOpts.user.id) },
        excludeCredentials: (pubKeyOpts.excludeCredentials || []).map((c: any) => ({ ...c, id: _b64urlToBuffer(c.id) })),
      }
      const cred = await navigator.credentials.create({ publicKey: createOpts }) as PublicKeyCredential | null
      if (!cred) throw new Error('No credential created')
      const ar = cred.response as AuthenticatorAttestationResponse
      const completeRes = await fetch(`${getApiBase()}/passkeys/register/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
        body: JSON.stringify({ challenge_key: challengeKey, name: newPasskeyName.trim() || 'Passkey', credential: { id: cred.id, rawId: _bufferToB64url(cred.rawId), response: { clientDataJSON: _bufferToB64url(ar.clientDataJSON), attestationObject: _bufferToB64url(ar.attestationObject), transports: ar.getTransports ? ar.getTransports() : [] }, type: cred.type } }),
      })
      const data = await completeRes.json()
      if (!completeRes.ok) throw new Error(data.detail || 'Registration failed')
      setNewPasskeyName('iCloud Keychain')
      await loadPasskeys()
    } catch (err: any) {
      if (err.name === 'NotAllowedError') setPasskeyError('Passkey prompt was cancelled.')
      else setPasskeyError(err.message || 'Registration failed')
    } finally { setPasskeyRegLoading(false) }
  }

  async function handleDeletePasskey(id: string) {
    await fetch(`${getApiBase()}/passkeys/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${authToken}` } })
    setPasskeys(prev => prev.filter(p => p.id !== id))
  }

  function _b64urlToBuffer(b64url: string): ArrayBuffer {
    const padded = b64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(b64url.length + (4 - (b64url.length % 4)) % 4, '=')
    const bin = atob(padded)
    const buf = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i)
    return buf.buffer
  }

  function _bufferToB64url(buf: ArrayBuffer): string {
    return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  }

  async function loadWebhooks() {
    try {
      const res = await fetch(`${getApiBase()}/webhooks`, { headers: { Authorization: `Bearer ${authToken}` } })
      if (res.ok) setWebhooks(await res.json())
    } catch { /* ignore */ }
  }

  async function handleCreateWebhook(e: React.FormEvent) {
    e.preventDefault()
    setWebhookError('')
    if (!webhookForm.name.trim() || !webhookForm.url.trim()) { setWebhookError('Name and URL are required.'); return }
    setWebhookSaving(true)
    try {
      const res = await fetch(`${getApiBase()}/webhooks`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` }, body: JSON.stringify(webhookForm) })
      if (!res.ok) { const d = await res.json(); setWebhookError(d.detail || 'Failed to create webhook'); return }
      setWebhookForm({ name: '', url: '', events: ['critical', 'warning'], active: true })
      await loadWebhooks()
    } catch { setWebhookError('Request failed') }
    finally { setWebhookSaving(false) }
  }

  async function handleDeleteWebhook(id: string) {
    await fetch(`${getApiBase()}/webhooks/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${authToken}` } })
    setWebhooks(w => w.filter(x => x.id !== id))
  }

  async function handleToggleWebhook(id: string, active: boolean) {
    const res = await fetch(`${getApiBase()}/webhooks/${id}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` }, body: JSON.stringify({ active }) })
    if (res.ok) setWebhooks(w => w.map(x => x.id === id ? { ...x, active } : x))
  }

  async function handleTestWebhook(id: string) {
    setWebhookTestId(id)
    try { await fetch(`${getApiBase()}/webhooks/${id}/test`, { method: 'POST', headers: { Authorization: `Bearer ${authToken}` } }) }
    finally { setTimeout(() => setWebhookTestId(null), 1500) }
  }

  function toggleWebhookEvent(event: string) {
    setWebhookForm(f => ({ ...f, events: f.events.includes(event) ? f.events.filter(e => e !== event) : [...f.events, event] }))
  }

  async function loadDemoStatus() {
    try {
      const res = await fetch(`${getApiBase()}/demo/status`)
      if (res.ok) setDemoActive((await res.json()).active)
    } catch { /* backend offline */ }
  }

  async function handleDemoToggle() {
    setDemoLoading(true); setDemoError('')
    try {
      const res = await fetch(`${getApiBase()}/demo/${demoActive ? 'clear' : 'seed'}`, { method: demoActive ? 'DELETE' : 'POST' })
      if (res.ok) { setDemoActive(!demoActive); navigate('/') }
      else setDemoError(`Failed to ${demoActive ? 'clear' : 'seed'} demo data (${res.status})`)
    } catch { setDemoError('Could not reach the backend.') }
    finally { setDemoLoading(false) }
  }

  async function loadTools() {
    setLoading(true)
    try {
      const [toolRes, hostRes] = await Promise.all([fetch(`${getApiBase()}/settings/tools`), fetch(`${getApiBase()}/settings/host-info`)])
      const result = await toolRes.json()
      setToolStatus(result)
      localStorage.setItem(TOOL_CACHE_KEY, JSON.stringify(result))
      if (hostRes.ok) setHostInfo(await hostRes.json())
    } finally { setLoading(false) }
  }

  async function loadProfiles() {
    const res = await fetch(`${getApiBase()}/profiles`)
    if (res.ok) setProfiles(await res.json())
  }

  async function loadProbeConfig() {
    setProbeLoading(true)
    try {
      const res = await fetch(`${getApiBase()}/settings/auto-probe`)
      if (res.ok) { const data = await res.json(); setProbeEnabled(data.enabled); setProbeTools(data.tools); setProbeIntensity(data.intensity) }
    } finally { setProbeLoading(false) }
  }

  async function saveProbeConfig() {
    setProbeSaving(true)
    try { await fetch(`${getApiBase()}/settings/auto-probe`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: probeEnabled, tools: probeTools, intensity: probeIntensity }) }) }
    finally { setProbeSaving(false) }
  }

  function toggleProbeTool(name: string) {
    setProbeTools(prev => prev.includes(name) ? prev.filter(t => t !== name) : [...prev, name])
  }

  async function handleUpdateProfile(e: React.FormEvent) {
    e.preventDefault(); setProfileError(''); setProfileOk(false); setProfileSaving(true)
    try {
      const fullName = `${profileFirstName.trim()} ${profileLastName.trim()}`.trim()
      const res = await fetch(`${getApiBase()}/auth/me`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` }, body: JSON.stringify({ full_name: fullName || null }) })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed to update profile')
      await refreshUser(); setProfileOk(true); setTimeout(() => setProfileOk(false), 3000)
    } catch (err: any) { setProfileError(err.message) }
    finally { setProfileSaving(false) }
  }

  async function loadUsers() {
    const res = await fetch(`${getApiBase()}/auth/users`)
    if (res.ok) setUserList(await res.json())
  }

  async function handleCreateUser(e: React.FormEvent) {
    e.preventDefault(); setUserError(''); setUserSaving(true)
    try {
      const res = await fetch(`${getApiBase()}/auth/users`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: newUsername.trim(), password: newPassword, role: newRole, full_name: `${newFirstName.trim()} ${newLastName.trim()}`.trim() || undefined }) })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed to create user')
      setNewUsername(''); setNewPassword(''); setNewFirstName(''); setNewLastName('')
      loadUsers()
    } catch (err: any) { setUserError(err.message) }
    finally { setUserSaving(false) }
  }

  async function handleDeleteUser(id: string) {
    await fetch(`${getApiBase()}/auth/users/${id}`, { method: 'DELETE' })
    loadUsers()
  }

  async function handleChangePassword(e: React.FormEvent) {
    e.preventDefault(); setPwError(''); setPwOk(false); setPwSaving(true)
    try {
      const res = await fetch(`${getApiBase()}/auth/change-password`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ current_password: curPw, new_password: newPw }) })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Failed to change password')
      setCurPw(''); setNewPw(''); setPwOk(true)
    } catch (err: any) { setPwError(err.message) }
    finally { setPwSaving(false) }
  }

  async function loadAiConfig() {
    try { const res = await fetch(`${getApiBase()}/ai/config`); if (res.ok) setAiConfig(await res.json()) }
    catch { /* backend offline */ }
  }

  async function loadPtesStatus() {
    try { const r = await fetch(`${getApiBase()}/ai/ptes/status`); if (r.ok) setPtesStatus(await r.json()) }
    catch { /* ignore */ }
  }

  async function loadAttackStatus() {
    try { const r = await fetch(`${getApiBase()}/ai/attack/status`); if (r.ok) setAttackStatus(await r.json()) }
    catch { /* backend offline */ }
  }

  async function saveAiConfig() {
    setAiSaving(true)
    try { await fetch(`${getApiBase()}/ai/config`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(aiConfig) }) }
    finally { setAiSaving(false) }
  }

  async function testAiConnection() {
    setAiTesting(true); setAiStatus(null); setAiModels([])
    try {
      await fetch(`${getApiBase()}/ai/config`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(aiConfig) })
      const [statusRes, modelsRes] = await Promise.all([fetch(`${getApiBase()}/ai/status`), fetch(`${getApiBase()}/ai/models`)])
      if (statusRes.ok) setAiStatus(await statusRes.json())
      if (modelsRes.ok) { const data = await modelsRes.json(); setAiModels(data.models || []); if (!aiConfig.model && data.models?.length > 0) setAiConfig(c => ({ ...c, model: data.models[0] })) }
    } finally { setAiTesting(false) }
  }

  async function loadLocalOllamaSettings() {
    try { const s = await window.electronAPI!.ollamaGetSettings(); setLocalOllamaSettings(s) }
    catch { /* ignore */ }
  }

  async function saveLocalOllamaSettings() {
    setLocalOllamaSaving(true)
    try { await window.electronAPI!.ollamaSetSettings(localOllamaSettings) }
    finally { setLocalOllamaSaving(false) }
  }

  async function testLocalOllama() {
    setLocalOllamaTesting(true); setLocalOllamaStatus(null); setLocalOllamaModels([])
    try {
      await window.electronAPI!.ollamaSetSettings(localOllamaSettings)
      const models = await window.electronAPI!.ollamaModels()
      setLocalOllamaModels(models); setLocalOllamaStatus({ online: true })
      if (!localOllamaSettings.localOllamaModel && models.length > 0) setLocalOllamaSettings(s => ({ ...s, localOllamaModel: models[0] }))
    } catch (err: any) { setLocalOllamaStatus({ online: false, error: err.message }) }
    finally { setLocalOllamaTesting(false) }
  }

  async function loadEnvVars() {
    try {
      const res = await fetch(`${getApiBase()}/settings/env`)
      if (res.ok) setEnvVars(await res.json())
    } catch { /* ignore */ }
  }

  async function loadNessusConfig() {
    try {
      const res = await fetch(`${getApiBase()}/nessus/config`)
      if (!res.ok) return
      const d = await res.json()
      if (d.host) setNessusHost(d.host)
      if (d.port) setNessusPort(String(d.port))
      if (d.username) setNessusUsername(d.username)
      setNessusVerifySsl(!!d.verify_ssl)
    } catch { /* ignore */ }
  }

  function copyText(text: string, key: string) {
    navigator.clipboard.writeText(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 2000)
  }

  function startInstall(toolName: string) {
    setInstallTool(toolName); setInstallLines([]); setInstallDone(false)
    const ws = new WebSocket(wsUrl(`/ws/install/${toolName}`))
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data)
      if (msg.type === 'stdout' || msg.type === 'stderr' || msg.type === 'error') setInstallLines(prev => [...prev, msg.data])
      else if (msg.type === 'exit') { setInstallDone(true); if (msg.code === 0) loadTools() }
    }
    ws.onerror = () => setInstallLines(prev => [...prev, '\nWebSocket error — check server logs.\n'])
  }

  // ── Derived values ────────────────────────────────────────────────────────

  const available = Object.entries(toolStatus).filter(([, v]) => v.available)
  const missing = Object.entries(toolStatus).filter(([, v]) => !v.available)
  const mgr = hostInfo?.pkg_manager || 'apt'
  const missingNames = missing.map(([name]) => name)
  const pkgMgrMissing = missingNames.filter(n => n !== 'go' && TOOL_PKGS[n]?.[mgr])
  const bulkInstallCmd = getBulkInstallCmd(pkgMgrMissing, hostInfo)

  // ── Render panels ─────────────────────────────────────────────────────────

  function renderUsers() {
    return (
      <div style={{ padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Section title={`USERS · ${userList.length}`}>
          <table className="data">
            <thead>
              <tr>
                <th>Username</th>
                <th>Full name</th>
                <th style={{ width: 90 }}>Role</th>
                <th style={{ width: 80 }}>Passkeys</th>
                <th style={{ width: 110 }}>Last login</th>
                <th style={{ width: 60 }}></th>
              </tr>
            </thead>
            <tbody>
              {userList.map(u => (
                <tr key={u.id}>
                  <td><span className="mono" style={{ fontSize: 12, color: 'var(--accent)' }}>@{u.username}</span></td>
                  <td style={{ fontSize: 13 }}>{u.full_name || '—'}</td>
                  <td>{u.role === 'admin' ? <Pill tone="warn">{u.role}</Pill> : <Pill tone="info">{u.role}</Pill>}</td>
                  <td className="tnum" style={{ fontSize: 12 }}>—</td>
                  <td><span className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>{u.last_login ? new Date(u.last_login).toLocaleDateString() : '—'}</span></td>
                  <td>
                    {u.id !== currentUser?.id && (
                      <button onClick={() => handleDeleteUser(u.id)} className="btn-sm btn-danger" title="Delete user">
                        <Icon name="trash" size={11} color="currentColor" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {userList.length === 0 && (
                <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--fg-3)', padding: '20px 0' }}>No users loaded.</td></tr>
              )}
            </tbody>
          </table>
        </Section>

        {currentUser?.role === 'admin' && (
          <Section title="CREATE USER">
            <div style={{ padding: '14px var(--pad)' }}>
              <form onSubmit={handleCreateUser} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
                  <Field label="First Name">
                    <input type="text" value={newFirstName} onChange={e => setNewFirstName(e.target.value)} required placeholder="Jane" style={inputStyle} />
                  </Field>
                  <Field label="Last Name">
                    <input type="text" value={newLastName} onChange={e => setNewLastName(e.target.value)} required placeholder="Doe" style={inputStyle} />
                  </Field>
                  <Field label="Role">
                    <select value={newRole} onChange={e => setNewRole(e.target.value as 'admin' | 'analyst')} style={inputStyle}>
                      <option value="analyst">Analyst</option>
                      <option value="admin">Admin</option>
                    </select>
                  </Field>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <Field label="Username">
                    <input type="text" value={newUsername} onChange={e => setNewUsername(e.target.value)} required style={inputStyle} />
                  </Field>
                  <Field label="Password">
                    <div style={{ position: 'relative' }}>
                      <input type={showNewPw ? 'text' : 'password'} value={newPassword} onChange={e => setNewPassword(e.target.value)} required style={{ ...inputStyle, paddingRight: 32 }} />
                      <button type="button" onClick={() => setShowNewPw(v => !v)} style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0, display: 'flex' }}>
                        <Icon name={showNewPw ? 'eye_off' : 'eye'} size={12} color="currentColor" />
                      </button>
                    </div>
                  </Field>
                </div>
                {userError && <p style={{ margin: 0, fontSize: 11, color: 'var(--crit)', fontFamily: 'var(--font-sans)' }}>{userError}</p>}
                <div>
                  <button type="submit" disabled={userSaving} className="btn btn-primary">
                    {userSaving ? <Loader size={13} className="animate-spin" /> : <UserPlus size={13} />} Create User
                  </button>
                </div>
              </form>
            </div>
          </Section>
        )}

        <Section title="MY PROFILE">
          <div style={{ padding: '14px var(--pad)' }}>
            <form onSubmit={handleUpdateProfile} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <Field label="First Name"><input type="text" value={profileFirstName} onChange={e => setProfileFirstName(e.target.value)} placeholder="Jane" style={inputStyle} /></Field>
                <Field label="Last Name"><input type="text" value={profileLastName} onChange={e => setProfileLastName(e.target.value)} placeholder="Doe" style={inputStyle} /></Field>
              </div>
              {profileError && <p style={{ margin: 0, fontSize: 11, color: 'var(--crit)' }}>{profileError}</p>}
              {profileOk && <p style={{ margin: 0, fontSize: 11, color: 'var(--ok)' }}>Profile updated.</p>}
              <div><button type="submit" disabled={profileSaving} className="btn">{profileSaving ? <Loader size={13} className="animate-spin" /> : <Save size={13} />} Save Profile</button></div>
            </form>
          </div>
        </Section>

        <Section title="CHANGE PASSWORD">
          <div style={{ padding: '14px var(--pad)' }}>
            <form onSubmit={handleChangePassword} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <Field label="Current password"><input type="password" value={curPw} onChange={e => setCurPw(e.target.value)} required style={inputStyle} /></Field>
                <Field label="New password (min 8)"><input type="password" value={newPw} onChange={e => setNewPw(e.target.value)} required style={inputStyle} /></Field>
              </div>
              {pwError && <p style={{ margin: 0, fontSize: 11, color: 'var(--crit)' }}>{pwError}</p>}
              {pwOk && <p style={{ margin: 0, fontSize: 11, color: 'var(--ok)' }}>Password changed successfully.</p>}
              <div><button type="submit" disabled={pwSaving} className="btn">{pwSaving ? <Loader size={13} className="animate-spin" /> : <Save size={13} />} Update Password</button></div>
            </form>
          </div>
        </Section>
      </div>
    )
  }

  function renderTools() {
    const TIERS = [
      { id: 'required' as const,    label: 'Required',    color: 'var(--crit)',   blurb: 'Core — primary workflows depend on these' },
      { id: 'recommended' as const, label: 'Recommended', color: 'var(--accent)', blurb: 'Broadly used across engagements and modules' },
      { id: 'optional' as const,    label: 'Optional',    color: 'var(--fg-3)',   blurb: 'Engagement-specific or niche' },
    ]

    const renderToolCard = (name: string, info: ToolInfo) => {
      const isGoRuntime = name === 'go'
      const needsGo = !isGoRuntime && !info.available && info.install_hint?.startsWith('go install')
      const goMissing = needsGo && toolStatus['go'] && !toolStatus['go'].available
      const leftBorder = info.available ? '2px solid var(--ok)' : isGoRuntime ? '2px solid var(--accent)' : '2px solid var(--crit)'
      return (
        <div key={name} style={{ background: 'var(--bg)', border: ruleStrong, borderLeft: leftBorder, borderRadius: 3, padding: '10px 12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
            {info.available
              ? <CheckCircle size={13} color="var(--ok)" style={{ flexShrink: 0 }} />
              : <XCircle size={13} color={isGoRuntime ? 'var(--accent)' : 'var(--crit)'} style={{ flexShrink: 0 }} />
            }
            <span className="mono" style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{info.label || name}</span>
            {TOOL_INFO[name] && (
              <button onClick={() => setInfoTool(name)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0, display: 'flex' }}>
                <Info size={12} />
              </button>
            )}
          </div>
          {info.available ? (
            <>
              {info.version && <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{info.version.slice(0, 50)}</div>}
            </>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {!goMissing && !isGoRuntime && info.install_hint && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <code className="mono" style={{ flex: 1, fontSize: 9, color: 'var(--fg-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{info.install_hint}</code>
                  <button onClick={() => copyText(info.install_hint!, `tool-${name}`)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied === `tool-${name}` ? 'var(--ok)' : 'var(--fg-3)', padding: 0, display: 'flex', flexShrink: 0 }}>
                    <Icon name={copied === `tool-${name}` ? 'check' : 'copy'} size={11} color="currentColor" />
                  </button>
                </div>
              )}
              <div style={{ display: 'flex', gap: 6 }}>
                {!goMissing && <button onClick={() => startInstall(name)} className="btn btn-sm"><Icon name="download" size={10} color="currentColor" /> Install</button>}
                {info.url && <a href={info.url} target="_blank" rel="noopener noreferrer" style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)', display: 'flex', alignItems: 'center', gap: 2 }}><ExternalLink size={10} /></a>}
              </div>
            </div>
          )}
        </div>
      )
    }

    return (
      <div style={{ padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Section title={`TOOL DETECTION · ${available.length}/${Object.keys(toolStatus).length} INSTALLED`}
          right={
            <button onClick={loadTools} disabled={loading} className="btn btn-sm">
              <Icon name="refresh" size={11} color={loading ? 'var(--accent)' : 'currentColor'} /> {loading ? 'Detecting…' : 'Refresh'}
            </button>
          }
        >
          {missing.length > 0 && bulkInstallCmd && (
            <div style={{ padding: '10px var(--pad)', background: 'rgba(240,168,58,0.04)', borderBottom: rule }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <Package size={13} color="var(--accent)" />
                <span style={{ fontSize: 12, color: 'var(--accent)', fontFamily: 'var(--font-sans)' }}>{missing.length} tools not installed</span>
                {hostInfo && <span className="mono" style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--fg-3)' }}>{hostInfo.distro_name} · {PKG_MANAGER_LABELS[mgr] || mgr}</span>}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <code style={{ flex: 1, background: 'var(--bg)', border: ruleStrong, borderRadius: 3, padding: '6px 10px', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--fg)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{bulkInstallCmd}</code>
                <button onClick={() => copyText(bulkInstallCmd, 'bulk-all')} className="btn btn-sm">
                  <Icon name={copied === 'bulk-all' ? 'check' : 'copy'} size={11} color="currentColor" /> {copied === 'bulk-all' ? 'Copied!' : 'Copy all'}
                </button>
              </div>
            </div>
          )}
          {TIERS.map(tier => {
            const entries = Object.entries(toolStatus).filter(([, v]) => (v.tier ?? 'optional') === tier.id)
            if (entries.length === 0) return null
            const installed = entries.filter(([, v]) => v.available).length
            return (
              <div key={tier.id} style={{ borderBottom: rule }}>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, padding: '10px var(--pad) 0', flexWrap: 'wrap' }}>
                  <span className="smcap" style={{ color: tier.color }}>{tier.label}</span>
                  <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>{installed}/{entries.length} installed</span>
                  <span style={{ fontSize: 10, color: 'var(--fg-4)', marginLeft: 'auto', fontFamily: 'var(--font-sans)' }}>{tier.blurb}</span>
                </div>
                <div style={{ padding: '10px var(--pad) 14px', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 10 }}>
                  {entries.map(([name, info]) => renderToolCard(name, info))}
                </div>
              </div>
            )
          })}
        </Section>

        <Section title="AUTO-PROBE"
          right={
            <button
              onClick={() => setProbeEnabled(v => !v)}
              style={{ position: 'relative', width: 40, height: 22, borderRadius: 11, background: probeEnabled ? 'var(--ok)' : 'rgba(100,116,139,0.3)', border: 'none', cursor: 'pointer', flexShrink: 0 }}
            >
              <span style={{ position: 'absolute', top: 2, left: probeEnabled ? 20 : 2, width: 18, height: 18, borderRadius: '50%', background: 'white', transition: 'left 0.2s' }} />
            </button>
          }
        >
          <div style={{ padding: '14px var(--pad)', display: 'flex', flexDirection: 'column', gap: 14 }}>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)', lineHeight: 1.6 }}>
              Automatically run a recon chain when a new target is added to a project. Runs in the background and creates findings.
            </p>

            <div>
              <label style={{ display: 'block', marginBottom: 8, fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: 'var(--font-mono)' }}>Intensity</label>
              <div style={{ display: 'flex', gap: 6 }}>
                {(['quick', 'standard', 'deep'] as const).map(v => (
                  <button key={v} onClick={() => setProbeIntensity(v)}
                    style={{ padding: '4px 14px', fontSize: 11, fontFamily: 'var(--font-sans)', textTransform: 'capitalize', cursor: 'pointer', background: probeIntensity === v ? 'var(--accent-2)' : 'var(--bg)', border: probeIntensity === v ? '1px solid var(--accent)' : ruleStrong, color: probeIntensity === v ? 'var(--accent)' : 'var(--fg-2)' }}
                  >{v}</button>
                ))}
              </div>
            </div>

            <div>
              <label style={{ display: 'block', marginBottom: 8, fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: 'var(--font-mono)' }}>Tools</label>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {['whois', 'rustscan', 'nmap', 'nikto', 'testssl', 'nuclei', 'feroxbuster'].map(t => {
                  const active = probeTools.includes(t)
                  return (
                    <button key={t} onClick={() => toggleProbeTool(t)}
                      style={{ padding: '3px 10px', fontSize: 11, fontFamily: 'var(--font-mono)', cursor: 'pointer', background: active ? 'rgba(84,175,97,0.08)' : 'var(--bg)', border: active ? '1px solid rgba(84,175,97,0.35)' : ruleStrong, color: active ? 'var(--ok)' : 'var(--fg-3)' }}
                    >
                      {active && <CheckCircle size={9} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />}
                      {t}
                    </button>
                  )
                })}
              </div>
            </div>

            <div>
              <button onClick={saveProbeConfig} disabled={probeSaving} className="btn btn-primary">
                {probeSaving ? <Loader size={13} className="animate-spin" /> : <Save size={13} />} Save
              </button>
            </div>
          </div>
        </Section>
      </div>
    )
  }

  function renderAi() {
    return (
      <div style={{ padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Section title="AI · LOCAL LLM">
          <div style={{ padding: '14px var(--pad)', display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <Field label="Provider">
                <div style={{ display: 'flex', gap: 6 }}>
                  {[{ label: 'Ollama', value: 'ollama', url: 'http://localhost:11434' }, { label: 'LMStudio', value: 'lmstudio', url: 'http://localhost:1234' }, { label: 'Custom', value: 'custom', url: '' }].map(p => (
                    <button key={p.value} onClick={() => setAiConfig(c => ({ ...c, provider: p.value, ...(p.url ? { endpoint: p.url } : {}) }))}
                      style={{ padding: '4px 10px', borderRadius: 3, fontSize: 11, fontFamily: 'var(--font-sans)', cursor: 'pointer', background: aiConfig.provider === p.value ? 'rgba(240,168,58,0.1)' : 'none', color: aiConfig.provider === p.value ? 'var(--accent)' : 'var(--fg-3)', border: aiConfig.provider === p.value ? '1px solid rgba(240,168,58,0.35)' : ruleStrong }}
                    >{p.label}</button>
                  ))}
                </div>
              </Field>
              <Field label="API Endpoint">
                <input type="text" value={aiConfig.endpoint} onChange={e => setAiConfig(c => ({ ...c, endpoint: e.target.value, provider: 'custom' }))} placeholder="http://localhost:11434" style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }} />
              </Field>
              <Field label="Model">
                {aiModels.length > 0 ? (
                  <select value={aiConfig.model} onChange={e => setAiConfig(c => ({ ...c, model: e.target.value }))} style={inputStyle}>
                    <option value="">Select a model…</option>
                    {aiModels.map(m => <option key={m} value={m}>{m}</option>)}
                  </select>
                ) : (
                  <input type="text" value={aiConfig.model} onChange={e => setAiConfig(c => ({ ...c, model: e.target.value }))} placeholder="e.g. llama3.2, mistral" style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }} />
                )}
              </Field>
              <Field label="Timeout (s)">
                <input type="number" value={aiConfig.timeout ?? ''} onChange={e => setAiConfig(c => ({ ...c, timeout: e.target.value === '' ? null : Number(e.target.value) }))} placeholder="300" style={inputStyle} />
              </Field>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <button onClick={testAiConnection} disabled={aiTesting} className="btn">
                {aiTesting ? <Loader size={13} className="animate-spin" color="var(--accent)" /> : <Icon name="wifi" size={13} color="currentColor" />} Test endpoint
              </button>
              <button onClick={saveAiConfig} disabled={aiSaving} className="btn btn-primary">
                {aiSaving ? <Loader size={13} className="animate-spin" /> : <Save size={13} />} Save
              </button>
              {aiStatus && (
                <span style={{ fontSize: 12, color: aiStatus.online ? 'var(--ok)' : 'var(--crit)', fontFamily: 'var(--font-sans)', display: 'flex', alignItems: 'center', gap: 5 }}>
                  {aiStatus.online ? <><CheckCircle size={13} /> Connected · {aiStatus.model_count} model{aiStatus.model_count !== 1 ? 's' : ''}</> : <><WifiOff size={13} /> Offline — {aiStatus.error}</>}
                </span>
              )}
            </div>
          </div>
        </Section>

        <Section title="LOCAL OLLAMA (THIS MACHINE)">
          <div style={{ padding: '14px var(--pad)', display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>Use Ollama running on your laptop. No data leaves your machine.</span>
              <button onClick={() => setLocalOllamaSettings(s => ({ ...s, useLocalOllama: !s.useLocalOllama }))} style={{ position: 'relative', width: 40, height: 22, borderRadius: 11, background: localOllamaSettings.useLocalOllama ? 'var(--ok)' : 'rgba(100,116,139,0.3)', border: 'none', cursor: 'pointer', flexShrink: 0 }}>
                <span style={{ position: 'absolute', top: 2, left: localOllamaSettings.useLocalOllama ? 20 : 2, width: 18, height: 18, borderRadius: '50%', background: 'white', transition: 'left 0.2s' }} />
              </button>
            </div>
            {localOllamaSettings.useLocalOllama && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <Field label="Ollama URL">
                  <input type="text" value={localOllamaSettings.localOllamaUrl} onChange={e => setLocalOllamaSettings(s => ({ ...s, localOllamaUrl: e.target.value }))} placeholder="http://localhost:11434" style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }} />
                </Field>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <button onClick={testLocalOllama} disabled={localOllamaTesting} className="btn">
                    {localOllamaTesting ? <Loader size={13} className="animate-spin" /> : <Icon name="wifi" size={13} color="currentColor" />} Test
                  </button>
                  <button onClick={saveLocalOllamaSettings} disabled={localOllamaSaving} className="btn btn-primary">
                    {localOllamaSaving ? <Loader size={13} className="animate-spin" /> : <Save size={13} />} Save
                  </button>
                  {localOllamaStatus && (
                    <span style={{ fontSize: 12, color: localOllamaStatus.online ? 'var(--ok)' : 'var(--crit)', fontFamily: 'var(--font-sans)' }}>
                      {localOllamaStatus.online ? `Connected · ${localOllamaModels.length} models` : `Offline — ${localOllamaStatus.error}`}
                    </span>
                  )}
                </div>
                {localOllamaModels.length > 0 && (
                  <Field label="Model">
                    <select value={localOllamaSettings.localOllamaModel} onChange={e => setLocalOllamaSettings(s => ({ ...s, localOllamaModel: e.target.value }))} style={inputStyle}>
                      <option value="">Select a model…</option>
                      {localOllamaModels.map(m => <option key={m} value={m}>{m}</option>)}
                    </select>
                  </Field>
                )}
              </div>
            )}
          </div>
        </Section>

        <Section title="MITRE ATT&CK KNOWLEDGE BASE">
          <div style={{ padding: '14px var(--pad)', display: 'flex', flexDirection: 'column', gap: 14 }}>
            <p style={{ fontSize: 12, color: 'var(--fg-3)', margin: 0, lineHeight: 1.6 }}>
              Index the MITRE Enterprise ATT&CK dataset locally for use by the AI Operator, Playbooks, and Command Library.
              Downloaded once from MITRE's public GitHub — no account required.
            </p>

            {/* Status */}
            {attackStatus && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
                {[
                  { label: 'Techniques', value: attackStatus.count > 0 ? String(attackStatus.count) : '—' },
                  { label: 'Status',     value: attackStatus.state === 'idle' && attackStatus.count > 0 ? 'Ready' : attackStatus.state === 'idle' ? 'Not indexed' : attackStatus.state.charAt(0).toUpperCase() + attackStatus.state.slice(1) },
                  { label: 'Last Sync',  value: attackStatus.last_sync ? new Date(attackStatus.last_sync).toLocaleDateString() : '—' },
                ].map(({ label, value }) => (
                  <div key={label} style={{ background: 'var(--bg)', border: '1px solid var(--rule)', padding: '10px 12px', borderRadius: 3 }}>
                    <div className="smcap" style={{ fontSize: 9, color: 'var(--fg-3)', marginBottom: 4 }}>{label}</div>
                    <div className="mono" style={{ fontSize: 13, color: 'var(--fg)' }}>{value}</div>
                  </div>
                ))}
              </div>
            )}

            {attackStatus?.error && (
              <div style={{ fontSize: 12, color: 'var(--crit)', fontFamily: 'var(--font-mono)' }}>Error: {attackStatus.error}</div>
            )}

            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <button
                className="btn btn-primary"
                disabled={attackSyncing}
                onClick={async () => {
                  setAttackSyncing(true)
                  await fetch(`${getApiBase()}/ai/attack/sync`, { method: 'POST' })
                  // Poll status until sync completes
                  const poll = setInterval(async () => {
                    const r = await fetch(`${getApiBase()}/ai/attack/status`)
                    const s = await r.json()
                    setAttackStatus(s)
                    if (s.state === 'idle' || s.state === 'error') {
                      clearInterval(poll)
                      setAttackSyncing(false)
                    }
                  }, 2000)
                }}
              >
                {attackSyncing ? <><Loader size={12} className="animate-spin" /> Syncing…</> : 'Sync ATT&CK'}
              </button>
              <button
                className="btn"
                onClick={async () => {
                  const r = await fetch(`${getApiBase()}/ai/attack/status`)
                  setAttackStatus(await r.json())
                }}
              >
                Refresh status
              </button>
              {attackStatus && attackStatus.count > 0 && !attackSyncing && (
                <span style={{ fontSize: 12, color: 'var(--accent)', display: 'flex', alignItems: 'center', gap: 5 }}>
                  <CheckCircle size={13} /> {attackStatus.count} techniques indexed
                </span>
              )}
            </div>
          </div>
        </Section>

        <Section title="PTES KNOWLEDGE BASE">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--fg-2)', lineHeight: 1.55 }}>
              Index the Penetration Testing Execution Standard (pentest-standard.org) for use by the AI Operator.
              Provides methodology guidance on pre-engagement, intelligence gathering, exploitation, and reporting.
            </p>
            {ptesStatus && (
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                {[
                  { label: 'Sections',   value: ptesStatus.count > 0 ? String(ptesStatus.count) : '—' },
                  { label: 'Status',     value: ptesStatus.count > 0 ? 'Ready' : 'Not indexed' },
                  { label: 'Last Sync',  value: ptesStatus.last_sync ? new Date(ptesStatus.last_sync).toLocaleDateString() : '—' },
                ].map(({ label, value }) => (
                  <div key={label} style={{ padding: '8px 14px', border: '1px solid var(--rule-strong)', background: 'var(--bg-2)', minWidth: 100 }}>
                    <div style={{ fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>{label}</div>
                    <div style={{ fontSize: 13, fontWeight: 600, fontFamily: 'var(--font-mono)', color: 'var(--fg)' }}>{value}</div>
                  </div>
                ))}
              </div>
            )}
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              <button
                className="btn-primary btn-sm"
                disabled={ptesSyncing}
                onClick={async () => {
                  setPtesSyncing(true)
                  await fetch(`${getApiBase()}/ai/ptes/sync`, { method: 'POST' })
                  const poll = setInterval(async () => {
                    const r = await fetch(`${getApiBase()}/ai/ptes/status`)
                    const s = await r.json()
                    setPtesStatus(s)
                    if (!s.syncing) { setPtesSyncing(false); clearInterval(poll) }
                  }, 2000)
                }}
              >
                {ptesSyncing ? <><Loader size={12} className="animate-spin" /> Syncing…</> : 'Sync PTES'}
              </button>
              <button className="btn" onClick={loadPtesStatus}>Refresh status</button>
              {ptesStatus && ptesStatus.count > 0 && !ptesSyncing && (
                <span style={{ fontSize: 12, color: 'var(--accent)', display: 'flex', alignItems: 'center', gap: 5 }}>
                  <CheckCircle size={13} /> {ptesStatus.count} sections indexed
                </span>
              )}
            </div>
          </div>
        </Section>
      </div>
    )
  }

  function renderMsf() {
    return (
      <div style={{ padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Section title="METASPLOIT RPC">
          <div style={{ padding: '20px var(--pad)', display: 'flex', flexDirection: 'column', gap: 14, alignItems: 'flex-start' }}>
            <div style={{ display: 'flex', gap: 14, alignItems: 'flex-start' }}>
              <div style={{ width: 36, height: 36, borderRadius: 4, background: 'rgba(240,168,58,0.08)', border: '1px solid rgba(240,168,58,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                <Icon name="zap" size={16} color="var(--accent)" />
              </div>
              <div>
                <div style={{ fontSize: 13, color: 'var(--fg)', fontFamily: 'var(--font-sans)', fontWeight: 500, marginBottom: 6 }}>MSF connections are managed in the C2 Console</div>
                <div style={{ fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)', lineHeight: 1.6, maxWidth: 460 }}>
                  Use the <strong style={{ color: 'var(--fg-2)' }}>Infrastructure</strong> tab in C2 Console to add, connect, and manage Metasploit RPC nodes.
                  Multiple nodes can be registered, checked, and switched between — with encrypted credential storage.
                </div>
              </div>
            </div>
            <button onClick={() => navigate('/c2')} className="btn btn-primary">
              <Icon name="zap" size={13} color="currentColor" /> Open C2 Console
            </button>
          </div>
        </Section>
      </div>
    )
  }

  function renderNessus() {
    async function saveNessusConfig() {
      setNessusSaving(true)
      try {
        const isTenable = nessusHost.trim() === 'api.tenable.com'
        await fetch(`${getApiBase()}/nessus/config`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            host: nessusHost.trim(),
            port: parseInt(nessusPort) || 8834,
            username: nessusUsername,
            password: nessusPassword,
            verify_ssl: nessusVerifySsl,
            api_access_key: isTenable ? nessusApiAccessKey : '',
            api_secret_key: isTenable ? nessusApiSecretKey : '',
          }),
        })
      } finally {
        setNessusSaving(false)
      }
    }

    async function testNessusConnection() {
      setNessusTesting(true)
      try {
        const res = await fetch(`${getApiBase()}/nessus/status`)
        const data = await res.json()
        setNessusStatus(data)
      } finally {
        setNessusTesting(false)
      }
    }

    const isTenable = nessusHost.trim() === 'api.tenable.com'

    return (
      <div style={{ padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Section title="NESSUS / TENABLE INTEGRATION">
          <div style={{ padding: '14px var(--pad)', display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ fontSize: 11, color: 'var(--fg-3)' }}>
              Connect to a self-hosted Nessus instance or Tenable.io. Import scan results as Seraph findings from the All Findings page.
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <Field label="Host">
                <input
                  type="text"
                  value={nessusHost}
                  onChange={e => setNessusHost(e.target.value)}
                  placeholder="192.168.1.50 or api.tenable.com"
                  style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                />
              </Field>
              <Field label="Port">
                <input
                  type="text"
                  value={nessusPort}
                  onChange={e => setNessusPort(e.target.value)}
                  placeholder="8834"
                  style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
                  disabled={isTenable}
                />
              </Field>
              {!isTenable && (
                <>
                  <Field label="Username">
                    <input type="text" value={nessusUsername} onChange={e => setNessusUsername(e.target.value)} placeholder="admin" style={inputStyle} />
                  </Field>
                  <Field label="Password">
                    <input type="password" value={nessusPassword} onChange={e => setNessusPassword(e.target.value)} placeholder="••••••••" style={inputStyle} />
                  </Field>
                  <Field label="Verify SSL">
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingTop: 4 }}>
                      <button onClick={() => setNessusVerifySsl(v => !v)} style={{ position: 'relative', width: 40, height: 22, borderRadius: 11, background: nessusVerifySsl ? 'var(--ok)' : 'rgba(100,116,139,0.3)', border: 'none', cursor: 'pointer' }}>
                        <span style={{ position: 'absolute', top: 2, left: nessusVerifySsl ? 20 : 2, width: 18, height: 18, borderRadius: '50%', background: 'white', transition: 'left 0.2s' }} />
                      </button>
                      <span style={{ fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>{nessusVerifySsl ? 'Enabled' : 'Disabled'}</span>
                    </div>
                  </Field>
                </>
              )}
              {isTenable && (
                <>
                  <Field label="API Access Key">
                    <input type="password" value={nessusApiAccessKey} onChange={e => setNessusApiAccessKey(e.target.value)} placeholder="Tenable.io access key" style={inputStyle} />
                  </Field>
                  <Field label="API Secret Key">
                    <input type="password" value={nessusApiSecretKey} onChange={e => setNessusApiSecretKey(e.target.value)} placeholder="Tenable.io secret key" style={inputStyle} />
                  </Field>
                </>
              )}
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <button onClick={saveNessusConfig} disabled={nessusSaving} className="btn btn-primary">
                {nessusSaving ? <Loader size={13} className="animate-spin" /> : <Save size={13} />} Save
              </button>
              <button onClick={testNessusConnection} disabled={nessusTesting} className="btn">
                {nessusTesting ? <Loader size={13} className="animate-spin" /> : <Icon name="wifi" size={13} />} Test Connection
              </button>
              {nessusStatus && (
                <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12 }}>
                  {nessusStatus.connected
                    ? <><CheckCircle size={13} color="var(--ok)" /> <span style={{ color: 'var(--ok)' }}>Connected</span></>
                    : <><XCircle size={13} color="var(--err)" /> <span style={{ color: 'var(--err)' }}>{nessusStatus.error || 'Unreachable'}</span></>
                  }
                </span>
              )}
            </div>
            {isTenable && <div style={{ fontSize: 11, color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>Tenable.io detected — API key auth mode</div>}
          </div>
        </Section>
      </div>
    )
  }

  function renderHermes() {
    return (
      <div style={{ padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Section title="HERMES OPERATOR">
          <div style={{ padding: '14px var(--pad)', display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ fontSize: 11, color: 'var(--fg-3)', lineHeight: 1.6 }}>
              The Hermes Operator runs the Hermes Agent (Nous Research) autonomously on the backend host,
              driven by your Ollama model with smart approvals. Install it on the backend with
              <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--fg-2)' }}> pip install hermes-agent</code>.
            </div>

            {/* Status */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: hermesStatus?.installed ? 'var(--ok)' : 'var(--fg-4)' }}>
                <span className={`dot ${hermesStatus?.installed ? 'dot-live' : 'dot-idle'}`} />
                {hermesStatus ? (hermesStatus.installed ? `Hermes ${hermesStatus.version || 'ready'}` : 'Not installed') : 'Checking…'}
              </span>
              {hermesStatus && (
                <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: hermesStatus.ollama_reachable ? 'var(--ok)' : 'var(--high)' }}>
                  <span className={`dot ${hermesStatus.ollama_reachable ? 'dot-live' : 'dot-warn'}`} />
                  Ollama {hermesStatus.ollama_reachable ? 'reachable' : 'unreachable'}
                </span>
              )}
            </div>

            <Field label="Default model (optional)">
              <input
                type="text"
                value={hermesDefaultModel}
                onChange={e => setHermesDefaultModel(e.target.value)}
                placeholder="e.g. qwen2.5:14b"
                style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
              />
            </Field>

            <Field label="Allow private/RFC1918 URLs">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingTop: 4 }}>
                <button onClick={() => setHermesAllowPrivate(v => !v)} style={{ position: 'relative', width: 40, height: 22, borderRadius: 11, background: hermesAllowPrivate ? 'var(--ok)' : 'rgba(100,116,139,0.3)', border: 'none', cursor: 'pointer' }}>
                  <span style={{ position: 'absolute', top: 2, left: hermesAllowPrivate ? 20 : 2, width: 18, height: 18, borderRadius: '50%', background: 'white', transition: 'left 0.2s' }} />
                </button>
                <span style={{ fontSize: 12, color: 'var(--fg-3)' }}>Needed to reach internal lab targets</span>
              </div>
            </Field>

            <Field label="Docker sandbox">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingTop: 4 }}>
                <button onClick={() => setHermesSandbox(v => !v)} style={{ position: 'relative', width: 40, height: 22, borderRadius: 11, background: hermesSandbox ? 'var(--ok)' : 'rgba(100,116,139,0.3)', border: 'none', cursor: 'pointer' }}>
                  <span style={{ position: 'absolute', top: 2, left: hermesSandbox ? 20 : 2, width: 18, height: 18, borderRadius: '50%', background: 'white', transition: 'left 0.2s' }} />
                </button>
                <span style={{ fontSize: 12, color: 'var(--fg-3)' }}>Run tools inside a container (requires Docker on the backend)</span>
              </div>
            </Field>

            <div>
              <button onClick={saveHermesConfigSettings} disabled={hermesSaving} className="btn btn-primary btn-sm">
                {hermesSaving ? 'Saving…' : 'Save Hermes settings'}
              </button>
            </div>
          </div>
        </Section>
      </div>
    )
  }

  function renderEnv() {
    return (
      <div style={{ padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Section title="ENVIRONMENT">
          <div style={{ padding: '14px var(--pad)' }}>
            <div className="term" style={{ padding: '12px 16px', fontSize: 11, lineHeight: 1.7, maxHeight: 400, overflowY: 'auto' }}>
              {Object.entries(envVars).length > 0 ? (
                Object.entries(envVars).map(([k, v]) => (
                  <div key={k}>
                    <span className="ok">{k}</span>
                    <span className="muted">=</span>
                    <span className="stdout">{v}</span>
                  </div>
                ))
              ) : (
                <span className="muted"># No environment variables loaded — check /settings/env</span>
              )}
            </div>
          </div>
        </Section>
      </div>
    )
  }

  function renderPasskeys() {
    return (
      <div style={{ padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Section title={`PASSKEYS · ${passkeys.length} REGISTERED`}>
          <div style={{ padding: '14px var(--pad)', display: 'flex', flexDirection: 'column', gap: 12 }}>
            {passkeys.length > 0 && (
              <table className="data" style={{ marginBottom: 8 }}>
                <thead><tr><th>Name</th><th style={{ width: 130 }}>Added</th><th style={{ width: 50 }}></th></tr></thead>
                <tbody>
                  {passkeys.map(pk => (
                    <tr key={pk.id}>
                      <td><span style={{ fontSize: 13 }}>{pk.name}</span></td>
                      <td><span className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>{new Date(pk.created_at).toLocaleDateString()}</span></td>
                      <td>
                        <button onClick={() => handleDeletePasskey(pk.id)} className="btn-sm btn-danger">
                          <Icon name="trash" size={11} color="currentColor" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <Field label="Passkey name (optional)">
              <input type="text" value={newPasskeyName} onChange={e => setNewPasskeyName(e.target.value)} placeholder="iCloud Keychain" style={inputStyle} />
            </Field>
            {passkeyError && <p style={{ margin: 0, fontSize: 11, color: 'var(--crit)', fontFamily: 'var(--font-sans)' }}>{passkeyError}</p>}
            <div>
              <button type="button" onClick={handleRegisterPasskey} disabled={passkeyRegLoading} className="btn btn-primary">
                {passkeyRegLoading ? <Loader size={13} className="animate-spin" /> : <Icon name="fingerprint" size={13} color="currentColor" />}
                {passkeys.length > 0 ? 'Add Another Passkey' : 'Register Passkey'}
              </button>
            </div>
          </div>
        </Section>

        {/* API Tokens */}
        <Section title="API TOKENS">
          <div style={{ padding: '14px var(--pad)', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {revealedToken && (
              <div style={{ background: 'rgba(240,168,58,0.06)', border: '1px solid rgba(240,168,58,0.3)', borderRadius: 3, padding: 10, marginBottom: 4 }}>
                <p style={{ margin: '0 0 6px', fontSize: 11, color: 'var(--accent)', fontFamily: 'var(--font-sans)', fontWeight: 600 }}>Copy this token now — it won't be shown again.</p>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <code className="mono" style={{ flex: 1, fontSize: 11, color: 'var(--fg)', wordBreak: 'break-all' }}>{revealedToken}</code>
                  <button onClick={handleCopyToken} style={{ background: 'none', border: 'none', cursor: 'pointer', color: tokenCopied ? 'var(--ok)' : 'var(--fg-3)', padding: 0, display: 'flex', flexShrink: 0 }}>
                    <Icon name={tokenCopied ? 'check' : 'copy'} size={13} color="currentColor" />
                  </button>
                  <button onClick={() => setRevealedToken(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0, display: 'flex', flexShrink: 0 }}>
                    <Icon name="x" size={13} color="currentColor" />
                  </button>
                </div>
              </div>
            )}
            {apiTokens.length > 0 && (
              <table className="data" style={{ marginBottom: 6 }}>
                <thead><tr><th>Name</th><th>Prefix</th><th style={{ width: 130 }}>Last used</th><th style={{ width: 50 }}></th></tr></thead>
                <tbody>
                  {apiTokens.map(t => (
                    <tr key={t.id}>
                      <td style={{ fontSize: 13 }}>{t.name}</td>
                      <td><span className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>srph_{t.prefix}…</span></td>
                      <td><span className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>{t.last_used_at ? new Date(t.last_used_at).toLocaleDateString() : 'never'}</span></td>
                      <td>
                        <button onClick={() => handleRevokeToken(t.id)} className="btn-sm btn-danger">
                          <Icon name="trash" size={11} color="currentColor" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <div style={{ display: 'flex', gap: 8 }}>
              <input type="text" value={newTokenName} onChange={e => setNewTokenName(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleGenerateToken()} placeholder='Token name (e.g. "Chronos — Laptop")' style={{ ...inputStyle, flex: 1, width: 'auto' }} />
              <button onClick={handleGenerateToken} disabled={tokenGenerating || !newTokenName.trim()} className="btn btn-primary" style={{ opacity: (tokenGenerating || !newTokenName.trim()) ? 0.5 : 1, flexShrink: 0 }}>
                {tokenGenerating ? <Loader size={13} className="animate-spin" /> : <Icon name="key" size={13} color="currentColor" />} Generate
              </button>
            </div>
          </div>
        </Section>

        <Section title="WEBHOOKS">
          <div style={{ padding: '14px var(--pad)', display: 'flex', flexDirection: 'column', gap: 12 }}>
            {webhookError && <p style={{ margin: 0, fontSize: 11, color: 'var(--crit)', fontFamily: 'var(--font-sans)' }}>{webhookError}</p>}
            <form onSubmit={handleCreateWebhook} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <Field label="Name"><input placeholder="Slack alerts" value={webhookForm.name} onChange={e => setWebhookForm(f => ({ ...f, name: e.target.value }))} style={inputStyle} /></Field>
                <Field label="URL"><input placeholder="https://hooks.slack.com/…" value={webhookForm.url} onChange={e => setWebhookForm(f => ({ ...f, url: e.target.value }))} style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }} /></Field>
              </div>
              <Field label="Events">
                <div style={{ display: 'flex', gap: 6 }}>
                  {(['critical', 'warning', 'info', 'all'] as const).map(ev => {
                    const on = webhookForm.events.includes(ev)
                    const col = ev === 'critical' ? 'var(--crit)' : ev === 'warning' ? 'var(--accent)' : ev === 'info' ? 'var(--fg-2)' : 'var(--ok)'
                    return <button key={ev} type="button" onClick={() => toggleWebhookEvent(ev)} style={{ padding: '3px 10px', borderRadius: 3, fontSize: 11, fontFamily: 'var(--font-sans)', textTransform: 'capitalize', cursor: 'pointer', background: on ? `${col}18` : 'none', color: on ? col : 'var(--fg-3)', border: on ? `1px solid ${col}55` : ruleStrong }}>{ev}</button>
                  })}
                </div>
              </Field>
              <div><button type="submit" disabled={webhookSaving} className="btn btn-primary">{webhookSaving ? 'Saving…' : 'Add Webhook'}</button></div>
            </form>
            {webhooks.length > 0 && (
              <table className="data">
                <thead><tr><th>Name</th><th>URL</th><th style={{ width: 90 }}>Status</th><th style={{ width: 120 }}></th></tr></thead>
                <tbody>
                  {webhooks.map(wh => (
                    <tr key={wh.id}>
                      <td style={{ fontSize: 13 }}>{wh.name}</td>
                      <td><span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block', maxWidth: 180 }}>{wh.url}</span></td>
                      <td>{wh.active ? <Pill tone="pass">active</Pill> : <Pill tone="info">paused</Pill>}</td>
                      <td>
                        <div style={{ display: 'flex', gap: 6 }}>
                          <button onClick={() => handleTestWebhook(wh.id)} disabled={webhookTestId === wh.id} className="btn btn-sm">{webhookTestId === wh.id ? '✓' : 'Test'}</button>
                          <button onClick={() => handleToggleWebhook(wh.id, !wh.active)} className="btn btn-sm">{wh.active ? 'Pause' : 'Resume'}</button>
                          <button onClick={() => handleDeleteWebhook(wh.id)} className="btn-sm btn-danger"><Icon name="trash" size={11} color="currentColor" /></button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </Section>
      </div>
    )
  }

  function renderDemo() {
    return (
      <div style={{ padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Section title="DEMO DATA">
          <div style={{ padding: '14px var(--pad)', display: 'flex', flexDirection: 'column', gap: 12 }}>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)', lineHeight: 1.6 }}>
              Populate the platform with three realistic demo projects — external pentest, web app audit, and internal network assessment — with targets, findings, credentials, and vulnerabilities. Turning off removes all demo data cleanly.
            </p>
            {demoError && <p style={{ margin: 0, fontSize: 11, color: 'var(--crit)', fontFamily: 'var(--font-sans)' }}>{demoError}</p>}
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              {demoActive ? (
                <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--accent)', fontFamily: 'var(--font-sans)' }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent)', boxShadow: '0 0 6px rgba(240,168,58,0.8)' }} /> Demo mode active — 3 projects seeded
                </span>
              ) : (
                <span style={{ fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>Demo mode off</span>
              )}
              <button onClick={handleDemoToggle} disabled={demoLoading} className={demoActive ? 'btn btn-danger' : 'btn btn-primary'}>
                {demoLoading ? <Loader size={13} className="animate-spin" /> : <FlaskConical size={13} />}
                {demoLoading ? (demoActive ? 'Clearing…' : 'Seeding…') : (demoActive ? 'Remove demo data' : 'Load demo data')}
              </button>
            </div>
          </div>
        </Section>

      </div>
    )
  }

  function renderAppearance() {
    const ACCENT_SWATCHES: { value: import('@/contexts/ThemeContext').Accent; label: string; color: string }[] = [
      { value: 'amber',          label: 'Amber',   color: '#f0a83a' },
      { value: 'cyan',           label: 'Cyan',    color: '#5fb6c4' },
      { value: 'electric-green', label: 'Green',   color: '#8ad26b' },
      { value: 'signal-red',     label: 'Red',     color: '#e85c4e' },
      { value: 'violet',         label: 'Violet',  color: '#b794f6' },
      { value: 'azure',          label: 'Azure',   color: '#5b8def' },
      { value: 'teal',           label: 'Teal',    color: '#45c0a4' },
      { value: 'magenta',        label: 'Magenta', color: '#d96fb8' },
      { value: 'ember',          label: 'Ember',   color: '#f0794a' },
      { value: 'steel',          label: 'Steel',   color: '#8f9bad' },
    ]
    const BG_OPTIONS: { value: import('@/contexts/ThemeContext').BgVariant; label: string; swatch: string }[] = [
      { value: 'paper',      label: 'Paper Dark', swatch: '#0d0c0a' },
      { value: 'true-black', label: 'True Black', swatch: '#000000' },
      { value: 'midnight',   label: 'Midnight',   swatch: '#07091a' },
      { value: 'slate',      label: 'Slate',      swatch: '#0e1217' },
      { value: 'abyss',      label: 'Abyss',      swatch: '#07130f' },
      { value: 'nebula',     label: 'Nebula',     swatch: '#0c0816' },
      { value: 'day',        label: 'Daylight',   swatch: '#f5f2ea' },
    ]
    type Accent = import('@/contexts/ThemeContext').Accent
    type BgVariant = import('@/contexts/ThemeContext').BgVariant
    const PRESETS: { name: string; accent: Accent; bg: BgVariant; color: string }[] = [
      { name: 'Seraph',   accent: 'amber',          bg: 'paper',      color: '#f0a83a' },
      { name: 'Cobalt',   accent: 'azure',          bg: 'midnight',   color: '#5b8def' },
      { name: 'Matrix',   accent: 'electric-green', bg: 'true-black', color: '#8ad26b' },
      { name: 'Tidal',    accent: 'teal',           bg: 'abyss',      color: '#45c0a4' },
      { name: 'Nebula',   accent: 'violet',         bg: 'nebula',     color: '#b794f6' },
      { name: 'Daybreak', accent: 'amber',          bg: 'day',        color: '#f0a83a' },
    ]
    const DENSITY_OPTIONS: import('@/contexts/ThemeContext').Density[] = ['compact', 'standard', 'roomy']
    return (
      <div style={{ padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Section title="PRESETS">
          <div style={{ padding: '14px var(--pad)' }}>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {PRESETS.map(p => {
                const isActive = accent === p.accent && bg === p.bg
                return (
                  <button key={p.name} onClick={() => { setAccent(p.accent); setBg(p.bg) }} title={`${p.name} — ${p.accent} on ${p.bg}`}
                    style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 12px', borderRadius: 3, cursor: 'pointer', fontSize: 11, fontFamily: 'var(--font-sans)', background: isActive ? `${p.color}18` : 'var(--bg)', border: isActive ? `1px solid ${p.color}` : ruleStrong, color: isActive ? p.color : 'var(--fg-2)' }}
                  >
                    <span style={{ width: 12, height: 12, borderRadius: '50%', background: p.color, flexShrink: 0 }} />
                    {p.name}
                    {isActive && <CheckCircle size={10} />}
                  </button>
                )
              })}
            </div>
          </div>
        </Section>
        <Section title="ACCENT COLOR">
          <div style={{ padding: '14px var(--pad)' }}>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {ACCENT_SWATCHES.map(s => {
                const isActive = accent === s.value
                return (
                  <button key={s.value} onClick={() => setAccent(s.value)} title={s.label}
                    style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 12px', borderRadius: 3, cursor: 'pointer', fontSize: 11, fontFamily: 'var(--font-sans)', background: isActive ? `${s.color}18` : 'var(--bg)', border: isActive ? `1px solid ${s.color}` : ruleStrong, color: isActive ? s.color : 'var(--fg-2)' }}
                  >
                    <span style={{ width: 12, height: 12, borderRadius: '50%', background: s.color, flexShrink: 0 }} />
                    {s.label}
                    {isActive && <CheckCircle size={10} />}
                  </button>
                )
              })}
            </div>
          </div>
        </Section>
        <Section title="BACKGROUND">
          <div style={{ padding: '14px var(--pad)' }}>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {BG_OPTIONS.map(opt => {
                const isActive = bg === opt.value
                return (
                  <button key={opt.value} onClick={() => setBg(opt.value)} title={opt.label}
                    style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 12px', borderRadius: 3, cursor: 'pointer', fontSize: 11, fontFamily: 'var(--font-sans)', background: isActive ? 'var(--accent-2)' : 'var(--bg)', border: isActive ? '1px solid var(--accent)' : ruleStrong, color: isActive ? 'var(--accent)' : 'var(--fg-2)' }}
                  >
                    <span style={{ width: 12, height: 12, border: '1px solid var(--rule-strong)', background: opt.swatch, flexShrink: 0 }} />
                    {opt.label}
                    {isActive && <CheckCircle size={10} />}
                  </button>
                )
              })}
            </div>
          </div>
        </Section>
        <Section title="DENSITY">
          <div style={{ padding: '14px var(--pad)' }}>
            <div style={{ display: 'flex', gap: 8 }}>
              {DENSITY_OPTIONS.map(v => {
                const isActive = density === v
                return (
                  <button key={v} onClick={() => setDensity(v)}
                    style={{ padding: '5px 18px', borderRadius: 3, fontSize: 11, fontFamily: 'var(--font-sans)', textTransform: 'capitalize', cursor: 'pointer', background: isActive ? 'var(--accent-2)' : 'var(--bg)', border: isActive ? '1px solid var(--accent)' : ruleStrong, color: isActive ? 'var(--accent)' : 'var(--fg-2)' }}
                  >{v}</button>
                )
              })}
            </div>
          </div>
        </Section>
      </div>
    )
  }

  function renderContent() {
    switch (activeNav) {
      case 'users':      return renderUsers()
      case 'appearance': return renderAppearance()
      case 'tools':      return renderTools()
      case 'ai':         return renderAi()
      case 'msf':        return renderMsf()
      case 'nessus':     return renderNessus()
      case 'hermes':     return renderHermes()
      case 'env':        return renderEnv()
      case 'passkeys':   return renderPasskeys()
      case 'demo':       return renderDemo()
    }
  }

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg)', color: 'var(--fg)' }}>

      {/* PageHeader */}
      <div style={{ borderBottom: rule, padding: '24px var(--pad) 18px', flexShrink: 0 }}>
        <h1 className="mono" style={{ margin: 0, fontWeight: 500, fontSize: 22, letterSpacing: '-0.01em' }}>Settings</h1>
        <div style={{ color: 'var(--fg-3)', fontSize: 12, marginTop: 6 }}>Server-side configuration · admin only</div>
      </div>

      {/* 2-pane grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr', flex: 1, minHeight: 0 }}>

        {/* Left nav */}
        <div style={{ borderRight: rule, overflowY: 'auto' }}>
          {NAV_ITEMS.map(item => {
            const active = activeNav === item.id
            return (
              <button
                key={item.id}
                onClick={() => setActiveNav(item.id as NavId)}
                style={{
                  width: '100%',
                  padding: '12px 16px',
                  textAlign: 'left',
                  fontSize: 12.5,
                  fontFamily: 'var(--font-sans)',
                  background: active ? 'var(--accent-2)' : 'transparent',
                  color: active ? 'var(--accent)' : 'var(--fg-2)',
                  border: 'none',
                  borderBottom: rule,
                  borderLeft: active ? '2px solid var(--accent)' : '2px solid transparent',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                }}
              >
                {item.id === 'users'      && <Icon name="user"        size={13} color="currentColor" />}
                {item.id === 'appearance' && <Palette size={13} />}
                {item.id === 'tools'      && <Icon name="terminal"    size={13} color="currentColor" />}
                {item.id === 'ai'         && <Brain size={13} />}
                {item.id === 'msf'        && <Icon name="zap"         size={13} color="currentColor" />}
                {item.id === 'nessus'     && <Icon name="scan"        size={13} color="currentColor" />}
                {item.id === 'hermes'     && <Icon name="cpu"         size={13} color="currentColor" />}
                {item.id === 'env'        && <Monitor size={13} />}
                {item.id === 'passkeys'   && <Icon name="fingerprint" size={13} color="currentColor" />}
                {item.id === 'demo'       && <FlaskConical size={13} />}
                {item.label}
              </button>
            )
          })}
        </div>

        {/* Right content */}
        <div style={{ overflowY: 'auto' }}>
          {renderContent()}
        </div>
      </div>

      {/* Tool info modal */}
      {infoTool && (() => {
        const data = TOOL_INFO[infoTool]
        const entry = toolStatus[infoTool]
        if (!data) return null
        return (
          <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.65)' }} onClick={() => setInfoTool(null)}>
            <div style={{ width: 520, maxHeight: '80vh', display: 'flex', flexDirection: 'column', background: 'var(--bg)', border: ruleStrong, borderRadius: 4, boxShadow: '0 8px 40px rgba(0,0,0,0.6)', overflow: 'hidden' }} onClick={e => e.stopPropagation()}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '14px 18px', borderBottom: rule, flexShrink: 0 }}>
                <Info size={15} color="var(--accent)" />
                <span className="mono" style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)', flex: 1 }}>{entry?.label || infoTool}</span>
                {entry?.available ? <Pill tone="pass">installed</Pill> : <Pill tone="fail">not installed</Pill>}
                {entry?.url && <a href={entry.url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--fg-3)', display: 'flex' }}><ExternalLink size={13} /></a>}
                <button onClick={() => setInfoTool(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0, display: 'flex' }}><Icon name="x" size={15} color="currentColor" /></button>
              </div>
              <div style={{ flex: 1, overflowY: 'auto', padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: 14 }}>
                <p style={{ margin: 0, fontSize: 13, color: 'var(--fg)', fontFamily: 'var(--font-sans)', lineHeight: 1.6 }}>{data.description}</p>
                {data.usedIn.length > 0 && (
                  <div>
                    <div className="smcap" style={{ marginBottom: 8 }}>Used in Seraph</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {data.usedIn.map((u, i) => {
                        const fs = FEATURE_STYLES[u.feature] ?? { color: 'var(--fg-3)', background: 'rgba(100,116,139,0.1)', border: '1px solid rgba(100,116,139,0.2)' }
                        return (
                          <div key={i} style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                            <span style={{ flexShrink: 0, fontSize: 11, fontWeight: 500, padding: '2px 8px', borderRadius: 3, fontFamily: 'var(--font-sans)', color: fs.color, background: fs.background, border: fs.border }}>{u.feature}</span>
                            <span style={{ fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)', lineHeight: 1.5 }}>{u.detail}</span>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
                {!entry?.available && entry?.install_hint && (
                  <div>
                    <div className="smcap" style={{ marginBottom: 8 }}>Install</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <code style={{ flex: 1, background: 'var(--bg-2)', border: ruleStrong, borderRadius: 3, padding: '6px 10px', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--fg)', wordBreak: 'break-all' }}>{entry.install_hint}</code>
                      <button onClick={() => copyText(entry.install_hint!, `info-${infoTool}`)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied === `info-${infoTool}` ? 'var(--ok)' : 'var(--fg-3)', padding: 0, flexShrink: 0, display: 'flex' }}>
                        <Icon name={copied === `info-${infoTool}` ? 'check' : 'copy'} size={13} color="currentColor" />
                      </button>
                    </div>
                  </div>
                )}
              </div>
              <div style={{ padding: '10px 18px', borderTop: rule, display: 'flex', alignItems: 'center', justifyContent: 'flex-end', flexShrink: 0 }}>
                {!entry?.available && (
                  <button onClick={() => { setInfoTool(null); startInstall(infoTool) }} className="btn btn-primary">
                    <Icon name="download" size={11} color="currentColor" /> Install now
                  </button>
                )}
              </div>
            </div>
          </div>
        )
      })()}

      {/* Install modal */}
      {installTool && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.65)' }}>
          <div style={{ width: 640, maxHeight: '80vh', display: 'flex', flexDirection: 'column', background: 'var(--bg)', border: ruleStrong, borderRadius: 4, boxShadow: '0 8px 40px rgba(0,0,0,0.6)', overflow: 'hidden' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '14px 18px', borderBottom: rule, flexShrink: 0 }}>
              <Icon name="terminal" size={15} color="var(--accent)" />
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)', fontFamily: 'var(--font-sans)', flex: 1 }}>
                Installing <span className="mono" style={{ color: 'var(--accent)' }}>{toolStatus[installTool]?.label || installTool}</span>
              </span>
              {installDone && <Pill tone="pass">Done</Pill>}
              <button onClick={() => setInstallTool(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0, display: 'flex' }}><Icon name="x" size={15} color="currentColor" /></button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', minHeight: 200 }}>
              <pre className="term" style={{ margin: 0, fontSize: 11, padding: '14px 18px', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
                {installLines.length === 0
                  ? <span className="muted">Connecting…</span>
                  : <span className="stdout">{installLines.join('')}</span>
                }
              </pre>
            </div>
            {installDone && (
              <div style={{ padding: '10px 18px', borderTop: rule, display: 'flex', justifyContent: 'flex-end', flexShrink: 0 }}>
                <button onClick={() => setInstallTool(null)} className="btn btn-primary">Close</button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
