import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  RefreshCw, CheckCircle, XCircle, Copy, Check,
  Trash2, Package, Terminal, Brain, Wifi, WifiOff, Save, Loader,
  Users, ShieldCheck, UserPlus, Eye, EyeOff, KeyRound,
  Zap, Gauge, Palette, Monitor, FlaskConical, Download, X,
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { useTheme } from '../contexts/ThemeContext'

interface ToolInfo {
  available: boolean
  path: string | null
  version: string | null
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
  openscap:     { apt: 'openscap-scanner', dnf: 'openscap-scanner', zypper: 'openscap' },
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
  aws:          { apt: 'awscli',           dnf: 'awscli',         pacman: 'aws-cli',     brew: 'awscli',        zypper: 'aws-cli' },
  hashcat:      { apt: 'hashcat',          dnf: 'hashcat',        pacman: 'hashcat',     brew: 'hashcat' },
  john:         { apt: 'john',             dnf: 'john',           pacman: 'john',        brew: 'john' },
}

function getInstallCmd(toolName: string, hostInfo: HostInfo | null): string {
  const pkgs = TOOL_PKGS[toolName]
  if (!pkgs) return ''
  const mgr = hostInfo?.pkg_manager || 'apt'
  const pkg = pkgs[mgr]
  if (pkg) {
    if (mgr === 'apt') return `sudo apt-get install -y ${pkg}`
    if (mgr === 'dnf' || mgr === 'yum') return `sudo ${mgr} install -y ${pkg}`
    if (mgr === 'pacman') return `sudo pacman -S --noconfirm ${pkg}`
    if (mgr === 'apk') return `sudo apk add ${pkg}`
    if (mgr === 'zypper') return `sudo zypper install -y ${pkg}`
    if (mgr === 'brew') return `brew install ${pkg}`
  }
  // Fall back to go install
  const go = pkgs['go']
  if (go) return `go install ${go}`
  return ''
}

function getBulkInstallCmd(toolNames: string[], hostInfo: HostInfo | null): string {
  const mgr = hostInfo?.pkg_manager || 'apt'
  const pkgList = toolNames
    .map(n => TOOL_PKGS[n]?.[mgr])
    .filter(Boolean) as string[]
  if (!pkgList.length) return ''
  if (mgr === 'apt') return `sudo apt-get update && sudo apt-get install -y ${pkgList.join(' ')}`
  if (mgr === 'dnf' || mgr === 'yum') return `sudo ${mgr} install -y ${pkgList.join(' ')}`
  if (mgr === 'pacman') return `sudo pacman -S --noconfirm ${pkgList.join(' ')}`
  if (mgr === 'apk') return `sudo apk add ${pkgList.join(' ')}`
  if (mgr === 'zypper') return `sudo zypper install -y ${pkgList.join(' ')}`
  if (mgr === 'brew') return `brew install ${pkgList.join(' ')}`
  return ''
}

const PKG_MANAGER_LABELS: Record<string, string> = {
  apt: 'Debian / Ubuntu', dnf: 'Fedora / RHEL', yum: 'CentOS / RHEL',
  pacman: 'Arch Linux', apk: 'Alpine', zypper: 'openSUSE', brew: 'macOS (Homebrew)',
}

interface AIConfig {
  endpoint: string
  model: string
  provider: string
}

interface AIStatus {
  online: boolean
  endpoint: string
  model_count?: number
  error?: string
}

export default function Settings() {
  const [activeTab, setActiveTab] = useState<'tools' | 'profiles' | 'ai' | 'users' | 'autoprobe' | 'appearance'>('tools')
  const { user: currentUser, token: authToken, refreshUser } = useAuth()
  const { theme, setTheme } = useTheme()
  const navigate = useNavigate()
  const [toolStatus, setToolStatus] = useState<Record<string, ToolInfo>>({})
  const [hostInfo, setHostInfo] = useState<HostInfo | null>(null)
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState('')
  const [profiles, setProfiles] = useState<Profile[]>([])

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
  const [probeTools, setProbeTools] = useState<string[]>(['whois', 'nmap', 'nikto', 'testssl'])
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

  // Demo mode state
  const [demoActive, setDemoActive] = useState(false)
  const [demoLoading, setDemoLoading] = useState(false)
  const [demoError, setDemoError] = useState('')

  // AI config state
  const [aiConfig, setAiConfig] = useState<AIConfig>({ endpoint: 'http://localhost:11434', model: '', provider: 'ollama' })
  const [aiStatus, setAiStatus] = useState<AIStatus | null>(null)
  const [aiModels, setAiModels] = useState<string[]>([])
  const [aiSaving, setAiSaving] = useState(false)
  const [aiTesting, setAiTesting] = useState(false)

  useEffect(() => {
    loadTools()
    loadProfiles()
    loadAiConfig()
    loadProbeConfig()
    if (currentUser?.role === 'admin') {
      loadUsers()
      loadDemoStatus()
    }
  }, [])

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
  const pkgMgrMissing = missingNames.filter(n => TOOL_PKGS[n]?.[mgr])
  const goMissing = missing.filter(([name]) => !TOOL_PKGS[name]?.[mgr] && TOOL_PKGS[name]?.['go'])
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

              {goMissing.length > 0 && (
                <div>
                  <div className="text-xs text-slate-400 mb-2">Install via Go (requires <code className="text-cyan-400">go</code> on PATH):</div>
                  <div className="space-y-1">
                    {goMissing.map(([name]) => {
                      const cmd = `go install ${TOOL_PKGS[name]?.['go']}`
                      return (
                        <div key={name} className="flex items-center gap-2">
                          <code className="flex-1 rounded px-3 py-1.5 text-xs font-mono text-slate-300 border border-cyan-900/20" style={{ background: '#05080d' }}>
                            {cmd}
                          </code>
                          <button
                            onClick={() => copyText(cmd, `go-${name}`)}
                            className="flex-shrink-0 px-2 py-1.5 rounded text-xs text-slate-400 hover:text-slate-200 border border-cyan-900/20 hover:border-cyan-900/40"
                            style={{ background: '#0d1520' }}
                          >
                            {copied === `go-${name}` ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
                          </button>
                        </div>
                      )
                    })}
                  </div>
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
              {Object.entries(toolStatus).map(([name, info]) => (
                <div
                  key={name}
                  className={`glass glass-hover rounded-xl p-4 border-l-4 transition-all ${
                    info.available ? 'border-l-green-500' : 'border-l-red-500'
                  }`}
                >
                  <div className="flex items-center gap-3 mb-2">
                    {info.available
                      ? <CheckCircle size={16} className="text-green-500 flex-shrink-0" style={{ filter: 'drop-shadow(0 0 4px rgba(34,197,94,0.5))' }} />
                      : <XCircle size={16} className="text-red-500 flex-shrink-0" style={{ filter: 'drop-shadow(0 0 4px rgba(239,68,68,0.5))' }} />
                    }
                    <span className="font-mono text-sm font-semibold text-slate-200">{name}</span>
                  </div>
                  {info.available ? (
                    <div className="space-y-1">
                      {info.path && (
                        <div className="text-xs font-mono text-slate-400 truncate">{info.path}</div>
                      )}
                      {info.version && (
                        <div className="text-xs text-slate-500 truncate">{info.version.slice(0, 60)}</div>
                      )}
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <div className="text-xs text-red-400">Not installed</div>
                      {getInstallCmd(name, hostInfo) && (
                        <div className="flex items-center gap-2">
                          <code className="flex-1 text-xs font-mono text-slate-400 truncate">
                            {getInstallCmd(name, hostInfo)}
                          </code>
                          <button
                            onClick={() => copyText(getInstallCmd(name, hostInfo), `tool-${name}`)}
                            className="flex-shrink-0 text-slate-500 hover:text-slate-300"
                          >
                            {copied === `tool-${name}` ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
                          </button>
                        </div>
                      )}
                      <button
                        onClick={() => startInstall(name)}
                        className="flex items-center gap-1.5 px-3 py-1 rounded text-xs bg-cyan-600/15 text-cyan-400 border border-cyan-600/25 hover:bg-cyan-600/25 transition-colors"
                      >
                        <Download size={11} /> Install
                      </button>
                    </div>
                  )}
                </div>
              ))}
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
                    { name: 'whois', label: 'whois', desc: 'Domain registration & ASN info', always: true },
                    { name: 'nmap', label: 'nmap', desc: 'Port scan & service detection', always: true },
                    { name: 'nikto', label: 'nikto', desc: 'Web server scan (if port 80/443 open)', always: false },
                    { name: 'testssl', label: 'testssl', desc: 'TLS/SSL audit (if port 443 open)', always: false },
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
                    { value: 'quick', label: 'Quick', desc: '2 min timeout' },
                    { value: 'standard', label: 'Standard', desc: '5 min timeout' },
                    { value: 'deep', label: 'Deep', desc: '10 min timeout' },
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

      {/* Install modal */}
      {installTool && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-[640px] max-h-[80vh] flex flex-col rounded-xl border border-cyan-900/30 shadow-2xl" style={{ background: '#070d17' }}>
            {/* Header */}
            <div className="flex items-center gap-3 px-5 py-4 border-b border-cyan-900/20 shrink-0">
              <Terminal size={16} className="text-cyan-400" />
              <span className="text-sm font-semibold text-white">Installing <span className="font-mono text-cyan-300">{installTool}</span></span>
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
