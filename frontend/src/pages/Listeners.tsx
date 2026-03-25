import { useState, useEffect } from 'react'
import {
  Radio, BarChart2, Activity, Cpu,
  Play, Pause, Square, Trash2, Plus, ChevronDown,
  ChevronRight, Clock, AlertTriangle, CheckCircle, XCircle,
  Minus, RefreshCw,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

type ListenerType = 'scheduled' | 'threshold' | 'healthcheck' | 'agent_audit'
type ListenerStatus = 'running' | 'paused' | 'stopped'
type EventOutcome = 'triggered' | 'skipped' | 'error'

interface ListenerRecord {
  id: string
  name: string
  type: ListenerType
  project_id: string
  target_id: string | null
  config: Record<string, unknown>
  status: ListenerStatus
  last_triggered: string | null
  created_at: string
}

interface ListenerEvent {
  id: string
  listener_id: string
  fired_at: string
  outcome: EventOutcome
  detail: string
}

interface Project { id: string; name: string }
interface Target { id: string; hostname_or_ip: string; project_id: string }
interface ScanCategory { id: string; label: string }
interface AgentOption { id: string; name: string }

// ── Helpers ───────────────────────────────────────────────────────────────────

const TYPE_META: Record<ListenerType, { label: string; icon: React.ReactNode; color: string }> = {
  scheduled:   { label: 'Scheduled',    icon: <Clock size={13} />,    color: 'text-cyan-400 border-cyan-500/30 bg-cyan-500/10' },
  threshold:   { label: 'Threshold',    icon: <BarChart2 size={13} />, color: 'text-amber-400 border-amber-500/30 bg-amber-500/10' },
  healthcheck: { label: 'Health Check', icon: <Activity size={13} />, color: 'text-green-400 border-green-500/30 bg-green-500/10' },
  agent_audit: { label: 'Agent Audit',  icon: <Cpu size={13} />,      color: 'text-purple-400 border-purple-500/30 bg-purple-500/10' },
}

const STATUS_META: Record<ListenerStatus, { label: string; color: string; dot: string }> = {
  running: { label: 'running', color: 'text-green-300',  dot: 'bg-green-400' },
  paused:  { label: 'paused',  color: 'text-amber-300',  dot: 'bg-amber-400' },
  stopped: { label: 'stopped', color: 'text-slate-400',  dot: 'bg-slate-500' },
}

const OUTCOME_META: Record<EventOutcome, { icon: React.ReactNode; color: string }> = {
  triggered: { icon: <CheckCircle size={12} />, color: 'text-cyan-400' },
  skipped:   { icon: <Minus size={12} />,       color: 'text-slate-500' },
  error:     { icon: <XCircle size={12} />,     color: 'text-red-400'  },
}

function fmtTime(iso: string | null) {
  if (!iso) return '—'
  const d = new Date(iso)
  const diff = Date.now() - d.getTime()
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return d.toLocaleDateString()
}

function configSummary(type: ListenerType, config: Record<string, unknown>): string {
  if (type === 'scheduled') return `cron: ${config.cron ?? '?'}`
  if (type === 'threshold')
    return `${config.severity ?? '?'} > ${config.limit ?? '?'} · every ${config.check_interval_minutes ?? '?'}m`
  if (type === 'healthcheck')
    return `port ${config.port ?? '?'} · every ${config.interval_minutes ?? '?'}m · alert on ${config.alert_on ?? '?'}`
  if (type === 'agent_audit') {
    const cats = Array.isArray(config.categories) ? (config.categories as string[]).join(', ') : '?'
    return `cron: ${config.cron ?? '?'} · categories: ${cats}`
  }
  return ''
}

// ── Listener card ─────────────────────────────────────────────────────────────

function ListenerCard({
  listener, projects, targets, onAction, onDelete,
}: {
  listener: ListenerRecord
  projects: Project[]
  targets: Target[]
  onAction: (id: string, action: 'start' | 'pause' | 'stop') => void
  onDelete: (id: string) => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [events, setEvents] = useState<ListenerEvent[]>([])
  const [loadingEvents, setLoadingEvents] = useState(false)

  const type = TYPE_META[listener.type]
  const status = STATUS_META[listener.status]
  const project = projects.find(p => p.id === listener.project_id)
  const target = targets.find(t => t.id === listener.target_id)

  function loadEvents() {
    if (loadingEvents) return
    setLoadingEvents(true)
    fetch(`/api/v1/listeners/${listener.id}/events`)
      .then(r => r.json())
      .then(setEvents)
      .finally(() => setLoadingEvents(false))
  }

  function toggle() {
    if (!expanded) loadEvents()
    setExpanded(e => !e)
  }

  return (
    <div className="rounded-xl border border-cyan-900/20 overflow-hidden" style={{ background: '#090d14' }}>
      {/* Header row */}
      <div className="flex items-center gap-3 px-4 py-3">
        {/* Status dot */}
        <div className="relative shrink-0">
          <span className={`w-2 h-2 rounded-full inline-block ${status.dot}`} />
          {listener.status === 'running' && (
            <span className={`absolute inset-0 rounded-full animate-ping ${status.dot} opacity-60`} />
          )}
        </div>

        {/* Type badge */}
        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium border ${type.color}`}>
          {type.icon}{type.label}
        </span>

        {/* Name */}
        <span className="flex-1 font-semibold text-sm text-slate-200 truncate">{listener.name}</span>

        {/* Meta */}
        <span className="text-[11px] text-slate-500 hidden sm:block">
          {project?.name ?? '—'} {target ? `· ${target.hostname_or_ip}` : ''}
        </span>
        <span className="text-[11px] text-slate-600 hidden md:block">{fmtTime(listener.last_triggered)}</span>

        {/* Actions */}
        <div className="flex items-center gap-1 shrink-0">
          {listener.status !== 'running' && (
            <button
              onClick={() => onAction(listener.id, 'start')}
              className="p-1.5 rounded text-green-400 hover:bg-green-500/10 transition-colors"
              title="Start"
            >
              <Play size={13} />
            </button>
          )}
          {listener.status === 'running' && (
            <button
              onClick={() => onAction(listener.id, 'pause')}
              className="p-1.5 rounded text-amber-400 hover:bg-amber-500/10 transition-colors"
              title="Pause"
            >
              <Pause size={13} />
            </button>
          )}
          {listener.status !== 'stopped' && (
            <button
              onClick={() => onAction(listener.id, 'stop')}
              className="p-1.5 rounded text-slate-400 hover:bg-slate-500/10 transition-colors"
              title="Stop"
            >
              <Square size={13} />
            </button>
          )}
          <button
            onClick={() => onDelete(listener.id)}
            className="p-1.5 rounded text-slate-600 hover:text-red-400 hover:bg-red-500/10 transition-colors"
            title="Delete"
          >
            <Trash2 size={13} />
          </button>
          <button onClick={toggle} className="p-1.5 rounded text-slate-500 hover:text-slate-300 transition-colors">
            <ChevronDown size={13} style={{ transform: expanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }} />
          </button>
        </div>
      </div>

      {/* Config summary bar */}
      <div className="px-4 pb-2">
        <span className="text-[11px] font-mono text-slate-500">{configSummary(listener.type, listener.config)}</span>
      </div>

      {/* Expanded: recent events */}
      {expanded && (
        <div className="border-t border-cyan-900/15 px-4 py-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Recent events</span>
            <button onClick={loadEvents} className="text-slate-600 hover:text-cyan-400 transition-colors" title="Refresh">
              <RefreshCw size={11} className={loadingEvents ? 'animate-spin' : ''} />
            </button>
          </div>
          {events.length === 0 ? (
            <p className="text-xs text-slate-600 italic">No events yet</p>
          ) : (
            <div className="space-y-1.5">
              {events.slice(0, 8).map(ev => {
                const m = OUTCOME_META[ev.outcome as EventOutcome] ?? OUTCOME_META.error
                return (
                  <div key={ev.id} className="flex items-start gap-2">
                    <span className={`mt-0.5 shrink-0 ${m.color}`}>{m.icon}</span>
                    <span className="text-[11px] text-slate-400 flex-1">{ev.detail}</span>
                    <span className="text-[10px] text-slate-600 shrink-0">{fmtTime(ev.fired_at)}</span>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Create form ───────────────────────────────────────────────────────────────

const SEVERITIES = ['critical', 'high', 'medium', 'low']
const ALERT_ON_OPTS = [
  { value: 'down', label: 'Target goes DOWN' },
  { value: 'up',   label: 'Target comes UP' },
  { value: 'both', label: 'Both' },
]

function CreateForm({
  projects, targets, categories, agents, onCreated,
}: {
  projects: Project[]
  targets: Target[]
  categories: ScanCategory[]
  agents: AgentOption[]
  onCreated: (l: ListenerRecord) => void
}) {
  const [name, setName] = useState('')
  const [type, setType] = useState<ListenerType>('scheduled')
  const [projectId, setProjectId] = useState('')
  const [targetId, setTargetId] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  // Scheduled
  const [cron, setCron] = useState('0 2 * * *')
  const [selCats, setSelCats] = useState<string[]>([])

  // Threshold
  const [severity, setSeverity] = useState('critical')
  const [limit, setLimit] = useState(5)
  const [checkInterval, setCheckInterval] = useState(60)

  // Healthcheck
  const [port, setPort] = useState(80)
  const [hcInterval, setHcInterval] = useState(5)
  const [timeout, setTimeout_] = useState(10)
  const [alertOn, setAlertOn] = useState('down')

  // Agent Audit
  const [agentId, setAgentId] = useState('')
  const [agentCron, setAgentCron] = useState('0 2 * * *')
  const [agentSelCats, setAgentSelCats] = useState<string[]>([])

  const filteredTargets = targets.filter(t => t.project_id === projectId)

  function toggleCat(id: string) {
    setSelCats(prev => prev.includes(id) ? prev.filter(c => c !== id) : [...prev, id])
  }

  function toggleAgentCat(id: string) {
    setAgentSelCats(prev => prev.includes(id) ? prev.filter(c => c !== id) : [...prev, id])
  }

  function buildConfig(): Record<string, unknown> {
    if (type === 'scheduled')
      return { cron, scan_categories: selCats.map(id => ({ category_id: id, config: {} })) }
    if (type === 'threshold')
      return { severity, limit, check_interval_minutes: checkInterval }
    if (type === 'agent_audit')
      return { agent_id: agentId, cron: agentCron, categories: agentSelCats }
    return { port, interval_minutes: hcInterval, timeout_seconds: timeout, alert_on: alertOn }
  }

  async function submit() {
    if (!name.trim() || !projectId) { setError('Name and project are required'); return }
    if (type === 'scheduled' && selCats.length === 0) { setError('Select at least one scan category'); return }
    if ((type === 'scheduled' || type === 'healthcheck') && !targetId) { setError('Target is required for this listener type'); return }
    if (type === 'agent_audit' && !agentId) { setError('Agent is required for Agent Audit type'); return }
    if (type === 'agent_audit' && agentSelCats.length === 0) { setError('Select at least one audit category'); return }
    setError('')
    setSaving(true)
    try {
      const res = await fetch('/api/v1/listeners', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim(),
          type,
          project_id: projectId,
          target_id: targetId || null,
          config: buildConfig(),
        }),
      })
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail ?? 'Failed'); }
      const listener = await res.json()
      onCreated(listener)
      setName(''); setSelCats([])
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setSaving(false)
    }
  }

  const inputCls = 'w-full px-3 py-2 rounded-lg border border-cyan-900/20 text-sm text-slate-200 focus:outline-none focus:border-cyan-500/50 transition-colors'
  const inputStyle = { background: '#05080d' }

  return (
    <div className="max-w-xl space-y-5">
      {error && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-red-500/30 bg-red-500/10 text-sm text-red-300">
          <AlertTriangle size={13} />{error}
        </div>
      )}

      {/* Name */}
      <div>
        <label className="block text-xs text-slate-400 mb-1.5">Listener name</label>
        <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. Nightly host audit"
          className={inputCls} style={inputStyle} />
      </div>

      {/* Type */}
      <div>
        <label className="block text-xs text-slate-400 mb-1.5">Type</label>
        <div className="flex gap-2">
          {(Object.entries(TYPE_META) as [ListenerType, typeof TYPE_META[ListenerType]][]).map(([t, m]) => (
            <button
              key={t}
              onClick={() => setType(t)}
              className={`flex-1 flex flex-col items-center gap-1.5 py-3 rounded-lg border text-xs font-medium transition-all ${
                type === t ? m.color : 'border-cyan-900/20 text-slate-500 hover:text-slate-300'
              }`}
              style={{ background: type === t ? undefined : '#05080d' }}
            >
              {m.icon}
              {m.label}
            </button>
          ))}
        </div>
      </div>

      {/* Project */}
      <div>
        <label className="block text-xs text-slate-400 mb-1.5">Project</label>
        <select value={projectId} onChange={e => { setProjectId(e.target.value); setTargetId('') }}
          className={inputCls} style={inputStyle}>
          <option value="">— select project —</option>
          {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>

      {/* Target */}
      {(type === 'scheduled' || type === 'healthcheck') && (
        <div>
          <label className="block text-xs text-slate-400 mb-1.5">
            Target
          </label>
          <select value={targetId} onChange={e => setTargetId(e.target.value)}
            className={inputCls} style={inputStyle} disabled={!projectId}>
            <option value="">— select target —</option>
            {filteredTargets.map(t => <option key={t.id} value={t.id}>{t.hostname_or_ip}</option>)}
          </select>
        </div>
      )}

      {/* Type-specific config */}
      {type === 'scheduled' && (
        <>
          <div>
            <label className="block text-xs text-slate-400 mb-1.5">Cron expression</label>
            <input value={cron} onChange={e => setCron(e.target.value)} placeholder="0 2 * * *"
              className={`${inputCls} font-mono`} style={inputStyle} />
            <p className="text-[10px] text-slate-600 mt-1">
              0 2 * * * = daily 2AM · 0 2 * * 0 = weekly Sun · 0 * * * * = hourly
            </p>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-2">Scan categories</label>
            <div className="grid grid-cols-2 gap-1.5">
              {categories.map(cat => (
                <label key={cat.id}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg border cursor-pointer transition-all text-xs ${
                    selCats.includes(cat.id)
                      ? 'border-cyan-500/40 text-cyan-300 bg-cyan-500/10'
                      : 'border-cyan-900/20 text-slate-400 hover:border-cyan-900/40'
                  }`}
                  style={{ background: selCats.includes(cat.id) ? undefined : '#05080d' }}
                >
                  <input type="checkbox" className="hidden" checked={selCats.includes(cat.id)}
                    onChange={() => toggleCat(cat.id)} />
                  <ChevronRight size={11} className={selCats.includes(cat.id) ? 'text-cyan-400' : 'text-slate-600'} />
                  {cat.label}
                </label>
              ))}
            </div>
          </div>
        </>
      )}

      {type === 'threshold' && (
        <>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1.5">Severity to watch</label>
              <select value={severity} onChange={e => setSeverity(e.target.value)} className={inputCls} style={inputStyle}>
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1.5">Alert when count exceeds</label>
              <input type="number" min={1} value={limit} onChange={e => setLimit(Number(e.target.value))}
                className={inputCls} style={inputStyle} />
            </div>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1.5">Check interval (minutes)</label>
            <input type="number" min={1} value={checkInterval} onChange={e => setCheckInterval(Number(e.target.value))}
              className={inputCls} style={inputStyle} />
          </div>
        </>
      )}

      {type === 'healthcheck' && (
        <>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1.5">Port</label>
              <input type="number" min={1} max={65535} value={port} onChange={e => setPort(Number(e.target.value))}
                className={inputCls} style={inputStyle} />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1.5">Check interval (minutes)</label>
              <input type="number" min={1} value={hcInterval} onChange={e => setHcInterval(Number(e.target.value))}
                className={inputCls} style={inputStyle} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1.5">Connection timeout (sec)</label>
              <input type="number" min={1} value={timeout} onChange={e => setTimeout_(Number(e.target.value))}
                className={inputCls} style={inputStyle} />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1.5">Alert when</label>
              <select value={alertOn} onChange={e => setAlertOn(e.target.value)} className={inputCls} style={inputStyle}>
                {ALERT_ON_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
          </div>
        </>
      )}

      {type === 'agent_audit' && (
        <>
          <div>
            <label className="block text-xs text-slate-400 mb-1.5">Agent</label>
            <select value={agentId} onChange={e => setAgentId(e.target.value)} className={inputCls} style={inputStyle}>
              <option value="">— select agent —</option>
              {agents.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-1.5">Cron expression</label>
            <input value={agentCron} onChange={e => setAgentCron(e.target.value)} placeholder="0 2 * * *"
              className={`${inputCls} font-mono`} style={inputStyle} />
            <p className="text-[10px] text-slate-600 mt-1">
              0 2 * * * = daily 2AM · 0 2 * * 0 = weekly Sun · 0 * * * * = hourly
            </p>
          </div>
          <div>
            <label className="block text-xs text-slate-400 mb-2">Audit categories</label>
            <div className="grid grid-cols-2 gap-1.5">
              {categories.map(cat => (
                <label key={cat.id}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg border cursor-pointer transition-all text-xs ${
                    agentSelCats.includes(cat.id)
                      ? 'border-purple-500/40 text-purple-300 bg-purple-500/10'
                      : 'border-cyan-900/20 text-slate-400 hover:border-cyan-900/40'
                  }`}
                  style={{ background: agentSelCats.includes(cat.id) ? undefined : '#05080d' }}
                >
                  <input type="checkbox" className="hidden" checked={agentSelCats.includes(cat.id)}
                    onChange={() => toggleAgentCat(cat.id)} />
                  <ChevronRight size={11} className={agentSelCats.includes(cat.id) ? 'text-purple-400' : 'text-slate-600'} />
                  {cat.label}
                </label>
              ))}
            </div>
          </div>
        </>
      )}

      <button
        onClick={submit}
        disabled={saving}
        className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/10 transition-all disabled:opacity-50"
        style={{ background: 'rgba(6,182,212,0.05)' }}
      >
        <Plus size={14} />
        {saving ? 'Creating…' : 'Create Listener'}
      </button>
    </div>
  )
}

// ── History tab ───────────────────────────────────────────────────────────────

function HistoryTab({ listeners }: { listeners: ListenerRecord[] }) {
  const [events, setEvents] = useState<ListenerEvent[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/v1/listeners/events/all')
      .then(r => r.json())
      .then(setEvents)
      .finally(() => setLoading(false))
  }, [])

  const byId = Object.fromEntries(listeners.map(l => [l.id, l]))

  return (
    <div>
      {loading ? (
        <p className="text-sm text-slate-500 py-4">Loading…</p>
      ) : events.length === 0 ? (
        <p className="text-sm text-slate-500 py-4">No events recorded yet.</p>
      ) : (
        <div className="rounded-xl border border-cyan-900/20 overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-cyan-900/20" style={{ background: '#060a10' }}>
                <th className="text-left px-4 py-2.5 text-slate-500 font-semibold">Listener</th>
                <th className="text-left px-4 py-2.5 text-slate-500 font-semibold">Type</th>
                <th className="text-left px-4 py-2.5 text-slate-500 font-semibold">Outcome</th>
                <th className="text-left px-4 py-2.5 text-slate-500 font-semibold">Detail</th>
                <th className="text-right px-4 py-2.5 text-slate-500 font-semibold">Time</th>
              </tr>
            </thead>
            <tbody>
              {events.map((ev, i) => {
                const m = OUTCOME_META[ev.outcome as EventOutcome] ?? OUTCOME_META.error
                const listener = byId[ev.listener_id]
                const tm = listener ? TYPE_META[listener.type] : null
                return (
                  <tr key={ev.id}
                    className="border-b border-cyan-900/10 last:border-0 hover:bg-cyan-900/5 transition-colors"
                    style={{ background: i % 2 === 0 ? '#090d14' : 'transparent' }}
                  >
                    <td className="px-4 py-2.5 text-slate-300 font-medium">{listener?.name ?? ev.listener_id.slice(0, 8)}</td>
                    <td className="px-4 py-2.5">
                      {tm && (
                        <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] ${tm.color}`}>
                          {tm.icon}{tm.label}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`flex items-center gap-1 ${m.color}`}>{m.icon}{ev.outcome}</span>
                    </td>
                    <td className="px-4 py-2.5 text-slate-400 max-w-xs truncate">{ev.detail}</td>
                    <td className="px-4 py-2.5 text-slate-600 text-right whitespace-nowrap">{fmtTime(ev.fired_at)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

type Tab = 'active' | 'create' | 'history'

export default function Listeners() {
  const [tab, setTab] = useState<Tab>('active')
  const [listeners, setListeners] = useState<ListenerRecord[]>([])
  const [projects, setProjects] = useState<Project[]>([])
  const [targets, setTargets] = useState<Target[]>([])
  const [categories, setCategories] = useState<ScanCategory[]>([])
  const [agents, setAgents] = useState<AgentOption[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      fetch('/api/v1/listeners').then(r => r.json()),
      fetch('/api/v1/projects').then(r => r.json()),
      fetch('/api/v1/targets').then(r => r.json()),
      fetch('/api/v1/audit/categories').then(r => r.json()),
      fetch('/api/v1/agents').then(r => r.json()).catch(() => []),
    ]).then(([ls, ps, ts, cats, agts]) => {
      setListeners(ls)
      setProjects(ps)
      setTargets(ts)
      setAgents(Array.isArray(agts) ? agts : [])
      // API returns a dict keyed by id; normalize to [{id, label}]
      const catList = Array.isArray(cats)
        ? cats
        : Object.values(cats as Record<string, { id: string; name: string }>)
            .map((c) => ({ id: c.id, label: c.name }))
      setCategories(catList)
    }).finally(() => setLoading(false))
  }, [])

  async function handleAction(id: string, action: 'start' | 'pause' | 'stop') {
    const res = await fetch(`/api/v1/listeners/${id}/${action}`, { method: 'PATCH' })
    if (res.ok) {
      const updated = await res.json()
      setListeners(prev => prev.map(l => l.id === id ? updated : l))
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this listener?')) return
    const res = await fetch(`/api/v1/listeners/${id}`, { method: 'DELETE' })
    if (res.ok || res.status === 204) {
      setListeners(prev => prev.filter(l => l.id !== id))
    }
  }

  function handleCreated(listener: ListenerRecord) {
    setListeners(prev => [listener, ...prev])
    setTab('active')
  }

  const counts = {
    running: listeners.filter(l => l.status === 'running').length,
    paused:  listeners.filter(l => l.status === 'paused').length,
    stopped: listeners.filter(l => l.status === 'stopped').length,
  }

  const TABS: { id: Tab; label: string }[] = [
    { id: 'active',  label: `Active (${listeners.length})` },
    { id: 'create',  label: 'Create' },
    { id: 'history', label: 'History' },
  ]

  return (
    <div className="p-6 pb-20 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Radio size={20} className="text-cyan-400" />
            <h1 className="text-xl font-bold text-white tracking-tight">Audit Listeners</h1>
          </div>
          <p className="text-sm text-slate-400">
            Persistent monitors that fire audit scans, threshold alerts, or health checks automatically.
          </p>
        </div>
        {/* Status summary */}
        <div className="flex items-center gap-3 shrink-0">
          {[
            { label: 'Running', count: counts.running, color: 'text-green-400' },
            { label: 'Paused',  count: counts.paused,  color: 'text-amber-400' },
            { label: 'Stopped', count: counts.stopped, color: 'text-slate-500' },
          ].map(s => (
            <div key={s.label} className="text-center">
              <div className={`text-lg font-bold ${s.color}`}>{s.count}</div>
              <div className="text-[10px] text-slate-600 uppercase tracking-widest">{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-cyan-900/20">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === t.id
                ? 'border-cyan-500 text-cyan-300'
                : 'border-transparent text-slate-500 hover:text-slate-300'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {loading ? (
        <p className="text-sm text-slate-500">Loading…</p>
      ) : tab === 'active' ? (
        <div>
          {listeners.length === 0 ? (
            <div className="text-center py-16">
              <Radio size={32} className="text-slate-700 mx-auto mb-3" />
              <p className="text-slate-500 text-sm">No listeners yet</p>
              <button
                onClick={() => setTab('create')}
                className="mt-4 inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/10 transition-all"
              >
                <Plus size={14} /> Create your first listener
              </button>
            </div>
          ) : (
            <div className="space-y-2">
              {listeners.map(l => (
                <ListenerCard
                  key={l.id}
                  listener={l}
                  projects={projects}
                  targets={targets}
                  onAction={handleAction}
                  onDelete={handleDelete}
                />
              ))}
            </div>
          )}
        </div>
      ) : tab === 'create' ? (
        <CreateForm
          projects={projects}
          targets={targets}
          categories={categories}
          agents={agents}
          onCreated={handleCreated}
        />
      ) : (
        <HistoryTab listeners={listeners} />
      )}
    </div>
  )
}
