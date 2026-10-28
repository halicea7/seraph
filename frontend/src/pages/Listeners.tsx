import { useState, useEffect } from 'react'
import { BarChart2, AlertTriangle } from 'lucide-react'
import Icon from '../components/Icon'
import { getApiBase } from '@/lib/config'

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

// ── Constants ─────────────────────────────────────────────────────────────────

const rule = '1px solid var(--rule)'
const ruleStrong = '1px solid var(--rule-strong)'

const inputStyle: React.CSSProperties = {
  width: '100%', boxSizing: 'border-box', background: 'var(--bg)',
  border: ruleStrong, borderRadius: 3, padding: '6px 10px',
  fontSize: 12, color: 'var(--fg)', fontFamily: 'var(--font-sans)', outline: 'none',
}

const labelStyle: React.CSSProperties = {
  display: 'block', fontSize: 10, fontWeight: 700, color: 'var(--fg-3)',
  textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6,
  fontFamily: 'var(--font-sans)',
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const TYPE_META: Record<ListenerType, { label: string; color: string; background: string; border: string }> = {
  scheduled:   { label: 'Scheduled',    color: 'var(--med)',    background: 'rgba(180,130,60,0.08)',  border: '1px solid rgba(180,130,60,0.25)' },
  threshold:   { label: 'Threshold',    color: 'var(--accent)', background: 'rgba(240,168,58,0.08)',  border: '1px solid rgba(240,168,58,0.25)' },
  healthcheck: { label: 'Health Check', color: 'var(--ok)',     background: 'rgba(84,175,97,0.08)',   border: '1px solid rgba(84,175,97,0.25)' },
  agent_audit: { label: 'Agent Audit',  color: '#a855f7',       background: 'rgba(168,85,247,0.08)',  border: '1px solid rgba(168,85,247,0.25)' },
}

const STATUS_COLOR: Record<ListenerStatus, string> = {
  running: 'var(--ok)',
  paused:  'var(--accent)',
  stopped: 'var(--fg-3)',
}

const OUTCOME_ICON: Record<EventOutcome, string> = {
  triggered: 'check',
  skipped:   'minus',
  error:     'x',
}

const OUTCOME_COLOR: Record<EventOutcome, string> = {
  triggered: 'var(--med)',
  skipped:   'var(--fg-3)',
  error:     'var(--crit)',
}

function TypeIconEl({ type, color, size = 13 }: { type: ListenerType; color: string; size?: number }) {
  if (type === 'threshold') return <BarChart2 size={size} color={color} />
  const names: Record<string, string> = { scheduled: 'clock', healthcheck: 'activity', agent_audit: 'cpu' }
  return <Icon name={names[type]} size={size} color={color} />
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
  const [confirmDelete, setConfirmDelete] = useState(false)

  const typeMeta = TYPE_META[listener.type]
  const statusColor = STATUS_COLOR[listener.status]
  const project = projects.find(p => p.id === listener.project_id)
  const target = targets.find(t => t.id === listener.target_id)

  function loadEvents() {
    if (loadingEvents) return
    setLoadingEvents(true)
    fetch(`${getApiBase()}/listeners/${listener.id}/events`)
      .then(r => r.json())
      .then(setEvents)
      .finally(() => setLoadingEvents(false))
  }

  function toggle() {
    if (!expanded) loadEvents()
    setExpanded(e => !e)
  }

  const actionBtnStyle = (color: string): React.CSSProperties => ({
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    width: 26, height: 26, borderRadius: 3, border: 'none',
    background: 'none', cursor: 'pointer', color,
  })

  return (
    <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, overflow: 'hidden' }}>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px' }}>
        {/* Status dot */}
        <div style={{ position: 'relative', flexShrink: 0 }}>
          <div style={{
            width: 8, height: 8, borderRadius: '50%', background: statusColor,
            boxShadow: listener.status === 'running' ? `0 0 6px ${statusColor}` : 'none',
          }} />
        </div>

        {/* Type badge */}
        <span style={{
          display: 'inline-flex', alignItems: 'center', gap: 5,
          padding: '2px 8px', borderRadius: 3, fontSize: 10, fontWeight: 600,
          fontFamily: 'var(--font-sans)',
          color: typeMeta.color, background: typeMeta.background, border: typeMeta.border,
        }}>
          <TypeIconEl type={listener.type} color={typeMeta.color} size={11} />
          {typeMeta.label}
        </span>

        {/* Name */}
        <span style={{ flex: 1, fontSize: 13, fontWeight: 600, color: 'var(--fg)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'var(--font-sans)' }}>
          {listener.name}
        </span>

        {/* Meta */}
        <span style={{ fontSize: 11, color: 'var(--fg-3)', flexShrink: 0, fontFamily: 'var(--font-sans)' }}>
          {project?.name ?? '—'}{target ? ` · ${target.hostname_or_ip}` : ''}
        </span>
        <span style={{ fontSize: 10, color: 'var(--fg-3)', flexShrink: 0, fontFamily: 'var(--font-mono)' }}>
          {fmtTime(listener.last_triggered)}
        </span>

        {/* Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 2, flexShrink: 0 }}>
          {listener.status !== 'running' && (
            <button onClick={() => onAction(listener.id, 'start')} title="Start" style={actionBtnStyle('var(--ok)')}>
              <Icon name="play" size={12} color="var(--ok)" />
            </button>
          )}
          {listener.status === 'running' && (
            <button onClick={() => onAction(listener.id, 'pause')} title="Pause" style={actionBtnStyle('var(--accent)')}>
              <Icon name="pause" size={12} color="var(--accent)" />
            </button>
          )}
          {listener.status !== 'stopped' && (
            <button onClick={() => onAction(listener.id, 'stop')} title="Stop" style={actionBtnStyle('var(--fg-3)')}>
              <Icon name="stop" size={12} color="var(--fg-3)" />
            </button>
          )}
          {confirmDelete ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <button
                onClick={() => onDelete(listener.id)}
                style={{ fontSize: 10, padding: '2px 8px', borderRadius: 3, background: 'rgba(232,64,64,0.12)', border: '1px solid rgba(232,64,64,0.35)', color: 'var(--crit)', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}
              >Yes</button>
              <button
                onClick={() => setConfirmDelete(false)}
                style={{ fontSize: 10, padding: '2px 8px', borderRadius: 3, background: 'none', border: ruleStrong, color: 'var(--fg-3)', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}
              >No</button>
            </div>
          ) : (
            <button onClick={() => setConfirmDelete(true)} title="Delete" style={actionBtnStyle('var(--fg-3)')}>
              <Icon name="trash" size={12} color="var(--fg-3)" />
            </button>
          )}
          <button onClick={toggle} style={actionBtnStyle('var(--fg-3)')}>
            <Icon name={expanded ? 'chev_u' : 'chev_d'} size={13} color="var(--fg-3)" />
          </button>
        </div>
      </div>

      {/* Config summary bar */}
      <div style={{ paddingLeft: 14, paddingRight: 14, paddingBottom: 10 }}>
        <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--fg-3)' }}>
          {configSummary(listener.type, listener.config)}
        </span>
      </div>

      {/* Expanded: recent events */}
      {expanded && (
        <div style={{ borderTop: rule, padding: '10px 14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: 'var(--font-sans)' }}>
              Recent events
            </span>
            <button
              onClick={loadEvents}
              style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center' }}
              title="Refresh"
            >
              <Icon name="refresh" size={11} color={loadingEvents ? 'var(--accent)' : 'var(--fg-3)'} />
            </button>
          </div>
          {events.length === 0 ? (
            <p style={{ margin: 0, fontSize: 12, color: 'var(--fg-3)', fontStyle: 'italic', fontFamily: 'var(--font-sans)' }}>
              No events yet
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {events.slice(0, 8).map(ev => {
                const outcome = (ev.outcome as EventOutcome) in OUTCOME_ICON ? ev.outcome as EventOutcome : 'error'
                return (
                  <div key={ev.id} style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                    <Icon name={OUTCOME_ICON[outcome]} size={12} color={OUTCOME_COLOR[outcome]} />
                    <span style={{ flex: 1, fontSize: 11, color: 'var(--fg-2)', fontFamily: 'var(--font-sans)' }}>{ev.detail}</span>
                    <span style={{ fontSize: 10, color: 'var(--fg-3)', flexShrink: 0, fontFamily: 'var(--font-mono)' }}>{fmtTime(ev.fired_at)}</span>
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

  const [cron, setCron] = useState('0 2 * * *')
  const [selCats, setSelCats] = useState<string[]>([])

  const [severity, setSeverity] = useState('critical')
  const [limit, setLimit] = useState(5)
  const [checkInterval, setCheckInterval] = useState(60)

  const [port, setPort] = useState(80)
  const [hcInterval, setHcInterval] = useState(5)
  const [timeout, setTimeout_] = useState(10)
  const [alertOn, setAlertOn] = useState('down')

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
      const res = await fetch(`${getApiBase()}/listeners`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim(), type,
          project_id: projectId,
          target_id: targetId || null,
          config: buildConfig(),
        }),
      })
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail ?? 'Failed') }
      const listener = await res.json()
      onCreated(listener)
      setName(''); setSelCats([])
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setSaving(false)
    }
  }

  const sectionStyle: React.CSSProperties = {
    display: 'flex', flexDirection: 'column', gap: 6,
  }

  function CatCheckbox({ label, selected, onToggle, activeColor }: {
    id: string; label: string; selected: boolean; onToggle: () => void; activeColor: string
  }) {
    return (
      <button
        onClick={onToggle}
        style={{
          display: 'flex', alignItems: 'center', gap: 8, padding: '7px 10px',
          borderRadius: 3, border: selected ? `1px solid ${activeColor}55` : ruleStrong,
          background: selected ? `${activeColor}10` : 'var(--bg)',
          cursor: 'pointer', textAlign: 'left', fontSize: 12, fontFamily: 'var(--font-sans)',
          color: selected ? activeColor : 'var(--fg-3)',
        }}
      >
        <Icon name={selected ? 'check' : 'chev_r'} size={11} color={selected ? activeColor : 'var(--fg-3)'} />
        {label}
      </button>
    )
  }

  return (
    <div style={{ maxWidth: 540, display: 'flex', flexDirection: 'column', gap: 16 }}>
      {error && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', borderRadius: 3, background: 'rgba(232,64,64,0.08)', border: '1px solid rgba(232,64,64,0.3)', fontSize: 12, color: 'var(--crit)', fontFamily: 'var(--font-sans)' }}>
          <AlertTriangle size={13} /> {error}
        </div>
      )}

      {/* Name */}
      <div style={sectionStyle}>
        <label style={labelStyle}>Listener name</label>
        <input
          value={name} onChange={e => setName(e.target.value)}
          placeholder="e.g. Nightly host audit"
          style={inputStyle}
        />
      </div>

      {/* Type picker */}
      <div style={sectionStyle}>
        <label style={labelStyle}>Type</label>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 6 }}>
          {(Object.entries(TYPE_META) as [ListenerType, typeof TYPE_META[ListenerType]][]).map(([t, m]) => {
            const isActive = type === t
            return (
              <button
                key={t}
                onClick={() => setType(t)}
                style={{
                  display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6,
                  padding: '10px 6px', borderRadius: 3, cursor: 'pointer',
                  border: isActive ? m.border : ruleStrong,
                  background: isActive ? m.background : 'var(--bg)',
                  color: isActive ? m.color : 'var(--fg-3)',
                  fontSize: 10, fontFamily: 'var(--font-sans)', fontWeight: 600,
                }}
              >
                <TypeIconEl type={t} color={isActive ? m.color : 'var(--fg-3)'} size={14} />
                {m.label}
              </button>
            )
          })}
        </div>
      </div>

      {/* Project */}
      <div style={sectionStyle}>
        <label style={labelStyle}>Project</label>
        <select
          value={projectId}
          onChange={e => { setProjectId(e.target.value); setTargetId('') }}
          style={inputStyle}
        >
          <option value="">— select project —</option>
          {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>

      {/* Target */}
      {(type === 'scheduled' || type === 'healthcheck') && (
        <div style={sectionStyle}>
          <label style={labelStyle}>Target</label>
          <select
            value={targetId} onChange={e => setTargetId(e.target.value)}
            style={{ ...inputStyle, opacity: projectId ? 1 : 0.5 }}
            disabled={!projectId}
          >
            <option value="">— select target —</option>
            {filteredTargets.map(t => <option key={t.id} value={t.id}>{t.hostname_or_ip}</option>)}
          </select>
        </div>
      )}

      {/* Type-specific config */}
      {type === 'scheduled' && (
        <>
          <div style={sectionStyle}>
            <label style={labelStyle}>Cron expression</label>
            <input
              value={cron} onChange={e => setCron(e.target.value)} placeholder="0 2 * * *"
              style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
            />
            <p style={{ margin: 0, fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>
              0 2 * * * = daily 2AM · 0 2 * * 0 = weekly Sun · 0 * * * * = hourly
            </p>
          </div>
          <div style={sectionStyle}>
            <label style={labelStyle}>Scan categories</label>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
              {categories.map(cat => (
                <CatCheckbox
                  key={cat.id} id={cat.id} label={cat.label}
                  selected={selCats.includes(cat.id)}
                  onToggle={() => toggleCat(cat.id)}
                  activeColor="var(--med)"
                />
              ))}
            </div>
          </div>
        </>
      )}

      {type === 'threshold' && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div style={sectionStyle}>
              <label style={labelStyle}>Severity to watch</label>
              <select value={severity} onChange={e => setSeverity(e.target.value)} style={inputStyle}>
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div style={sectionStyle}>
              <label style={labelStyle}>Alert when count exceeds</label>
              <input type="number" min={1} value={limit} onChange={e => setLimit(Number(e.target.value))} style={inputStyle} />
            </div>
          </div>
          <div style={sectionStyle}>
            <label style={labelStyle}>Check interval (minutes)</label>
            <input type="number" min={1} value={checkInterval} onChange={e => setCheckInterval(Number(e.target.value))} style={inputStyle} />
          </div>
        </>
      )}

      {type === 'healthcheck' && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div style={sectionStyle}>
              <label style={labelStyle}>Port</label>
              <input type="number" min={1} max={65535} value={port} onChange={e => setPort(Number(e.target.value))} style={inputStyle} />
            </div>
            <div style={sectionStyle}>
              <label style={labelStyle}>Check interval (minutes)</label>
              <input type="number" min={1} value={hcInterval} onChange={e => setHcInterval(Number(e.target.value))} style={inputStyle} />
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div style={sectionStyle}>
              <label style={labelStyle}>Connection timeout (sec)</label>
              <input type="number" min={1} value={timeout} onChange={e => setTimeout_(Number(e.target.value))} style={inputStyle} />
            </div>
            <div style={sectionStyle}>
              <label style={labelStyle}>Alert when</label>
              <select value={alertOn} onChange={e => setAlertOn(e.target.value)} style={inputStyle}>
                {ALERT_ON_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
          </div>
        </>
      )}

      {type === 'agent_audit' && (
        <>
          <div style={sectionStyle}>
            <label style={labelStyle}>Agent</label>
            <select value={agentId} onChange={e => setAgentId(e.target.value)} style={inputStyle}>
              <option value="">— select agent —</option>
              {agents.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
            </select>
          </div>
          <div style={sectionStyle}>
            <label style={labelStyle}>Cron expression</label>
            <input
              value={agentCron} onChange={e => setAgentCron(e.target.value)} placeholder="0 2 * * *"
              style={{ ...inputStyle, fontFamily: 'var(--font-mono)' }}
            />
            <p style={{ margin: 0, fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>
              0 2 * * * = daily 2AM · 0 2 * * 0 = weekly Sun · 0 * * * * = hourly
            </p>
          </div>
          <div style={sectionStyle}>
            <label style={labelStyle}>Audit categories</label>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 4 }}>
              {categories.map(cat => (
                <CatCheckbox
                  key={cat.id} id={cat.id} label={cat.label}
                  selected={agentSelCats.includes(cat.id)}
                  onToggle={() => toggleAgentCat(cat.id)}
                  activeColor="#a855f7"
                />
              ))}
            </div>
          </div>
        </>
      )}

      <button
        onClick={submit}
        disabled={saving}
        style={{
          display: 'inline-flex', alignItems: 'center', gap: 8, padding: '8px 16px',
          borderRadius: 4, border: '1px solid rgba(240,168,58,0.35)',
          background: 'rgba(240,168,58,0.08)', fontSize: 12, color: 'var(--accent)',
          cursor: saving ? 'not-allowed' : 'pointer', opacity: saving ? 0.6 : 1,
          fontFamily: 'var(--font-sans)', fontWeight: 600,
        }}
      >
        <Icon name="plus" size={13} color="var(--accent)" />
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
    fetch(`${getApiBase()}/listeners/events/all`)
      .then(r => r.json())
      .then(setEvents)
      .finally(() => setLoading(false))
  }, [])

  const byId = Object.fromEntries(listeners.map(l => [l.id, l]))

  if (loading) {
    return (
      <p style={{ margin: 0, fontSize: 13, color: 'var(--fg-3)', padding: '16px 0', fontFamily: 'var(--font-sans)' }}>
        Loading…
      </p>
    )
  }

  if (events.length === 0) {
    return (
      <p style={{ margin: 0, fontSize: 13, color: 'var(--fg-3)', padding: '16px 0', fontFamily: 'var(--font-sans)' }}>
        No events recorded yet.
      </p>
    )
  }

  const thStyle: React.CSSProperties = {
    textAlign: 'left', padding: '8px 14px', fontSize: 10, fontWeight: 700,
    color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.07em',
    fontFamily: 'var(--font-sans)', background: 'var(--bg)', whiteSpace: 'nowrap',
  }

  return (
    <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, overflow: 'hidden' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
        <thead>
          <tr style={{ borderBottom: ruleStrong }}>
            <th style={thStyle}>Listener</th>
            <th style={thStyle}>Type</th>
            <th style={thStyle}>Outcome</th>
            <th style={thStyle}>Detail</th>
            <th style={{ ...thStyle, textAlign: 'right' }}>Time</th>
          </tr>
        </thead>
        <tbody>
          {events.map((ev, i) => {
            const outcome = (ev.outcome as EventOutcome) in OUTCOME_ICON ? ev.outcome as EventOutcome : 'error'
            const listener = byId[ev.listener_id]
            const tm = listener ? TYPE_META[listener.type] : null

            return (
              <tr key={ev.id} style={{ borderBottom: i < events.length - 1 ? rule : 'none', background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.01)' }}>
                <td style={{ padding: '8px 14px', color: 'var(--fg)', fontWeight: 500, fontFamily: 'var(--font-sans)' }}>
                  {listener?.name ?? ev.listener_id.slice(0, 8)}
                </td>
                <td style={{ padding: '8px 14px' }}>
                  {tm && listener && (
                    <span style={{
                      display: 'inline-flex', alignItems: 'center', gap: 4,
                      padding: '1px 7px', borderRadius: 3, fontSize: 10, fontWeight: 600,
                      fontFamily: 'var(--font-sans)',
                      color: tm.color, background: tm.background, border: tm.border,
                    }}>
                      <TypeIconEl type={listener.type} color={tm.color} size={10} />
                      {tm.label}
                    </span>
                  )}
                </td>
                <td style={{ padding: '8px 14px' }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: OUTCOME_COLOR[outcome], fontFamily: 'var(--font-sans)' }}>
                    <Icon name={OUTCOME_ICON[outcome]} size={11} color={OUTCOME_COLOR[outcome]} />
                    {ev.outcome}
                  </span>
                </td>
                <td style={{ padding: '8px 14px', color: 'var(--fg-2)', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'var(--font-sans)' }}>
                  {ev.detail}
                </td>
                <td style={{ padding: '8px 14px', color: 'var(--fg-3)', textAlign: 'right', whiteSpace: 'nowrap', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                  {fmtTime(ev.fired_at)}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
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
      fetch(`${getApiBase()}/listeners`).then(r => r.json()),
      fetch(`${getApiBase()}/projects`).then(r => r.json()),
      fetch(`${getApiBase()}/targets`).then(r => r.json()),
      fetch(`${getApiBase()}/audit/categories`).then(r => r.json()),
      fetch(`${getApiBase()}/agents`).then(r => r.json()).catch(() => []),
    ]).then(([ls, ps, ts, cats, agts]) => {
      setListeners(ls)
      setProjects(ps)
      setTargets(ts)
      setAgents(Array.isArray(agts) ? agts : [])
      const catList = Array.isArray(cats)
        ? cats
        : Object.values(cats as Record<string, { id: string; name: string }>)
            .map(c => ({ id: c.id, label: c.name }))
      setCategories(catList)
    }).finally(() => setLoading(false))
  }, [])

  async function handleAction(id: string, action: 'start' | 'pause' | 'stop') {
    const res = await fetch(`${getApiBase()}/listeners/${id}/${action}`, { method: 'PATCH' })
    if (res.ok) {
      const updated = await res.json()
      setListeners(prev => prev.map(l => l.id === id ? updated : l))
    }
  }

  async function handleDelete(id: string) {
    const res = await fetch(`${getApiBase()}/listeners/${id}`, { method: 'DELETE' })
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
    <div style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 20, background: 'var(--bg)', color: 'var(--fg)', minHeight: '100%' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: 'var(--fg)', display: 'flex', alignItems: 'center', gap: 8, fontFamily: 'var(--font-sans)' }}>
            <Icon name="radio" size={18} color="var(--accent)" />
            Audit Listeners
          </h1>
          <p style={{ margin: '3px 0 0', fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>
            Persistent monitors that fire audit scans, threshold alerts, or health checks automatically.
          </p>
        </div>

        {/* Status counts */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 20, flexShrink: 0 }}>
          {[
            { label: 'Running', count: counts.running, color: 'var(--ok)' },
            { label: 'Paused',  count: counts.paused,  color: 'var(--accent)' },
            { label: 'Stopped', count: counts.stopped, color: 'var(--fg-3)' },
          ].map(s => (
            <div key={s.label} style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 20, fontWeight: 700, fontFamily: 'var(--font-mono)', color: s.color }}>{s.count}</div>
              <div style={{ fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.07em', fontFamily: 'var(--font-sans)' }}>{s.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, borderBottom: ruleStrong }}>
        {TABS.map(t => {
          const isActive = tab === t.id
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              style={{
                padding: '8px 16px', fontSize: 13, fontWeight: 500, cursor: 'pointer',
                background: 'none', border: 'none',
                borderBottom: isActive ? '2px solid var(--accent)' : '2px solid transparent',
                marginBottom: -1,
                color: isActive ? 'var(--accent)' : 'var(--fg-3)',
                fontFamily: 'var(--font-sans)',
              }}
            >
              {t.label}
            </button>
          )
        })}
      </div>

      {/* Tab content */}
      {loading ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '64px 0' }}>
          <Icon name="refresh" size={24} color="var(--accent)" />
        </div>
      ) : tab === 'active' ? (
        listeners.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '80px 0' }}>
            <Icon name="radio" size={32} color="var(--rule-strong)" />
            <p style={{ margin: '12px 0 0', fontSize: 13, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>
              No listeners yet
            </p>
            <button
              onClick={() => setTab('create')}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 8, marginTop: 16,
                padding: '8px 16px', borderRadius: 4, border: '1px solid rgba(240,168,58,0.35)',
                background: 'rgba(240,168,58,0.08)', fontSize: 12, color: 'var(--accent)',
                cursor: 'pointer', fontFamily: 'var(--font-sans)', fontWeight: 600,
              }}
            >
              <Icon name="plus" size={13} color="var(--accent)" />
              Create your first listener
            </button>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
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
        )
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
