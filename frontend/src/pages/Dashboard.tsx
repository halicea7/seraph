import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAppStore } from '@/stores/appStore'
import {
  getProjects,
  getStats,
  createProject,
  createTarget,
  deleteProject,
  getProjectScans,
  type PlatformStats,
} from '@/api/client'
import ProjectModal from '@/components/ProjectModal'
import Icon from '@/components/Icon'
import EmptyState from '@/components/EmptyState'
import { useCountUp } from '@/lib/useCountUp'
import { getApiBase, wsUrl } from '@/lib/config'

const rule = '1px solid var(--rule)'

// ── Sparkline ─────────────────────────────────────────────────────────────────

function Sparkline({
  data,
  width = 70,
  height = 26,
  color,
  fill = false,
}: {
  data: number[]
  width?: number
  height?: number
  color: string
  fill?: boolean
}) {
  if (data.length < 2) return null
  const max = Math.max(...data, 1)
  const pts = data.map((v, i) => ({ x: (i / (data.length - 1)) * width, y: height - (v / max) * height }))
  const polyPts = pts.map((p) => `${p.x},${p.y}`).join(' ')
  if (fill) {
    const fillPath =
      `M${pts[0].x},${height} ` +
      pts.map((p) => `L${p.x},${p.y}`).join(' ') +
      ` L${pts[pts.length - 1].x},${height} Z`
    return (
      <svg width={width} height={height} style={{ overflow: 'visible', flexShrink: 0 }}>
        <path d={fillPath} fill={color} fillOpacity={0.15} />
        <polyline points={polyPts} fill="none" stroke={color} strokeWidth={1.5} />
      </svg>
    )
  }
  return (
    <svg width={width} height={height} style={{ overflow: 'visible', flexShrink: 0 }}>
      <polyline points={polyPts} fill="none" stroke={color} strokeWidth={1.5} />
    </svg>
  )
}

// ── KPI cell ──────────────────────────────────────────────────────────────────

function KPI({
  label,
  value,
  sub,
  accentVar,
  trend,
  divider,
}: {
  label: string
  value: number
  sub: string
  accentVar?: string
  trend?: number[]
  divider?: boolean
}) {
  const color = accentVar ? `var(${accentVar})` : 'var(--fg)'
  const display = useCountUp(value)
  return (
    <div style={{ padding: '20px var(--pad) 18px', borderLeft: divider ? rule : 'none' }}>
      <div className="smcap">{label}</div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginTop: 8 }}>
        <span
          className="mono tnum"
          style={{ fontSize: 44, fontWeight: 500, color, letterSpacing: '-0.02em', lineHeight: 1 }}
        >
          {String(display).padStart(2, '0')}
        </span>
        {trend && <Sparkline data={trend} width={70} height={26} color={color} fill />}
      </div>
      <div
        className="mono"
        style={{ fontSize: 10, color: 'var(--fg-3)', marginTop: 10, textTransform: 'uppercase', letterSpacing: '0.1em' }}
      >
        {sub}
      </div>
    </div>
  )
}

// ── Section wrapper ───────────────────────────────────────────────────────────

function Section({
  title,
  right,
  children,
  style,
}: {
  title: string
  right?: React.ReactNode
  children: React.ReactNode
  style?: React.CSSProperties
}) {
  return (
    <div style={style}>
      <div className="sec-h">
        <span className="title">{title}</span>
        {right}
      </div>
      {children}
    </div>
  )
}

// ── PhasePipeline ─────────────────────────────────────────────────────────────

interface PhaseData {
  id: string
  name: string
  status: 'done' | 'running' | 'pending'
  tools: string[]
  started?: string | null
  ended?: string | null
  progress?: number
}

function PhasePipeline({ phases }: { phases: PhaseData[] }) {

  const borderColor = (s: PhaseData['status']) =>
    s === 'running' ? 'var(--warn)' : s === 'done' ? 'var(--ok)' : 'var(--rule-strong)'

  if (phases.length === 0) return (
    <Section title="PHASE PIPELINE">
      <EmptyState
        icon="activity"
        title="No scans recorded yet"
        hint="Run a scan from a module like OSINT, Network Map, or Pentest Workbench to populate the engagement timeline."
        pad={28}
      />
    </Section>
  )

  return (
    <Section title="PHASE PIPELINE">
      {phases.length > 0 && (
      <div style={{ display: 'grid', gridTemplateColumns: `repeat(${phases.length}, 1fr)`, gap: 0 }}>
        {phases.map((ph, i) => (
          <div
            key={ph.id}
            style={{
              padding: '12px var(--pad)',
              borderTop: `2px solid ${borderColor(ph.status)}`,
              borderLeft: i > 0 ? rule : 'none',
              position: 'relative',
            }}
          >
            <div
              className="mono"
              style={{ fontSize: 9, color: 'var(--fg-4)', textTransform: 'uppercase', letterSpacing: '0.12em' }}
            >
              {String(i + 1).padStart(2, '0')}
            </div>
            <div className="mono" style={{ fontSize: 12, fontWeight: 500, marginTop: 4 }}>
              {ph.name}
            </div>
            <div
              className="mono"
              style={{ fontSize: 9, color: 'var(--fg-3)', marginTop: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}
            >
              {ph.tools.join(' · ')}
            </div>
            {ph.started && (
              <div className="mono" style={{ fontSize: 9, color: 'var(--fg-4)', marginTop: 6 }}>
                {ph.started}
              </div>
            )}
            <div
              style={{
                position: 'absolute',
                bottom: 0,
                left: 0,
                height: 2,
                width: `${ph.progress ?? 0}%`,
                background: borderColor(ph.status),
                opacity: 0.5,
              }}
            />
          </div>
        ))}
      </div>
      )}
    </Section>
  )
}

// ── FindingsPreview ───────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--crit)',
  high: 'var(--high)',
  medium: 'var(--med)',
  low: 'var(--low)',
  info: 'var(--info, var(--fg-3))',
}

interface FindingRow {
  id: string
  severity: string
  cvss_score: string | null
  title: string
  cve_id: string | null
  target: string
  status?: string
}

function FindingsPreview({ findings }: { findings: FindingRow[] }) {
  const navigate = useNavigate()
  const sorted = [...findings].sort((a, b) => parseFloat(b.cvss_score ?? '0') - parseFloat(a.cvss_score ?? '0')).slice(0, 8)

  const statusColor = (s?: string) => {
    if (s === 'remediated') return 'var(--ok)'
    if (s === 'in-review') return 'var(--warn)'
    if (s === 'accepted') return 'var(--fg-3)'
    return 'var(--crit)'
  }

  return (
    <Section
      title="FINDINGS PREVIEW"
      right={
        <button className="btn btn-ghost btn-sm" onClick={() => navigate('/findings')}>
          View all <Icon name="arrow_r" size={9} />
        </button>
      }
    >
      {sorted.length === 0 ? (
        <EmptyState
          icon="flag"
          title="No findings yet"
          hint="Findings surface here as scans complete. Import a Nessus scan or run a module to get started."
          pad={28}
        />
      ) : (
        <table className="data">
          <thead>
            <tr>
              <th style={{ width: 20 }}>SEV</th>
              <th style={{ width: 48 }}>CVSS</th>
              <th>Title / CVE</th>
              <th style={{ width: 140 }}>Host</th>
              <th style={{ width: 80 }}>Status</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((f) => (
              <tr key={f.id}>
                <td>
                  <span
                    style={{
                      display: 'inline-block',
                      width: 8,
                      height: 8,
                      background: SEV_COLOR[f.severity] ?? 'var(--fg-4)',
                    }}
                  />
                </td>
                <td className="mono tnum" style={{ fontSize: 11, color: 'var(--fg-2)' }}>
                  {f.cvss_score ?? '—'}
                </td>
                <td>
                  <div style={{ fontWeight: 500, fontSize: 11 }}>{f.title}</div>
                  {f.cve_id && (
                    <div className="mono" style={{ fontSize: 9, color: 'var(--fg-3)', marginTop: 1 }}>
                      {f.cve_id}
                    </div>
                  )}
                </td>
                <td className="mono" style={{ fontSize: 10, color: 'var(--fg-2)' }}>
                  {f.target}
                </td>
                <td>
                  <span
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: 9,
                      textTransform: 'uppercase',
                      letterSpacing: '0.08em',
                      color: statusColor(f.status),
                      padding: '2px 5px',
                      border: `1px solid ${statusColor(f.status)}`,
                      opacity: 0.85,
                    }}
                  >
                    {f.status ?? 'open'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Section>
  )
}

// ── SeverityBreakdown ─────────────────────────────────────────────────────────

function SeverityBreakdown({ counts }: { counts: Record<string, number> }) {
  const bars = [
    { label: 'Critical', k: 'critical', color: 'var(--crit)' },
    { label: 'High', k: 'high', color: 'var(--high)' },
    { label: 'Medium', k: 'medium', color: 'var(--med)' },
    { label: 'Low', k: 'low', color: 'var(--low)' },
  ]
  const total = bars.reduce((s, b) => s + (counts[b.k] || 0), 0)
  const max = Math.max(...bars.map((b) => counts[b.k] || 0), 1)

  return (
    <Section title="SEVERITY · OPEN" right={<span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>n = {total}</span>}>
      <div style={{ padding: 'var(--pad)' }}>
        {/* Stacked bar */}
        <div style={{ display: 'flex', height: 8, marginBottom: 16, gap: 1 }}>
          {total === 0 ? (
            <div style={{ flex: 1, background: 'var(--rule-2)' }} />
          ) : (
            bars.map((b) => (
              <div
                key={b.k}
                style={{ flex: counts[b.k] || 0, background: b.color, opacity: counts[b.k] ? 1 : 0, minWidth: counts[b.k] ? 2 : 0 }}
              />
            ))
          )}
        </div>
        {/* Micro bars */}
        {bars.map((b) => (
          <div
            key={b.k}
            style={{ display: 'grid', gridTemplateColumns: '64px 1fr 32px', gap: 8, alignItems: 'center', marginBottom: 6 }}
          >
            <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              {b.label}
            </span>
            <div style={{ background: 'var(--rule-2)', height: 6 }}>
              <div style={{ height: '100%', width: `${((counts[b.k] || 0) / max) * 100}%`, background: b.color }} />
            </div>
            <span className="mono tnum" style={{ fontSize: 11, color: 'var(--fg-2)', textAlign: 'right' }}>
              {counts[b.k] || 0}
            </span>
          </div>
        ))}
        {/* SLA grid */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: 6,
            marginTop: 14,
            paddingTop: 12,
            borderTop: rule,
          }}
        >
          {[
            { label: 'Crit < 24h', val: counts.critical || 0, warn: (counts.critical || 0) > 0 },
            { label: 'High < 7d', val: counts.high || 0, warn: (counts.high || 0) > 5 },
            { label: 'Breached', val: 0, warn: false },
            { label: 'At risk', val: (counts.critical || 0) + (counts.high || 0), warn: (counts.critical || 0) + (counts.high || 0) > 3 },
          ].map((item) => (
            <div key={item.label} style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <span className="mono" style={{ fontSize: 9, color: 'var(--fg-4)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                {item.label}
              </span>
              <span
                className="mono tnum"
                style={{ fontSize: 18, fontWeight: 500, color: item.warn ? 'var(--crit)' : 'var(--fg-3)' }}
              >
                {String(item.val).padStart(2, '0')}
              </span>
            </div>
          ))}
        </div>
      </div>
    </Section>
  )
}

// ── ActiveSessionsList ────────────────────────────────────────────────────────

interface C2SessionRow {
  id: string
  msf_session_id?: string
  session_type: string
  remote_host: string
  via_payload?: string
  established_at?: string
  last_seen?: string
  status?: string
}

function uptimeStr(established?: string): string {
  if (!established) return '—'
  const ms = Date.now() - new Date(established).getTime()
  const mins = Math.floor(ms / 60000)
  if (mins < 60) return `${mins}m`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h`
  return `${Math.floor(hrs / 24)}d`
}

function ActiveSessionsList({ projectId }: { projectId: string | null }) {
  const navigate = useNavigate()
  const [sessions, setSessions] = useState<C2SessionRow[]>([])

  useEffect(() => {
    if (!projectId) { setSessions([]); return }
    fetch(`${getApiBase()}/c2/sessions?project_id=${projectId}`)
      .then((r) => r.json())
      .then((d: C2SessionRow[]) => setSessions(d))
      .catch(() => setSessions([]))
  }, [projectId])

  return (
    <Section
      title={`ACTIVE SESSIONS · ${sessions.length}`}
      right={
        <button className="btn btn-ghost btn-sm" onClick={() => navigate('/c2')}>
          Open C2 <Icon name="arrow_r" size={9} />
        </button>
      }
    >
      {sessions.length === 0 ? (
        <div style={{ padding: 'var(--pad)', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg-3)' }}>
          No active sessions.
        </div>
      ) : (
        <div>
          {sessions.slice(0, 4).map((s, i) => (
            <div
              key={s.id}
              style={{
                display: 'grid',
                gridTemplateColumns: '32px 1fr auto',
                gap: 8,
                padding: '8px var(--pad)',
                borderBottom: i < Math.min(sessions.length, 4) - 1 ? rule : 'none',
                alignItems: 'center',
              }}
            >
              <span className="mono tnum" style={{ fontSize: 10, color: 'var(--fg-4)' }}>
                #{s.msf_session_id ?? s.id.slice(0, 3)}
              </span>
              <div>
                <div className="mono" style={{ fontSize: 11, fontWeight: 500 }}>
                  {s.remote_host}
                </div>
                <div className="mono" style={{ fontSize: 9, color: 'var(--fg-3)', marginTop: 2 }}>
                  {s.session_type} · {s.via_payload ?? '—'}
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 2 }}>
                <span
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 9,
                    color: s.status === 'active' ? 'var(--ok)' : 'var(--fg-4)',
                    textTransform: 'uppercase',
                  }}
                >
                  {s.status ?? 'active'}
                </span>
                <span className="mono" style={{ fontSize: 9, color: 'var(--fg-4)' }}>
                  {uptimeStr(s.established_at)}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </Section>
  )
}

// ── ActivityLedger ────────────────────────────────────────────────────────────

interface ActivityEntry {
  id: string
  timestamp: string
  message: string
  kind?: string
}

const ACTIVITY_COLOR: Record<string, string> = {
  scan: 'var(--accent)',
  finding: 'var(--crit)',
  session: 'var(--ok)',
  info: 'var(--fg-3)',
}

function ActivityLedger({ projectId }: { projectId: string | null }) {
  const [entries, setEntries] = useState<ActivityEntry[]>([])

  useEffect(() => {
    if (!projectId) { setEntries([]); return }
    fetch(`${getApiBase()}/activity?project_id=${projectId}`)
      .then((r) => r.json())
      .then((d: ActivityEntry[]) => setEntries(d))
      .catch(() => setEntries([]))
  }, [projectId])

  return (
    <Section title="ACTIVITY LEDGER">
      <div style={{ maxHeight: 320, overflowY: 'auto' }}>
        {entries.length === 0 ? (
          <EmptyState icon="history" title="No activity yet" hint="Scans, findings, and sessions for this engagement will appear here as they happen." pad={28} />
        ) : (
          entries.map((e, i) => (
            <div
              key={e.id}
              style={{
                display: 'grid',
                gridTemplateColumns: '120px 10px 1fr',
                gap: 10,
                padding: '7px var(--pad)',
                borderBottom: i < entries.length - 1 ? rule : 'none',
                alignItems: 'center',
              }}
            >
              <span className="mono" style={{ fontSize: 9, color: 'var(--fg-3)' }}>
                {new Date(e.timestamp).toISOString().slice(11, 19)}
              </span>
              <span
                style={{
                  width: 6,
                  height: 6,
                  background: ACTIVITY_COLOR[e.kind ?? 'info'] ?? 'var(--fg-3)',
                  flexShrink: 0,
                }}
              />
              <span className="mono" style={{ fontSize: 11 }}>
                {e.message}
              </span>
            </div>
          ))
        )}
      </div>
    </Section>
  )
}

// ── ScanHistorySection ────────────────────────────────────────────────────────

interface ScanRow {
  id: string
  scan_type: string
  target?: string
  profile?: string
  status: string
  started_at?: string | null
  completed_at?: string | null
  findings_count?: number
  auto_probe?: boolean
}

const SCAN_STATE: Record<string, { dot: string; label: string }> = {
  completed: { dot: 'dot-live', label: 'done' },
  running: { dot: 'dot-warn', label: 'running' },
  pending: { dot: 'dot-idle', label: 'pending' },
  failed: { dot: 'dot-crit', label: 'failed' },
}

function ScanHistorySection({ projectId }: { projectId: string | null }) {
  const navigate = useNavigate()
  const [scans, setScans] = useState<ScanRow[]>([])

  useEffect(() => {
    if (!projectId) { setScans([]); return }
    getProjectScans(projectId)
      .then((d: ScanRow[]) => setScans(d))
      .catch(() => setScans([]))
  }, [projectId])

  return (
    <Section
      title={`SCAN HISTORY · ${scans.length}`}
      right={
        <button className="btn btn-ghost btn-sm" onClick={() => navigate('/scans')}>
          All scans <Icon name="arrow_r" size={9} />
        </button>
      }
    >
      {scans.length === 0 ? (
        <div style={{ padding: 'var(--pad)', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg-3)' }}>
          No scans yet.
        </div>
      ) : (
        <table className="data">
          <thead>
            <tr>
              <th>Tool</th>
              <th>Target</th>
              <th>Profile</th>
              <th style={{ width: 50 }}>Found</th>
              <th style={{ width: 80 }}>Status</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => {
              const st = SCAN_STATE[s.status] ?? SCAN_STATE.pending
              return (
                <tr key={s.id}>
                  <td className="mono" style={{ fontSize: 11 }}>
                    {s.scan_type}
                  </td>
                  <td className="mono" style={{ fontSize: 10, color: 'var(--fg-2)' }}>
                    {s.target ?? '—'}
                  </td>
                  <td className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>
                    {s.profile ?? '—'}
                  </td>
                  <td className="mono tnum" style={{ fontSize: 11, color: 'var(--fg-2)' }}>
                    {s.findings_count ?? '—'}
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span className={`dot ${st.dot}`} />
                      <span className="badge">{st.label}</span>
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </Section>
  )
}

// ── SchedulerSection ──────────────────────────────────────────────────────────

const PLACEHOLDER_JOBS = [
  { id: '1', name: 'Weekly Recon', cron: '0 2 * * 0', nextIn: '6h', target: '10.0.0.0/24' },
  { id: '2', name: 'Daily Web Scan', cron: '0 4 * * *', nextIn: '22h', target: 'app.internal' },
  { id: '3', name: 'Cred Audit', cron: '0 6 * * 1', nextIn: '5d', target: 'all projects' },
]

function SchedulerSection() {
  return (
    <Section title="SCHEDULER" style={{ borderLeft: rule }}>
      <div>
        {PLACEHOLDER_JOBS.map((j, i) => (
          <div
            key={j.id}
            style={{
              display: 'grid',
              gridTemplateColumns: '1fr auto',
              gap: 8,
              padding: '10px var(--pad)',
              borderBottom: i < PLACEHOLDER_JOBS.length - 1 ? rule : 'none',
              alignItems: 'center',
            }}
          >
            <div>
              <div className="mono" style={{ fontSize: 11, fontWeight: 500 }}>
                {j.name}
              </div>
              <div className="mono" style={{ fontSize: 9, color: 'var(--fg-3)', marginTop: 3 }}>
                {j.cron} · {j.target}
              </div>
            </div>
            <span className="mono" style={{ fontSize: 10, color: 'var(--accent)', whiteSpace: 'nowrap' }}>
              next in {j.nextIn}
            </span>
          </div>
        ))}
      </div>
    </Section>
  )
}


// ── ProjectsList ──────────────────────────────────────────────────────────────

function ProjectsList({ onNew, onNavigate }: { onNew: () => void; onNavigate: (id: string) => void }) {
  const { projects, removeProject } = useAppStore()
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null)

  async function handleDelete(id: string) {
    await deleteProject(id)
    removeProject(id)
    setConfirmDeleteId(null)
  }

  return (
    <Section
      title={`PROJECTS · ${projects.length}`}
      right={
        <button className="btn btn-sm btn-primary" onClick={onNew}>
          <Icon name="plus" size={9} color="#1a1408" /> New
        </button>
      }
    >
      {projects.length === 0 ? (
        <div style={{ padding: 'var(--pad)' }}>
          <p style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg-3)', marginBottom: 12 }}>
            No projects yet. Create one to begin.
          </p>
          <button className="btn btn-primary btn-sm" onClick={onNew}>
            <Icon name="plus" size={9} color="#1a1408" /> Create project
          </button>
        </div>
      ) : (
        <div>
          {projects.map((p, i) => (
            <div
              key={p.id}
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr auto',
                gap: 12,
                padding: '10px var(--pad)',
                borderBottom: i < projects.length - 1 ? rule : 'none',
                alignItems: 'center',
              }}
            >
              <div style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {p.name}
                </div>
                {p.description && p.description !== '__seraph_demo__' && (
                  <div
                    className="mono"
                    style={{ fontSize: 10, color: 'var(--fg-3)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                  >
                    {p.description}
                  </div>
                )}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>
                  {p.target_count} {p.target_count === 1 ? 'target' : 'targets'}
                </span>
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => onNavigate(p.id)}
                  style={{ height: 20, padding: '0 8px', fontSize: 9 }}
                >
                  Pentest →
                </button>
                {confirmDeleteId === p.id ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--crit)' }}>Delete?</span>
                    <button
                      className="btn btn-danger btn-sm"
                      onClick={() => handleDelete(p.id)}
                      style={{ height: 20, padding: '0 6px', fontSize: 9 }}
                    >
                      Yes
                    </button>
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() => setConfirmDeleteId(null)}
                      style={{ height: 20, padding: '0 6px', fontSize: 9 }}
                    >
                      No
                    </button>
                  </div>
                ) : (
                  <button
                    className="btn btn-ghost"
                    onClick={() => setConfirmDeleteId(p.id)}
                    title="Delete project"
                    style={{ padding: 4, height: 22, width: 22, justifyContent: 'center' }}
                    onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--crit)')}
                    onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--fg-2)')}
                  >
                    <Icon name="trash" size={11} />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </Section>
  )
}

// ── ProbeToast ────────────────────────────────────────────────────────────────

function ProbeToast({ visible, fading }: { visible: boolean; fading: boolean }) {
  if (!visible) return null
  return (
    <div
      style={{
        position: 'fixed',
        bottom: 24,
        right: 24,
        zIndex: 50,
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        padding: '10px 16px',
        background: 'var(--bg-2)',
        border: '1px solid var(--accent)',
        boxShadow: '0 4px 24px rgba(0,0,0,0.4)',
        transition: 'opacity 0.5s, transform 0.5s',
        opacity: fading ? 0 : 1,
        transform: fading ? 'translateY(8px)' : 'translateY(0)',
      }}
    >
      <span className="dot dot-warn" />
      <Icon name="bolt" size={12} color="var(--accent)" />
      <div>
        <div className="mono" style={{ fontSize: 11.5, fontWeight: 500 }}>
          Auto-probe running
        </div>
        <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', marginTop: 2 }}>
          Background scan started on new target
        </div>
      </div>
    </div>
  )
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const { projects, setProjects, selectedProject } = useAppStore()
  const navigate = useNavigate()
  const [stats, setStats] = useState<PlatformStats | null>(null)
  const [showProjectModal, setShowProjectModal] = useState(false)
  const [now, setNow] = useState(new Date())
  const [findings, setFindings] = useState<FindingRow[]>([])
  const [projectSev, setProjectSev] = useState<Record<string, number>>({})
  const [phases, setPhases] = useState<PhaseData[]>([])

  const [probeToast, setProbeToast] = useState(false)
  const [probeToastFading, setProbeToastFading] = useState(false)
  const wasProbing = useRef(false)
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const projectIdRef = useRef<string | null>(selectedProject?.id ?? null)

  // Clock — updates every 5s
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 5000)
    return () => clearInterval(id)
  }, [])

  function showProbeToastFn() {
    if (toastTimer.current) clearTimeout(toastTimer.current)
    setProbeToast(true)
    setProbeToastFading(false)
    toastTimer.current = setTimeout(() => {
      setProbeToastFading(true)
      toastTimer.current = setTimeout(() => setProbeToast(false), 600)
    }, 4000)
  }

  function loadData() {
    getProjects().then(setProjects).catch(() => {})

    getStats()
      .then((data) => {
        setStats(data)
        const isProbing = data.recent_scans.some(
          (s) => s.auto_probe && (s.status === 'running' || s.status === 'pending')
        )
        if (isProbing && !wasProbing.current) showProbeToastFn()
        wasProbing.current = isProbing

        // Load findings — use recent_findings from stats or fetch separately
        const rf = data.recent_findings ?? []
        if (rf.length > 0) {
          setFindings(
            rf.map((f) => ({
              id: f.id,
              severity: f.severity,
              cvss_score: f.cvss_score,
              title: f.title,
              cve_id: f.cve_id,
              target: f.target,
              status: 'open',
            }))
          )
        } else if (projectIdRef.current) {
          fetch(`${getApiBase()}/findings?project_id=${projectIdRef.current}&limit=8`)
            .then((r) => r.json())
            .then((d) => setFindings(d))
            .catch(() => {})
        }
      })
      .catch(() => {})
  }

  useEffect(() => {
    loadData()
    let delay = 1000
    function connect() {
      const ws = new WebSocket(wsUrl(`/ws/events`))
      wsRef.current = ws
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data)
          if (msg.type === 'scan_update') { loadData(); delay = 1000 }
        } catch { /* ignore */ }
      }
      ws.onclose = () => {
        delay = Math.min(delay * 2, 30000)
        reconnectTimer.current = setTimeout(connect, delay)
      }
    }
    connect()
    return () => {
      if (toastTimer.current) clearTimeout(toastTimer.current)
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [setProjects]) // eslint-disable-line react-hooks/exhaustive-deps

  // Refresh project-specific data when engagement changes
  useEffect(() => {
    projectIdRef.current = selectedProject?.id ?? null
    if (!selectedProject?.id) { setFindings([]); setProjectSev({}); setPhases([]); return }
    const pid = selectedProject.id
    setFindings([])
    setProjectSev({})
    setPhases([])
    fetch(`${getApiBase()}/projects/${pid}/phases`, { cache: 'no-store' })
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (Array.isArray(d)) setPhases(d) })
      .catch(() => {})
    fetch(`${getApiBase()}/findings?project_id=${pid}`)
      .then(r => r.json())
      .then(d => {
        if (!Array.isArray(d)) return
        setFindings(d.slice(0, 8))
        const counts: Record<string, number> = {}
        d.forEach(f => {
          const s = (f.severity ?? '').toLowerCase()
          if (s) counts[s] = (counts[s] ?? 0) + 1
        })
        setProjectSev(counts)
      })
      .catch(() => {})
  }, [selectedProject?.id]) // eslint-disable-line react-hooks/exhaustive-deps

  async function handleCreateProject(
    projectData: { name: string; description: string },
    targets: Array<{ hostname_or_ip: string; target_type: string; ports: string; notes: string }>,
    scope?: { include: string[]; exclude: string[] }
  ) {
    const project = await createProject({ name: projectData.name, description: projectData.description })
    if (scope && (scope.include.length > 0 || scope.exclude.length > 0)) {
      await fetch(`${getApiBase()}/projects/${project.id}/scope`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scope),
      })
    }
    for (const t of targets) {
      if (t.hostname_or_ip.trim()) {
        await createTarget(project.id, {
          hostname_or_ip: t.hostname_or_ip.trim(),
          target_type: t.target_type as any,
          ports: t.ports || undefined,
          notes: t.notes || undefined,
        })
      }
    }
    loadData()
  }

  const sev = selectedProject ? projectSev : (stats?.severity_counts ?? {})
  const projectId = selectedProject?.id ?? (projects.length > 0 ? projects[0].id : null)

  // Generate trend arrays from current severity counts
  const makeTrend = (n: number) => Array.from({ length: 7 }, (_, i) => Math.max(0, n - (6 - i)))

  const runningScans = stats?.recent_scans?.filter((s) => s.status === 'running' || s.status === 'pending').length ?? 0

  // Engagement name + day X of Y
  const engName = selectedProject?.name ?? (projects[0]?.name ?? 'No project selected')
  // Simple day-of-engagement: diff from project created_at
  const dayOf = (() => {
    const proj = selectedProject ?? projects[0]
    if (!proj?.created_at) return null
    const diff = Math.floor((Date.now() - new Date(proj.created_at).getTime()) / 86400000) + 1
    return diff
  })()
  const totalDays = 30 // default engagement length

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column' }}>
      {showProjectModal && (
        <ProjectModal onClose={() => setShowProjectModal(false)} onSave={handleCreateProject} />
      )}

      {/* ── Page header ────────────────────────────────────────────────────── */}
      <div
        style={{
          borderBottom: rule,
          padding: '20px var(--pad) 16px',
          display: 'flex',
          alignItems: 'flex-end',
          justifyContent: 'space-between',
          gap: 16,
        }}
      >
        <div>
          <div className="smcap" style={{ marginBottom: 4 }}>
            {projects.length > 0
              ? `${projects.length} project${projects.length !== 1 ? 's' : ''} · ${selectedProject?.target_count ?? stats?.targets ?? 0} targets`
              : 'workspace'}
          </div>
          <h1 className="mono" style={{ margin: 0, fontWeight: 500, fontSize: 22, letterSpacing: '-0.01em' }}>
            {engName}
            {dayOf !== null && (
              <span style={{ fontSize: 14, color: 'var(--fg-3)', marginLeft: 12 }}>
                day {dayOf} of {totalDays}
              </span>
            )}
          </h1>
          <div style={{ color: 'var(--fg-3)', fontSize: 12, marginTop: 6 }}>
            {runningScans > 0
              ? `${runningScans} scan${runningScans > 1 ? 's' : ''} active · monitoring`
              : 'All systems nominal · monitoring'}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>
          <span className="mono" style={{ fontSize: 11, color: 'var(--fg-3)', letterSpacing: '0.08em' }}>
            {now.toISOString().replace('T', ' ').slice(0, 19)} UTC
          </span>
          <button className="btn" onClick={loadData}>
            <Icon name="refresh" size={11} /> Resync
          </button>
          <button className="btn btn-primary" onClick={() => setShowProjectModal(true)}>
            <Icon name="plus" size={11} color="#1a1408" /> Add target
          </button>
        </div>
      </div>

      {/* ── KPI strip ──────────────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', borderBottom: rule }}>
        <KPI
          label="Critical · open"
          value={sev.critical ?? 0}
          sub={`${sev.critical ?? 0} verified`}
          accentVar="--crit"
          trend={makeTrend(sev.critical ?? 0)}
        />
        <KPI
          label="High · open"
          value={sev.high ?? 0}
          sub="SLA 7d"
          accentVar="--high"
          trend={makeTrend(sev.high ?? 0)}
          divider
        />
        <KPI
          label="Medium · open"
          value={sev.medium ?? 0}
          sub={`${sev.low ?? 0} low open`}
          trend={makeTrend(sev.medium ?? 0)}
          divider
        />
        <KPI
          label="Active sessions"
          value={runningScans}
          sub={`${stats?.scans ?? 0} scans total`}
          accentVar="--accent"
          divider
        />
        <KPI
          label="Captured creds"
          value={0}
          sub="vault entries"
          divider
        />
      </div>

      {/* ── Main grid 1.6fr / 1fr ──────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', borderBottom: rule, minHeight: 0 }}>
        {/* Left column */}
        <div style={{ borderRight: rule }}>
          <PhasePipeline phases={phases} />
          <FindingsPreview findings={findings} />
          <ProjectsList onNew={() => setShowProjectModal(true)} onNavigate={() => navigate('/pentest')} />
        </div>

        {/* Right column */}
        <div>
          <SeverityBreakdown counts={sev} />
          <ActiveSessionsList projectId={projectId} />
          <ActivityLedger projectId={projectId} />
        </div>
      </div>

      {/* ── Bottom strip 2fr / 1fr ─────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr' }}>
        <ScanHistorySection projectId={projectId} />
        <SchedulerSection />
      </div>

      <ProbeToast visible={probeToast} fading={probeToastFading} />
    </div>
  )
}
