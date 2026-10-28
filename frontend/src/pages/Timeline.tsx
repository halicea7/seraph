import { useEffect, useState } from 'react'
import Icon from '../components/Icon'
import { useAppStore } from '@/stores/appStore'
import type { Project } from '@/types'
import { getApiBase } from '@/lib/config'

// ── Types ─────────────────────────────────────────────────────────────────────

interface TimelineEvent {
  id: string
  kind: 'project' | 'target' | 'scan_start' | 'scan_end' | 'finding'
  title: string
  target: string | null
  severity: string | null
  status: string | null
  ts: string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const rule = '1px solid var(--rule)'

function PageHeader({ title, sub, right }: { title: string; sub: string; right?: React.ReactNode }) {
  return (
    <div style={{ borderBottom: rule, padding: '24px var(--pad) 18px', display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: 16, flexShrink: 0 }}>
      <div>
        <h1 className="mono" style={{ margin: 0, fontWeight: 500, fontSize: 22, letterSpacing: '-0.01em' }}>{title}</h1>
        <div style={{ color: 'var(--fg-3)', fontSize: 12, marginTop: 6 }}>{sub}</div>
      </div>
      {right && <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>{right}</div>}
    </div>
  )
}

function SegBtns({ options, value, onChange }: { options: string[]; value: string; onChange: (v: string) => void }) {
  return (
    <div style={{ display: 'flex', border: rule, height: 26 }}>
      {options.map((o, i) => (
        <button key={o} onClick={() => onChange(o)} style={{
          background: value === o ? 'var(--accent-2)' : 'transparent',
          color: value === o ? 'var(--accent)' : 'var(--fg-3)',
          border: 'none', borderLeft: i > 0 ? rule : 'none',
          padding: '0 10px', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em',
          cursor: 'pointer', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap',
        }}>{o}</button>
      ))}
    </div>
  )
}

function dotStyle(sev: string | null, kind: TimelineEvent['kind']): React.CSSProperties {
  if (sev === 'critical') {
    return { background: 'var(--crit)', border: '2px solid var(--bg)' }
  }
  if (sev === 'high') {
    return { background: 'var(--high)', border: '2px solid var(--bg)' }
  }
  switch (kind) {
    case 'scan_start':
    case 'finding':
      return { background: 'var(--accent)', border: '2px solid var(--bg)' }
    case 'scan_end':
      return { background: 'var(--ok)', border: '2px solid var(--bg)' }
    case 'target':
      return { background: '#8b5cf6', border: '2px solid var(--bg)' }
    default:
      return { background: 'var(--fg-3)', border: '2px solid var(--bg)' }
  }
}

function fmt(ts: string) {
  const d = new Date(ts)
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function Timeline() {
  const { selectedProject, setSelectedProject } = useAppStore()
  const [projects, setProjects] = useState<Project[]>([])
  const [localProjectId, setLocalProjectId] = useState<string>(selectedProject?.id ?? '')
  const [events, setEvents] = useState<TimelineEvent[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [timeRange, setTimeRange] = useState('7d')

  useEffect(() => {
    fetch(`${getApiBase()}/projects`)
      .then(r => r.json())
      .then((data: Project[]) => {
        setProjects(data)
        if (!localProjectId && data.length > 0) setLocalProjectId(data[0].id)
      })
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (selectedProject?.id && selectedProject.id !== localProjectId) {
      setLocalProjectId(selectedProject.id)
    }
  }, [selectedProject?.id])

  function handleProjectChange(id: string) {
    setLocalProjectId(id)
    const proj = projects.find(p => p.id === id)
    if (proj) setSelectedProject(proj)
  }

  const activeProjectId = localProjectId || selectedProject?.id || ''

  async function load(projectId: string) {
    setLoading(true); setError('')
    try {
      const res = await fetch(`${getApiBase()}/projects/${projectId}/timeline`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data: TimelineEvent[] = await res.json()
      setEvents([...data].reverse())
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load timeline')
    } finally { setLoading(false) }
  }

  useEffect(() => {
    if (activeProjectId) load(activeProjectId)
    else setEvents([])
  }, [activeProjectId])

  function exportJsonl() {
    const lines = filteredEvents.map(e => JSON.stringify(e)).join('\n')
    const blob = new Blob([lines], { type: 'application/jsonl' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = 'timeline.jsonl'; a.click()
    URL.revokeObjectURL(url)
  }

  // Apply the time-range filter (Today / 7d / 30d / Engagement).
  function inRange(ts: string): boolean {
    if (timeRange === 'Engagement') return true
    const t = new Date(ts).getTime()
    if (timeRange === 'Today') { const d = new Date(); d.setHours(0, 0, 0, 0); return t >= d.getTime() }
    if (timeRange === '7d') return Date.now() - t <= 7 * 86_400_000
    if (timeRange === '30d') return Date.now() - t <= 30 * 86_400_000
    return true
  }
  const filteredEvents = events.filter(e => inRange(e.ts))

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg)', color: 'var(--fg)' }}>

      <PageHeader
        title="Timeline"
        sub="Reconstructed engagement timeline — events from scans, findings, and target additions."
        right={
          <>
            {/* project selector */}
            {projects.length > 1 && (
              <select
                value={localProjectId}
                onChange={e => handleProjectChange(e.target.value)}
                style={{ background: 'var(--bg)', border: rule, borderRadius: 3, padding: '4px 10px', fontSize: 11, color: 'var(--fg)', fontFamily: 'var(--font-sans)', outline: 'none', height: 26 }}
              >
                {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            )}
            <SegBtns options={['Today', '7d', '30d', 'Engagement']} value={timeRange} onChange={setTimeRange} />
            <button className="btn" onClick={exportJsonl} disabled={filteredEvents.length === 0} style={{ opacity: filteredEvents.length === 0 ? 0.4 : 1 }}>
              <Icon name="download" size={12} color="currentColor" /> Export JSONL
            </button>
          </>
        }
      />

      <div style={{ flex: 1, overflowY: 'auto', padding: '20px var(--pad)' }}>

        {!activeProjectId && (
          <div style={{ textAlign: 'center', padding: '80px 0', color: 'var(--fg-3)', fontSize: 13 }}>
            Select a project to view its timeline.
          </div>
        )}

        {loading && (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '80px 0' }}>
            <Icon name="refresh" size={24} color="var(--accent)" />
          </div>
        )}

        {error && (
          <div style={{ background: 'rgba(232,64,64,0.08)', border: '1px solid rgba(232,64,64,0.3)', borderRadius: 3, color: 'var(--crit)', padding: '10px 14px', fontSize: 13 }}>
            {error}
          </div>
        )}

        {!loading && !error && activeProjectId && filteredEvents.length === 0 && (
          <div style={{ textAlign: 'center', padding: '80px 0', color: 'var(--fg-3)', fontSize: 13 }}>
            {events.length === 0 ? 'No events in this project yet.' : `No events in the “${timeRange}” range.`}
          </div>
        )}

        {!loading && filteredEvents.length > 0 && (
          <div style={{ position: 'relative', paddingLeft: 80 }}>
            {/* Vertical line */}
            <div style={{ position: 'absolute', left: 76, top: 0, bottom: 0, width: 1, background: 'var(--rule-strong)' }} />

            {filteredEvents.map(event => (
              <div key={event.id} style={{ display: 'grid', gridTemplateColumns: '60px 1fr', gap: 16, marginBottom: 18 }}>
                {/* Time */}
                <div className="mono" style={{ fontSize: 11, color: 'var(--fg-3)', textAlign: 'right', paddingTop: 2 }}>
                  {fmt(event.ts)}
                </div>

                {/* Content */}
                <div style={{ position: 'relative', paddingLeft: 22 }}>
                  {/* Dot */}
                  <div style={{
                    position: 'absolute',
                    left: -5,
                    top: 4,
                    width: 10,
                    height: 10,
                    borderRadius: '50%',
                    ...dotStyle(event.severity, event.kind),
                  }} />

                  {/* Kind badge */}
                  <span className="badge badge-info" style={{ textTransform: 'uppercase' }}>
                    {event.kind.replace('_', ' ')}
                  </span>

                  {/* Title */}
                  <div style={{ fontSize: 13, color: 'var(--fg)', marginTop: 6, lineHeight: 1.5 }}>
                    {event.title}
                  </div>

                  {/* Meta */}
                  {(event.target || event.severity || event.status) && (
                    <div style={{ display: 'flex', gap: 8, marginTop: 4, flexWrap: 'wrap' }}>
                      {event.target && (
                        <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>{event.target}</span>
                      )}
                      {event.severity && (
                        <span className="mono" style={{
                          fontSize: 10,
                          color: event.severity === 'critical' ? 'var(--crit)'
                            : event.severity === 'high' ? 'var(--high)'
                            : event.severity === 'medium' ? 'var(--accent)'
                            : 'var(--ok)',
                        }}>{event.severity}</span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
