import { useEffect, useState } from 'react'
import {
  FolderOpen,
  Target,
  ScanLine,
  CheckCircle2,
  AlertTriangle,
  Loader,
  RefreshCw,
  Filter,
} from 'lucide-react'
import { useAppStore } from '@/stores/appStore'
import type { Project } from '@/types'

interface TimelineEvent {
  id: string
  kind: 'project' | 'target' | 'scan_start' | 'scan_end' | 'finding'
  title: string
  target: string | null
  severity: string | null
  status: string | null
  ts: string
}

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22c55e',
  info: '#3b82f6',
}

const SEV_BG: Record<string, string> = {
  critical: 'rgba(239,68,68,0.12)',
  high: 'rgba(249,115,22,0.12)',
  medium: 'rgba(245,158,11,0.12)',
  low: 'rgba(34,197,94,0.12)',
  info: 'rgba(59,130,246,0.12)',
}

const STATUS_STYLE: Record<string, string> = {
  completed: 'bg-green-500/15 text-green-400 border-green-500/30',
  running: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  pending: 'bg-slate-500/15 text-slate-400 border-slate-500/20',
  failed: 'bg-red-500/15 text-red-400 border-red-500/30',
}

function kindIcon(kind: TimelineEvent['kind']) {
  switch (kind) {
    case 'project':   return <FolderOpen size={14} className="text-cyan-400" />
    case 'target':    return <Target size={14} className="text-violet-400" />
    case 'scan_start':return <ScanLine size={14} className="text-blue-400" />
    case 'scan_end':  return <CheckCircle2 size={14} className="text-green-400" />
    case 'finding':   return <AlertTriangle size={14} className="text-amber-400" />
  }
}

function kindDotColor(kind: TimelineEvent['kind']) {
  switch (kind) {
    case 'project':    return '#06b6d4'
    case 'target':     return '#8b5cf6'
    case 'scan_start': return '#3b82f6'
    case 'scan_end':   return '#22c55e'
    case 'finding':    return '#f59e0b'
  }
}

function fmt(ts: string) {
  const d = new Date(ts)
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

type KindFilter = TimelineEvent['kind'] | 'all'
const KIND_FILTERS: { label: string; value: KindFilter }[] = [
  { label: 'All', value: 'all' },
  { label: 'Projects', value: 'project' },
  { label: 'Targets', value: 'target' },
  { label: 'Scans', value: 'scan_end' },
  { label: 'Findings', value: 'finding' },
]

export default function Timeline() {
  const { selectedProject, setSelectedProject } = useAppStore()
  const [projects, setProjects] = useState<Project[]>([])
  const [localProjectId, setLocalProjectId] = useState<string>(selectedProject?.id ?? '')
  const [events, setEvents] = useState<TimelineEvent[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [kindFilter, setKindFilter] = useState<KindFilter>('all')
  const [severityFilter, setSeverityFilter] = useState<string>('all')

  useEffect(() => {
    fetch('/api/v1/projects')
      .then(r => r.json())
      .then((data: Project[]) => {
        setProjects(data)
        if (!localProjectId && data.length > 0) {
          setLocalProjectId(data[0].id)
        }
      })
      .catch(() => {})
  }, [])

  // Keep local picker in sync if global store changes
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
  const activeProjectName = projects.find(p => p.id === activeProjectId)?.name ?? selectedProject?.name ?? ''

  async function load(projectId: string) {
    setLoading(true)
    setError('')
    try {
      const res = await fetch(`/api/v1/projects/${projectId}/timeline`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data: TimelineEvent[] = await res.json()
      // Reverse so newest is first
      setEvents([...data].reverse())
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load timeline')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (activeProjectId) load(activeProjectId)
    else setEvents([])
  }, [activeProjectId])

  const filtered = events.filter(e => {
    const kindOk = kindFilter === 'all'
      || e.kind === kindFilter
      || (kindFilter === 'scan_end' && (e.kind === 'scan_start' || e.kind === 'scan_end'))
    const sevOk = severityFilter === 'all' || e.severity === severityFilter
    return kindOk && sevOk
  })

  const findingCount = events.filter(e => e.kind === 'finding').length
  const scanCount = events.filter(e => e.kind === 'scan_end').length
  const targetCount = events.filter(e => e.kind === 'target').length
  const criticalCount = events.filter(e => e.severity === 'critical').length

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-white">Engagement Timeline</h1>
          <p className="text-sm text-slate-400 mt-0.5">
            {activeProjectName || 'Select a project'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={localProjectId}
            onChange={e => handleProjectChange(e.target.value)}
            className="rounded px-3 py-1.5 text-sm text-slate-200 border border-cyan-900/30 focus:border-cyan-500/50 focus:outline-none"
            style={{ background: '#090d14' }}
          >
            {projects.length === 0 && <option value="">No projects</option>}
            {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          {activeProjectId && (
            <button
              onClick={() => load(activeProjectId)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs text-slate-300 hover:text-white border border-slate-700 hover:border-slate-500 transition-colors"
            >
              <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
              Refresh
            </button>
          )}
        </div>
      </div>

      {/* Summary cards */}
      {activeProjectId && events.length > 0 && (
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: 'Targets', value: targetCount, color: '#8b5cf6' },
            { label: 'Scans run', value: scanCount, color: '#3b82f6' },
            { label: 'Findings', value: findingCount, color: '#f59e0b' },
            { label: 'Critical', value: criticalCount, color: '#ef4444' },
          ].map(({ label, value, color }) => (
            <div
              key={label}
              className="rounded-lg border border-slate-800 p-3 text-center"
              style={{ background: '#0b1120' }}
            >
              <div className="text-2xl font-bold" style={{ color }}>{value}</div>
              <div className="text-xs text-slate-500 mt-0.5">{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      {events.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <Filter size={14} className="text-slate-500" />
          <div className="flex gap-1">
            {KIND_FILTERS.map(f => (
              <button
                key={f.value}
                onClick={() => setKindFilter(f.value)}
                className={`px-2.5 py-1 rounded text-xs border transition-colors ${
                  kindFilter === f.value
                    ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40'
                    : 'text-slate-400 border-slate-700 hover:border-slate-500'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
          <div className="flex gap-1 ml-2">
            {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2.5 py-1 rounded text-xs border transition-colors ${
                  severityFilter === sev
                    ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40'
                    : 'text-slate-400 border-slate-700 hover:border-slate-500'
                }`}
                style={sev !== 'all' && severityFilter === sev ? { color: SEV_COLOR[sev] } : undefined}
              >
                {sev === 'all' ? 'All sev.' : sev}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* States */}
      {!activeProjectId && (
        <div className="text-center py-20 text-slate-500">Select a project above to view its timeline.</div>
      )}
      {loading && (
        <div className="flex justify-center py-20">
          <Loader size={24} className="animate-spin text-cyan-500" />
        </div>
      )}
      {error && (
        <div className="rounded border border-red-500/30 bg-red-500/10 text-red-400 px-4 py-3 text-sm">{error}</div>
      )}

      {/* Timeline */}
      {!loading && filtered.length === 0 && activeProjectId && !error && (
        <div className="text-center py-20 text-slate-500">No events match the current filters.</div>
      )}

      {!loading && filtered.length > 0 && (
        <div className="relative">
          {/* Vertical line */}
          <div
            className="absolute left-5 top-0 bottom-0 w-px"
            style={{ background: 'linear-gradient(to bottom, #1e293b, #0f172a)' }}
          />

          <div className="space-y-0">
            {filtered.map((event) => (
              <div key={event.id} className="relative flex gap-4 group">
                {/* Dot */}
                <div className="relative z-10 flex-shrink-0 w-10 h-10 flex items-center justify-center">
                  <div
                    className="w-3 h-3 rounded-full border-2 transition-transform group-hover:scale-125"
                    style={{
                      background: kindDotColor(event.kind),
                      borderColor: '#0f172a',
                      boxShadow: `0 0 8px ${kindDotColor(event.kind)}60`,
                    }}
                  />
                </div>

                {/* Card */}
                <div
                  className="flex-1 mb-3 rounded-lg border border-slate-800/80 px-4 py-3 transition-colors group-hover:border-slate-700"
                  style={{ background: '#080e1a' }}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-2 min-w-0">
                      {kindIcon(event.kind)}
                      <span className="text-sm text-slate-200 truncate">{event.title}</span>
                    </div>
                    <span className="text-xs text-slate-500 flex-shrink-0">{fmt(event.ts)}</span>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 mt-2">
                    {event.target && (
                      <span className="text-xs text-slate-500 font-mono">{event.target}</span>
                    )}
                    {event.severity && (
                      <span
                        className="text-xs px-1.5 py-0.5 rounded border"
                        style={{
                          color: SEV_COLOR[event.severity] ?? '#94a3b8',
                          background: SEV_BG[event.severity] ?? 'rgba(148,163,184,0.1)',
                          borderColor: `${SEV_COLOR[event.severity] ?? '#94a3b8'}40`,
                        }}
                      >
                        {event.severity}
                      </span>
                    )}
                    {event.status && (
                      <span className={`text-xs px-1.5 py-0.5 rounded border ${STATUS_STYLE[event.status] ?? 'text-slate-400 border-slate-600'}`}>
                        {event.status}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
