import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  FolderOpen,
  Target,
  ScanLine,
  AlertTriangle,
  Plus,
  ShieldCheck,
  Swords,
  Activity,
  BarChart2,
  Zap,
  Trash2,
} from 'lucide-react'
import { useAppStore } from '@/stores/appStore'
import { getProjects, getStats, createProject, createTarget, deleteProject, type PlatformStats } from '@/api/client'
import ProjectModal from '@/components/ProjectModal'
import SparkLine from '@/components/SparkLine'

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22c55e',
  info: '#3b82f6',
}

const SEV_BG: Record<string, string> = {
  critical: 'rgba(239,68,68,0.15)',
  high: 'rgba(249,115,22,0.15)',
  medium: 'rgba(245,158,11,0.15)',
  low: 'rgba(34,197,94,0.15)',
  info: 'rgba(59,130,246,0.15)',
}

const STATUS_COLORS: Record<string, string> = {
  completed: '#22c55e',
  running: '#3b82f6',
  pending: '#64748b',
  failed: '#ef4444',
}

const STATUS_STYLES: Record<string, string> = {
  completed: 'bg-green-500/15 text-green-400 border border-green-500/30',
  running: 'bg-blue-500/15 text-blue-400 border border-blue-500/30',
  pending: 'bg-slate-500/15 text-slate-400 border border-slate-500/20',
  failed: 'bg-red-500/15 text-red-400 border border-red-500/30',
}

function useCountUp(target: number, duration = 900) {
  const [value, setValue] = useState(0)
  useEffect(() => {
    if (target === 0) { setValue(0); return }
    const steps = 30
    const increment = target / steps
    const interval = duration / steps
    let current = 0
    const timer = setInterval(() => {
      current += increment
      if (current >= target) {
        setValue(target)
        clearInterval(timer)
      } else {
        setValue(Math.floor(current))
      }
    }, interval)
    return () => clearInterval(timer)
  }, [target, duration])
  return value
}

function StatCard({ label, value, icon, accent, borderColor }: {
  label: string
  value: number
  icon: React.ReactNode
  accent: string
  borderColor: string
}) {
  const displayValue = useCountUp(value)
  return (
    <div
      className="glass glass-hover rounded-xl p-5 shadow-card border-t-2 flex items-start gap-4"
      style={{ borderTopColor: borderColor }}
    >
      <div
        className="flex items-center justify-center w-10 h-10 rounded-lg shrink-0"
        style={{ backgroundColor: `${accent}18`, color: accent }}
      >
        {icon}
      </div>
      <div>
        <p className="text-3xl font-bold font-mono gradient-text">{displayValue}</p>
        <p className="text-xs text-slate-400 mt-0.5">{label}</p>
      </div>
    </div>
  )
}

function DonutChart({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0)
  if (total === 0) return <div className="text-slate-500 text-sm text-center py-8">No findings yet</div>

  const colors = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22c55e', info: '#3b82f6' }
  const order = ['critical', 'high', 'medium', 'low', 'info']

  const cx = 80, cy = 80, r = 60, strokeWidth = 16
  const circumference = 2 * Math.PI * r

  let offset = 0
  const segments = order.map(key => {
    const count = counts[key] || 0
    const pct = count / total
    const dash = pct * circumference
    const seg = { key, count, color: colors[key as keyof typeof colors], dash, offset }
    offset += dash
    return seg
  })

  return (
    <div className="flex items-center gap-6">
      <svg width="160" height="160" viewBox="0 0 160 160" className="flex-shrink-0">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#0d1520" strokeWidth={strokeWidth} />
        {segments.map(seg => seg.count > 0 && (
          <circle
            key={seg.key}
            cx={cx} cy={cy} r={r}
            fill="none"
            stroke={seg.color}
            strokeWidth={strokeWidth}
            strokeDasharray={`${seg.dash} ${circumference - seg.dash}`}
            strokeDashoffset={-seg.offset + circumference / 4}
            strokeLinecap="butt"
            style={{ filter: `drop-shadow(0 0 4px ${seg.color}80)` }}
          />
        ))}
        <text x={cx} y={cy - 8} textAnchor="middle" fill="#e2e8f0" fontSize="22" fontWeight="700" fontFamily="monospace">{total}</text>
        <text x={cx} y={cy + 10} textAnchor="middle" fill="#64748b" fontSize="10">findings</text>
      </svg>
      <div className="space-y-1.5">
        {order.map(key => (
          <div key={key} className="flex items-center gap-2">
            <div
              className="w-2 h-2 rounded-full flex-shrink-0"
              style={{
                backgroundColor: colors[key as keyof typeof colors],
                boxShadow: `0 0 6px ${colors[key as keyof typeof colors]}`
              }}
            />
            <span className="text-xs text-slate-300 capitalize w-16">{key}</span>
            <span className="text-xs font-mono text-white font-bold">{counts[key] || 0}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function Dashboard() {
  const { projects, setProjects, removeProject } = useAppStore()
  const navigate = useNavigate()
  const [stats, setStats] = useState<PlatformStats | null>(null)
  const [history, setHistory] = useState<{ days: string[]; pivot: Record<string, Record<string, number>> } | null>(null)
  const [showProjectModal, setShowProjectModal] = useState(false)
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null)

  // Auto-probe toast
  const [probeToast, setProbeToast] = useState(false)
  const [probeToastFading, setProbeToastFading] = useState(false)
  const wasProbing = useRef(false)
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  function showProbeToast() {
    if (toastTimer.current) clearTimeout(toastTimer.current)
    setProbeToast(true)
    setProbeToastFading(false)
    toastTimer.current = setTimeout(() => {
      setProbeToastFading(true)
      toastTimer.current = setTimeout(() => setProbeToast(false), 600)
    }, 4000)
  }

  function loadData() {
    getProjects()
      .then(setProjects)
      .catch(() => {})

    getStats()
      .then(data => {
        setStats(data)
        const isProbing = data.recent_scans.some(s => s.auto_probe && (s.status === 'running' || s.status === 'pending'))
        if (isProbing && !wasProbing.current) showProbeToast()
        wasProbing.current = isProbing
      })
      .catch(() => {})

    fetch('/api/v1/stats/history')
      .then(r => r.json())
      .then(setHistory)
      .catch(() => {})
  }

  useEffect(() => {
    loadData()
    return () => { if (toastTimer.current) clearTimeout(toastTimer.current) }
  }, [setProjects])  // eslint-disable-line react-hooks/exhaustive-deps

  async function handleDeleteProject(id: string) {
    await deleteProject(id)
    removeProject(id)
    setConfirmDeleteId(null)
    loadData()
  }

  async function handleCreateProject(
    projectData: { name: string; description: string },
    targets: Array<{ hostname_or_ip: string; target_type: string; ports: string; notes: string }>
  ) {
    const project = await createProject({
      name: projectData.name,
      description: projectData.description,
    })
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

  const severityCounts = stats?.severity_counts || {}

  const statCards = [
    {
      label: 'Total Projects',
      value: stats?.projects ?? projects.length,
      icon: <FolderOpen size={20} />,
      accent: '#3b82f6',
      borderColor: 'rgba(59,130,246,0.5)',
    },
    {
      label: 'Targets',
      value: stats?.targets ?? projects.reduce((sum, p) => sum + p.target_count, 0),
      icon: <Target size={20} />,
      accent: '#06b6d4',
      borderColor: 'rgba(6,182,212,0.5)',
    },
    {
      label: 'Scans Run',
      value: stats?.scans ?? 0,
      icon: <ScanLine size={20} />,
      accent: '#f59e0b',
      borderColor: 'rgba(245,158,11,0.5)',
    },
    {
      label: 'Findings',
      value: stats?.findings ?? 0,
      icon: <AlertTriangle size={20} />,
      accent: '#ef4444',
      borderColor: 'rgba(239,68,68,0.5)',
    },
  ]

  return (
    <div className="p-8">
      {showProjectModal && (
        <ProjectModal
          onClose={() => setShowProjectModal(false)}
          onSave={handleCreateProject}
        />
      )}

      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-white tracking-wide">Dashboard</h1>
        <p className="text-sm text-slate-400 mt-1">
          Overview of your security assessment workspace
        </p>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {statCards.map((stat) => (
          <StatCard key={stat.label} {...stat} />
        ))}
      </div>

      {/* Projects list */}
      {projects.length > 0 && (
        <div className="glass rounded-xl mb-6 overflow-hidden">
          <div className="flex items-center gap-2 px-5 py-3.5 border-b border-cyan-900/15">
            <FolderOpen size={15} className="text-blue-400" />
            <h2 className="text-xs font-semibold text-white uppercase tracking-wider flex-1">Projects</h2>
            <button
              onClick={() => setShowProjectModal(true)}
              className="flex items-center gap-1 text-[11px] text-cyan-500 hover:text-cyan-300 transition-colors"
            >
              <Plus size={11} /> New
            </button>
          </div>
          <div className="divide-y divide-cyan-900/10">
            {projects.map(p => (
              <div key={p.id} className="flex items-center gap-4 px-5 py-3 hover:bg-cyan-950/10 transition-colors group">
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-slate-200 truncate">{p.name}</p>
                  {p.description && p.description !== '__seraph_demo__' && (
                    <p className="text-xs text-slate-500 truncate">{p.description}</p>
                  )}
                </div>
                <span className="text-xs text-slate-600 shrink-0 font-mono">
                  {p.target_count} {p.target_count === 1 ? 'target' : 'targets'}
                </span>
                <button
                  onClick={() => navigate('/pentest')}
                  className="text-xs text-cyan-500 hover:text-cyan-300 transition-colors shrink-0 opacity-0 group-hover:opacity-100"
                >
                  Pentest →
                </button>
                {confirmDeleteId === p.id ? (
                  <div className="flex items-center gap-1.5 shrink-0">
                    <span className="text-xs text-red-400">Delete?</span>
                    <button
                      onClick={() => handleDeleteProject(p.id)}
                      className="text-xs px-2 py-0.5 rounded bg-red-600/20 text-red-400 border border-red-600/30 hover:bg-red-600/30 transition-colors"
                    >
                      Yes
                    </button>
                    <button
                      onClick={() => setConfirmDeleteId(null)}
                      className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
                    >
                      No
                    </button>
                  </div>
                ) : (
                  <button
                    onClick={() => setConfirmDeleteId(p.id)}
                    className="text-slate-700 hover:text-red-400 transition-colors shrink-0 opacity-0 group-hover:opacity-100"
                    title="Delete project"
                  >
                    <Trash2 size={14} />
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {/* Findings by Severity — Donut Chart */}
        <div className="glass glass-hover rounded-xl border-cyan-900/20 p-6">
          <div className="flex items-center gap-2 mb-4">
            <BarChart2 size={16} className="text-amber-400" />
            <h2 className="text-sm font-semibold text-white uppercase tracking-wider">
              Findings by Severity
            </h2>
          </div>
          <DonutChart counts={severityCounts} />
        </div>

        {/* Quick Actions */}
        <div className="glass glass-hover rounded-xl border-cyan-900/20 p-6">
          <div className="flex items-center gap-2 mb-4">
            <Plus size={16} className="text-cyan-400" />
            <h2 className="text-sm font-semibold text-white uppercase tracking-wider">
              Quick Actions
            </h2>
          </div>
          <div className="space-y-3">
            <button
              onClick={() => setShowProjectModal(true)}
              className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm text-slate-300 hover:text-white transition-all duration-150 glass glass-hover"
            >
              <div className="flex items-center justify-center w-8 h-8 rounded" style={{ background: 'rgba(59,130,246,0.1)' }}>
                <Plus size={14} className="text-blue-400" />
              </div>
              <div className="text-left">
                <p className="font-medium">New Project</p>
                <p className="text-xs text-slate-400">Start a new security assessment</p>
              </div>
            </button>

            <button
              onClick={() => navigate('/audit')}
              className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm text-slate-300 hover:text-white transition-all duration-150 glass glass-hover"
            >
              <div className="flex items-center justify-center w-8 h-8 rounded" style={{ background: 'rgba(34,197,94,0.1)' }}>
                <ShieldCheck size={14} className="text-green-400" />
              </div>
              <div className="text-left">
                <p className="font-medium">Run Audit</p>
                <p className="text-xs text-slate-400">CIS / NIST compliance check</p>
              </div>
            </button>

            <button
              onClick={() => navigate('/pentest')}
              className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm text-slate-300 hover:text-white transition-all duration-150 glass glass-hover"
            >
              <div className="flex items-center justify-center w-8 h-8 rounded" style={{ background: 'rgba(239,68,68,0.1)' }}>
                <Swords size={14} className="text-red-400" />
              </div>
              <div className="text-left">
                <p className="font-medium">Start Pentest</p>
                <p className="text-xs text-slate-400">Launch penetration test workflow</p>
              </div>
            </button>
          </div>
        </div>
      </div>

      {/* Auto-probe toast — fixed corner pop-up */}
      {probeToast && (
        <div
          className="fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-xl border border-green-700/40 shadow-2xl"
          style={{
            background: 'rgba(5,46,22,0.92)',
            backdropFilter: 'blur(12px)',
            transition: 'opacity 0.5s ease, transform 0.5s ease',
            opacity: probeToastFading ? 0 : 1,
            transform: probeToastFading ? 'translateY(8px)' : 'translateY(0)',
          }}
        >
          <span className="relative flex h-2.5 w-2.5 shrink-0">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-60" />
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-400" />
          </span>
          <Zap size={13} className="text-green-400 shrink-0" />
          <div>
            <p className="text-sm text-green-300 font-medium leading-none">Auto-Probe running</p>
            <p className="text-[11px] text-green-600 mt-0.5">Background scan started on new target</p>
          </div>
        </div>
      )}

      {/* Severity Trend */}
      {history && history.days.length > 0 && (
        <div className="glass rounded-xl border-cyan-900/20 p-5 mb-6">
          <div className="flex items-center gap-2 mb-4">
            <BarChart2 size={15} className="text-cyan-400" />
            <h2 className="text-xs font-semibold text-white uppercase tracking-wider">14-Day Finding Trend</h2>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
            {(['critical','high','medium','low','info'] as const).map(sev => {
              const vals = history.days.map(d => history.pivot[d]?.[sev] ?? 0)
              const total = vals.reduce((a, b) => a + b, 0)
              return (
                <div key={sev} className="flex flex-col gap-1">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-bold uppercase tracking-wider capitalize" style={{ color: SEV_COLOR[sev] }}>{sev}</span>
                    <span className="text-[11px] font-mono text-slate-400">{total}</span>
                  </div>
                  <SparkLine values={vals} color={SEV_COLOR[sev]} width={120} height={36} />
                </div>
              )
            })}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans */}
        <div className="glass rounded-xl border-cyan-900/20 flex flex-col" style={{ maxHeight: '340px' }}>
          <div className="flex items-center gap-2 px-5 py-3.5 border-b border-cyan-900/15 shrink-0">
            <Activity size={15} className="text-cyan-400" />
            <h2 className="text-xs font-semibold text-white uppercase tracking-wider flex-1">Recent Scans</h2>
            <button
              onClick={() => navigate('/scans')}
              className="text-[11px] text-cyan-500 hover:text-cyan-300 transition-colors font-medium"
            >
              View All →
            </button>
          </div>
          {!stats || stats.recent_scans.length === 0 ? (
            <div className="flex-1 flex items-center justify-center">
              <p className="text-slate-500 text-sm">No scans yet.</p>
            </div>
          ) : (
            <ul className="overflow-y-auto flex-1 divide-y divide-cyan-900/10">
              {stats.recent_scans.map((scan) => (
                <li key={scan.id} className="flex items-center gap-2.5 px-4 py-2.5 hover:bg-cyan-950/10 transition-colors">
                  <div className="w-1 h-6 rounded-full shrink-0" style={{ backgroundColor: STATUS_COLORS[scan.status] || STATUS_COLORS.pending }} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-slate-200 truncate font-mono">{scan.scan_type}</p>
                    <p className="text-[11px] text-slate-500 truncate">{scan.target}</p>
                  </div>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium shrink-0 ${STATUS_STYLES[scan.status] || STATUS_STYLES.pending}`}>
                    {scan.status}
                  </span>
                  {scan.auto_probe && (
                    <span className="text-[10px] text-green-400 shrink-0 flex items-center gap-0.5">
                      <Zap size={9} />
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Recent Findings */}
        <div className="glass rounded-xl border-cyan-900/20 flex flex-col" style={{ maxHeight: '340px' }}>
          <div className="flex items-center gap-2 px-5 py-3.5 border-b border-cyan-900/15 shrink-0">
            <AlertTriangle size={15} className="text-red-400" />
            <h2 className="text-xs font-semibold text-white uppercase tracking-wider flex-1">Recent Findings</h2>
            <button
              onClick={() => navigate('/findings')}
              className="text-[11px] text-cyan-500 hover:text-cyan-300 transition-colors font-medium"
            >
              View All →
            </button>
          </div>
          {!stats || !stats.recent_findings || stats.recent_findings.length === 0 ? (
            <div className="flex-1 flex items-center justify-center">
              <p className="text-slate-500 text-sm">No findings yet.</p>
            </div>
          ) : (
            <ul className="overflow-y-auto flex-1 divide-y divide-cyan-900/10">
              {stats.recent_findings.map((f) => (
                <li key={f.id} className="flex items-center gap-2.5 px-4 py-2.5 hover:bg-cyan-950/10 transition-colors">
                  <span
                    className="text-[9px] font-bold px-1.5 py-0.5 rounded uppercase shrink-0 w-14 text-center"
                    style={{ background: SEV_BG[f.severity] ?? 'rgba(100,116,139,0.15)', color: SEV_COLOR[f.severity] ?? '#94a3b8' }}
                  >
                    {f.severity}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-slate-200 truncate">{f.title}</p>
                    <p className="text-[11px] text-slate-500 truncate font-mono">{f.target}</p>
                  </div>
                  {f.cve_id && (
                    <span className="text-[10px] text-blue-400 font-mono shrink-0">{f.cve_id}</span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  )
}
