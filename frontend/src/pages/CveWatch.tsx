import { useState, useEffect } from 'react'
import { ShieldAlert, RefreshCw, Eye, ChevronDown, ChevronRight, Clock, AlertTriangle } from 'lucide-react'
import type { Project } from '../types/index'

interface WatchedService {
  id: string
  target_id: string
  service_term: string
  last_checked: string | null
  known_cves: string[]  // parsed from JSON
  created_at: string
}

interface Target {
  id: string
  hostname_or_ip: string
  project_id: string
}

interface CveFinding {
  id: string
  severity: string
  title: string
  description: string
  cve_id: string | null
  created_at: string
}

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-900/40 text-red-300 border-red-500/30',
  high:     'bg-orange-900/40 text-orange-300 border-orange-500/30',
  medium:   'bg-amber-900/40 text-amber-300 border-amber-500/30',
  low:      'bg-green-900/40 text-green-300 border-green-500/30',
  info:     'bg-blue-900/40 text-blue-300 border-blue-500/30',
}

export default function CveWatch() {
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedProject, setSelectedProject] = useState('')
  const [targets, setTargets] = useState<Target[]>([])
  const [watchedServices, setWatchedServices] = useState<Record<string, WatchedService[]>>({})  // target_id → services
  const [cveFindings, setCveFindings] = useState<CveFinding[]>([])
  const [expandedTarget, setExpandedTarget] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    fetch('/api/v1/projects').then(r => r.json()).then(data => {
      setProjects(data)
      if (data.length > 0) setSelectedProject(data[0].id)
    })
  }, [])

  useEffect(() => {
    if (selectedProject) loadData()
  }, [selectedProject])

  async function loadData() {
    setLoading(true)
    try {
      const [targetsRes, wsRes, findingsRes] = await Promise.all([
        fetch(`/api/v1/projects/${selectedProject}/targets`),
        fetch(`/api/v1/cve-watch?project_id=${selectedProject}`),
        fetch(`/api/v1/findings?project_id=${selectedProject}`),
      ])

      const targetsData: Target[] = targetsRes.ok ? await targetsRes.json() : []
      setTargets(targetsData)

      // Group watched services by target
      const wsData: WatchedService[] = wsRes.ok ? await wsRes.json() : []
      const grouped: Record<string, WatchedService[]> = {}
      for (const ws of wsData) {
        if (!grouped[ws.target_id]) grouped[ws.target_id] = []
        grouped[ws.target_id].push(ws)
      }
      setWatchedServices(grouped)

      // CVE-related findings only
      const findingsData: CveFinding[] = findingsRes.ok ? (await findingsRes.json()).filter((f: CveFinding) => f.cve_id) : []
      setCveFindings(findingsData)
    } finally {
      setLoading(false)
    }
  }

  const totalServices = Object.values(watchedServices).flat().length
  const totalCves = Object.values(watchedServices).flat().reduce((acc, ws) => acc + ws.known_cves.length, 0)

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <ShieldAlert size={20} className="text-amber-400" />
            CVE Watchlist
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Services discovered via auto-probe are watched for new CVEs daily.
          </p>
        </div>
        <button
          onClick={loadData}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg glass glass-hover text-xs text-slate-300"
        >
          <RefreshCw size={12} className={loading ? 'animate-spin text-cyan-400' : ''} />
          Refresh
        </button>
      </div>

      {/* Project selector */}
      <div className="flex items-center gap-3">
        <label className="text-xs text-slate-400 shrink-0">Project</label>
        <select
          className="bg-slate-900/60 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500/50"
          value={selectedProject}
          onChange={e => setSelectedProject(e.target.value)}
        >
          {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 gap-4 max-w-lg">
        <div className="glass rounded-xl p-4 text-center">
          <p className="text-2xl font-bold text-white">{targets.length}</p>
          <p className="text-xs text-slate-400 mt-0.5">Targets</p>
        </div>
        <div className="glass rounded-xl p-4 text-center">
          <p className="text-2xl font-bold text-white">{totalServices}</p>
          <p className="text-xs text-slate-400 mt-0.5">Watched Services</p>
        </div>
        <div className="glass rounded-xl p-4 text-center">
          <p className={`text-2xl font-bold ${totalCves > 0 ? 'text-amber-400' : 'text-white'}`}>{totalCves}</p>
          <p className="text-xs text-slate-400 mt-0.5">Known CVEs</p>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-16">
          <RefreshCw size={24} className="animate-spin text-cyan-400" />
        </div>
      ) : targets.length === 0 ? (
        <div className="glass rounded-xl p-12 text-center text-slate-500">
          <ShieldAlert size={40} className="mx-auto opacity-20 mb-3" />
          <p className="text-sm">No targets in this project. Add a target with Auto-Probe enabled to start watching for CVEs.</p>
        </div>
      ) : (
        <div className="space-y-3 max-w-3xl">
          {targets.map(target => {
            const services = watchedServices[target.id] || []
            const expanded = expandedTarget === target.id
            const cveCount = services.reduce((acc, ws) => acc + ws.known_cves.length, 0)

            return (
              <div key={target.id} className="glass rounded-xl overflow-hidden">
                <button
                  onClick={() => setExpandedTarget(expanded ? null : target.id)}
                  className="w-full flex items-center gap-3 px-4 py-3 hover:bg-white/5 transition-colors text-left"
                >
                  {expanded ? <ChevronDown size={14} className="text-slate-400 shrink-0" /> : <ChevronRight size={14} className="text-slate-400 shrink-0" />}
                  <span className="flex-1 text-sm font-medium text-white">{target.hostname_or_ip}</span>
                  <div className="flex items-center gap-2">
                    {services.length > 0 && (
                      <span className="text-[10px] px-2 py-0.5 rounded-full border border-blue-500/30 text-blue-400 bg-blue-900/20">
                        {services.length} service{services.length !== 1 ? 's' : ''}
                      </span>
                    )}
                    {cveCount > 0 && (
                      <span className="text-[10px] px-2 py-0.5 rounded-full border border-amber-500/30 text-amber-400 bg-amber-900/20 flex items-center gap-1">
                        <AlertTriangle size={9} /> {cveCount} CVE{cveCount !== 1 ? 's' : ''}
                      </span>
                    )}
                    {services.length === 0 && (
                      <span className="text-[10px] text-slate-500">No services detected yet</span>
                    )}
                  </div>
                </button>

                {expanded && services.length > 0 && (
                  <div className="border-t border-slate-800/60 divide-y divide-slate-800/40">
                    {services.map(ws => (
                      <div key={ws.id} className="px-5 py-3 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-mono text-cyan-300">{ws.service_term}</span>
                          {ws.last_checked && (
                            <span className="text-[10px] text-slate-500 flex items-center gap-1">
                              <Clock size={9} /> {new Date(ws.last_checked).toLocaleDateString()}
                            </span>
                          )}
                        </div>
                        {ws.known_cves.length > 0 ? (
                          <div className="flex flex-wrap gap-1.5">
                            {ws.known_cves.map(cve => (
                              <a
                                key={cve}
                                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                                target="_blank"
                                rel="noreferrer"
                                className="text-[10px] px-1.5 py-0.5 rounded border border-amber-500/30 text-amber-400 bg-amber-900/20 hover:bg-amber-900/40 transition-colors font-mono"
                              >
                                {cve}
                              </a>
                            ))}
                          </div>
                        ) : (
                          <p className="text-[11px] text-slate-500">No CVEs found yet — will check nightly.</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {expanded && services.length === 0 && (
                  <div className="px-5 py-3 border-t border-slate-800/60">
                    <p className="text-xs text-slate-500">Enable Auto-Probe to automatically discover and watch services on this target.</p>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* CVE Findings from this project */}
      {cveFindings.length > 0 && (
        <div className="space-y-3 max-w-3xl">
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Eye size={14} className="text-amber-400" />
            CVE Findings ({cveFindings.length})
          </h2>
          <div className="glass rounded-xl divide-y divide-slate-800/40">
            {cveFindings.map(f => (
              <div key={f.id} className="px-4 py-3 flex items-start gap-3">
                <span className={`shrink-0 text-[10px] px-1.5 py-0.5 rounded border font-semibold uppercase ${SEV_BADGE[f.severity] || SEV_BADGE.info}`}>
                  {f.severity}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-white truncate">{f.title}</p>
                  {f.cve_id && (
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`}
                      target="_blank"
                      rel="noreferrer"
                      className="text-[10px] text-amber-400 font-mono hover:underline"
                    >
                      {f.cve_id}
                    </a>
                  )}
                </div>
                <span className="text-[10px] text-slate-500 shrink-0">
                  {new Date(f.created_at).toLocaleDateString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
