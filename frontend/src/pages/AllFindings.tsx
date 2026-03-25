import { useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { ArrowLeft, Search, ChevronDown, Download, Tag, X } from 'lucide-react'

interface FindingRow {
  id: string
  severity: string
  title: string
  description: string
  cve_id: string | null
  cvss_score: string | null
  status: string
  tags: string
  target: string
  project: string
  project_id: string | null
  created_at: string | null
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#22c55e',
  info:     '#3b82f6',
}

const SEV_BG: Record<string, string> = {
  critical: 'rgba(239,68,68,0.15)',
  high:     'rgba(249,115,22,0.15)',
  medium:   'rgba(245,158,11,0.15)',
  low:      'rgba(34,197,94,0.15)',
  info:     'rgba(59,130,246,0.15)',
}

const STATUS_OPTIONS = ['open', 'in-review', 'remediated', 'accepted'] as const
type FindingStatus = typeof STATUS_OPTIONS[number]

const STATUS_STYLES: Record<FindingStatus, string> = {
  'open':        'bg-red-500/15 text-red-400 border border-red-500/25',
  'in-review':   'bg-amber-500/15 text-amber-400 border border-amber-500/25',
  'remediated':  'bg-green-500/15 text-green-400 border border-green-500/25',
  'accepted':    'bg-slate-500/15 text-slate-400 border border-slate-500/25',
}

export default function AllFindings() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [findings, setFindings] = useState<FindingRow[]>([])
  const [loading, setLoading] = useState(true)
  const [sevFilter, setSevFilter] = useState(searchParams.get('severity') ?? 'all')
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') ?? 'all')
  const [tagFilter, setTagFilter] = useState(searchParams.get('tag') ?? '')
  const [search, setSearch] = useState(searchParams.get('q') ?? '')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [exportOpen, setExportOpen] = useState(false)
  const [statusDropdown, setStatusDropdown] = useState<string | null>(null)
  const [tagInput, setTagInput] = useState<Record<string, string>>({})
  const exportRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handler(e: MouseEvent) {
      if (exportRef.current && !exportRef.current.contains(e.target as Node)) setExportOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  // Close status dropdown when clicking outside
  useEffect(() => {
    function handler() { setStatusDropdown(null) }
    if (statusDropdown) document.addEventListener('click', handler)
    return () => document.removeEventListener('click', handler)
  }, [statusDropdown])

  function exportCSV() {
    const header = 'severity,status,title,target,project,cve_id,cvss_score,tags,created_at,description'
    const rows = filtered.map(f =>
      [f.severity, f.status, f.title, f.target, f.project, f.cve_id ?? '', f.cvss_score ?? '',
       f.tags ?? '', f.created_at ?? '', f.description ?? '']
        .map(v => `"${String(v).replace(/"/g, '""')}"`)
        .join(',')
    )
    const blob = new Blob([header + '\n' + rows.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'findings.csv'; a.click()
    URL.revokeObjectURL(url)
    setExportOpen(false)
  }

  function exportJSON() {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'findings.json'; a.click()
    URL.revokeObjectURL(url)
    setExportOpen(false)
  }

  function updateFilter(sev: string, q: string, stat: string, tag: string) {
    const params: Record<string, string> = {}
    if (sev !== 'all') params.severity = sev
    if (q) params.q = q
    if (stat !== 'all') params.status = stat
    if (tag) params.tag = tag
    setSearchParams(params, { replace: true })
  }

  useEffect(() => {
    fetch('/api/v1/findings')
      .then(r => r.json())
      .then(setFindings)
      .finally(() => setLoading(false))
  }, [])

  const filtered = findings.filter(f => {
    if (sevFilter !== 'all' && f.severity !== sevFilter) return false
    if (statusFilter !== 'all' && f.status !== statusFilter) return false
    if (tagFilter) {
      const tags = (f.tags ?? '').split(',').map(t => t.trim().toLowerCase()).filter(Boolean)
      if (!tags.includes(tagFilter.toLowerCase())) return false
    }
    if (search) {
      const q = search.toLowerCase()
      return (
        f.title.toLowerCase().includes(q) ||
        f.target.toLowerCase().includes(q) ||
        f.project.toLowerCase().includes(q) ||
        (f.cve_id?.toLowerCase().includes(q) ?? false)
      )
    }
    return true
  })

  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})

  const statusCounts = findings.reduce<Record<string, number>>((acc, f) => {
    const s = f.status || 'open'
    acc[s] = (acc[s] || 0) + 1
    return acc
  }, {})

  function changeStatus(id: string, newStatus: FindingStatus) {
    fetch(`/api/v1/findings/${id}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus }),
    }).then(() => {
      setFindings(prev => prev.map(f => f.id === id ? { ...f, status: newStatus } : f))
    })
    setStatusDropdown(null)
  }

  function addTag(id: string) {
    const raw = (tagInput[id] ?? '').trim()
    if (!raw) return
    const finding = findings.find(f => f.id === id)
    if (!finding) return
    const existing = (finding.tags ?? '').split(',').map(t => t.trim()).filter(Boolean)
    if (existing.includes(raw)) { setTagInput(p => ({ ...p, [id]: '' })); return }
    const newTags = [...existing, raw]
    fetch(`/api/v1/findings/${id}/tags`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tags: newTags }),
    }).then(() => {
      setFindings(prev => prev.map(f => f.id === id ? { ...f, tags: newTags.join(',') } : f))
      setTagInput(p => ({ ...p, [id]: '' }))
    })
  }

  function removeTag(id: string, tag: string) {
    const finding = findings.find(f => f.id === id)
    if (!finding) return
    const newTags = (finding.tags ?? '').split(',').map(t => t.trim()).filter(t => t && t !== tag)
    fetch(`/api/v1/findings/${id}/tags`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tags: newTags }),
    }).then(() => {
      setFindings(prev => prev.map(f => f.id === id ? { ...f, tags: newTags.join(',') } : f))
    })
  }

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center gap-3">
        <button onClick={() => navigate('/')} className="text-slate-400 hover:text-slate-200 transition-colors">
          <ArrowLeft size={18} />
        </button>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-white">All Findings</h1>
          <p className="text-slate-400 text-sm mt-0.5">{findings.length} findings across all projects</p>
        </div>
        {/* Export dropdown */}
        <div className="relative" ref={exportRef}>
          <button
            onClick={() => setExportOpen(o => !o)}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-300 border border-cyan-900/30 hover:border-cyan-500/40 hover:text-white transition-colors glass"
          >
            <Download size={13} />
            Export
            <ChevronDown size={11} className="text-slate-500" style={{ transform: exportOpen ? 'rotate(180deg)' : 'none' }} />
          </button>
          {exportOpen && (
            <div className="absolute right-0 mt-1 w-36 glass border border-cyan-900/30 rounded-lg shadow-xl z-10 overflow-hidden">
              <button onClick={exportCSV} className="w-full px-4 py-2.5 text-left text-xs text-slate-300 hover:bg-cyan-950/30 hover:text-white transition-colors">
                Download CSV
              </button>
              <button onClick={exportJSON} className="w-full px-4 py-2.5 text-left text-xs text-slate-300 hover:bg-cyan-950/30 hover:text-white transition-colors">
                Download JSON
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center gap-3 flex-wrap">
          {/* Search */}
          <div className="relative">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search title, target, CVE…"
              value={search}
              onChange={e => { setSearch(e.target.value); updateFilter(sevFilter, e.target.value, statusFilter, tagFilter) }}
              className="pl-8 pr-4 py-1.5 rounded-lg text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none w-64"
              style={{ background: '#090d14' }}
            />
          </div>

          {/* Tag filter */}
          <div className="relative">
            <Tag size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Filter by tag…"
              value={tagFilter}
              onChange={e => { setTagFilter(e.target.value); updateFilter(sevFilter, search, statusFilter, e.target.value) }}
              className="pl-8 pr-4 py-1.5 rounded-lg text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none w-40"
              style={{ background: '#090d14' }}
            />
          </div>

          <span className="text-xs text-slate-500">{filtered.length} shown</span>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {/* Severity chips */}
          <div className="flex gap-1 glass rounded-lg p-1">
            <button
              onClick={() => { setSevFilter('all'); updateFilter('all', search, statusFilter, tagFilter) }}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${sevFilter === 'all' ? 'bg-slate-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
            >
              All ({findings.length})
            </button>
            {SEV_ORDER.map(s => (
              counts[s] ? (
                <button
                  key={s}
                  onClick={() => { setSevFilter(s); updateFilter(s, search, statusFilter, tagFilter) }}
                  className={`px-3 py-1 rounded text-xs font-medium capitalize transition-colors ${sevFilter === s ? 'text-white' : 'text-slate-400 hover:text-slate-200'}`}
                  style={sevFilter === s ? { background: SEV_BG[s], color: SEV_COLOR[s] } : {}}
                >
                  {s} ({counts[s]})
                </button>
              ) : null
            ))}
          </div>

          {/* Status chips */}
          <div className="flex gap-1 glass rounded-lg p-1">
            <button
              onClick={() => { setStatusFilter('all'); updateFilter(sevFilter, search, 'all', tagFilter) }}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${statusFilter === 'all' ? 'bg-slate-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}
            >
              Any status
            </button>
            {STATUS_OPTIONS.map(s => (
              statusCounts[s] ? (
                <button
                  key={s}
                  onClick={() => { setStatusFilter(s); updateFilter(sevFilter, search, s, tagFilter) }}
                  className={`px-3 py-1 rounded text-xs font-medium capitalize transition-colors ${statusFilter === s ? STATUS_STYLES[s] : 'text-slate-400 hover:text-slate-200'}`}
                >
                  {s} ({statusCounts[s]})
                </button>
              ) : null
            ))}
          </div>
        </div>
      </div>

      {/* List */}
      <div className="glass rounded-xl overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-16 text-slate-500 text-sm">Loading…</div>
        ) : filtered.length === 0 ? (
          <div className="flex items-center justify-center py-16 text-slate-500 text-sm">No findings match the current filter.</div>
        ) : (
          <div className="divide-y divide-cyan-900/10">
            {filtered.map(f => {
              const fStatus = (f.status || 'open') as FindingStatus
              const fTags = (f.tags ?? '').split(',').map(t => t.trim()).filter(Boolean)
              return (
                <div key={f.id}>
                  <button
                    onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                    className="w-full flex items-center gap-3 px-5 py-3 hover:bg-cyan-950/10 transition-colors text-left"
                  >
                    <span
                      className="text-[9px] font-bold px-2 py-0.5 rounded uppercase shrink-0 w-16 text-center"
                      style={{ background: SEV_BG[f.severity] ?? 'rgba(100,116,139,0.15)', color: SEV_COLOR[f.severity] ?? '#94a3b8' }}
                    >
                      {f.severity}
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-slate-200 truncate">{f.title}</p>
                      <div className="flex items-center gap-3 mt-0.5">
                        <span className="text-[11px] text-slate-500 font-mono truncate">{f.target}</span>
                        <span className="text-[11px] text-slate-600 truncate">{f.project}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {f.cve_id && (
                        <span className="text-[10px] text-blue-400 font-mono">{f.cve_id}</span>
                      )}
                      {f.cvss_score && (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-slate-700/40 text-slate-400">
                          CVSS {f.cvss_score}
                        </span>
                      )}
                      {/* Status badge — inline dropdown */}
                      <div
                        className="relative"
                        onClick={e => { e.stopPropagation(); setStatusDropdown(statusDropdown === f.id ? null : f.id) }}
                      >
                        <span className={`text-[9px] font-medium px-2 py-0.5 rounded cursor-pointer ${STATUS_STYLES[fStatus]}`}>
                          {fStatus}
                        </span>
                        {statusDropdown === f.id && (
                          <div className="absolute right-0 top-6 w-28 glass border border-cyan-900/30 rounded-lg shadow-xl z-20 overflow-hidden">
                            {STATUS_OPTIONS.map(opt => (
                              <button
                                key={opt}
                                onClick={e => { e.stopPropagation(); changeStatus(f.id, opt) }}
                                className={`w-full px-3 py-2 text-left text-[10px] font-medium transition-colors hover:bg-cyan-950/30 ${opt === fStatus ? STATUS_STYLES[opt] : 'text-slate-400'}`}
                              >
                                {opt}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                      <ChevronDown
                        size={12}
                        className="text-slate-600 transition-transform duration-150"
                        style={{ transform: expanded === f.id ? 'rotate(180deg)' : 'none' }}
                      />
                    </div>
                  </button>
                  {expanded === f.id && (
                    <div className="px-5 pb-4 pt-1 ml-[76px] space-y-3">
                      <p className="text-xs text-slate-400 leading-relaxed">{f.description}</p>
                      {/* Tags */}
                      <div className="flex items-center gap-1.5 flex-wrap">
                        {fTags.map(tag => (
                          <span key={tag} className="flex items-center gap-1 text-[10px] bg-cyan-900/20 text-cyan-400 border border-cyan-900/30 rounded px-2 py-0.5">
                            {tag}
                            <button onClick={() => removeTag(f.id, tag)} className="text-cyan-600 hover:text-red-400 transition-colors">
                              <X size={9} />
                            </button>
                          </span>
                        ))}
                        <div className="flex items-center gap-1">
                          <Tag size={10} className="text-slate-600" />
                          <input
                            type="text"
                            placeholder="add tag…"
                            value={tagInput[f.id] ?? ''}
                            onChange={e => setTagInput(p => ({ ...p, [f.id]: e.target.value }))}
                            onKeyDown={e => { if (e.key === 'Enter') addTag(f.id) }}
                            className="bg-transparent text-[10px] text-slate-400 placeholder-slate-600 outline-none w-20 border-b border-slate-700/40 focus:border-cyan-500/40"
                          />
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
