import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import {
  ArrowLeft, Zap, Search, GitCompare, X, Plus, Minus, Equal,
  Terminal as TerminalIcon, Loader, Cpu,
} from 'lucide-react'

interface ScanRow {
  id: string
  scan_type: string
  status: string
  target: string
  target_id: string | null
  project: string
  project_id: string | null
  finding_count: number
  auto_probe: boolean
  started_at: string | null
  completed_at: string | null
  created_at: string | null
}

interface ScanDetail extends ScanRow {
  raw_output: string | null
  config_json: string | null
}

interface DiffFinding {
  id: string
  severity: string
  title: string
  description: string
  cve_id: string | null
  cvss_score: string | null
}

interface DiffResult {
  scan_a: string
  scan_b: string
  new: DiffFinding[]
  resolved: DiffFinding[]
  unchanged: DiffFinding[]
}

const STATUS_COLORS: Record<string, string> = {
  completed: '#22c55e',
  running:   '#3b82f6',
  pending:   '#64748b',
  failed:    '#ef4444',
}

const STATUS_STYLES: Record<string, string> = {
  completed: 'bg-green-500/15 text-green-400 border border-green-500/30',
  running:   'bg-blue-500/15 text-blue-400 border border-blue-500/30',
  pending:   'bg-slate-500/15 text-slate-400 border border-slate-500/20',
  failed:    'bg-red-500/15 text-red-400 border border-red-500/30',
}

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#22c55e', info: '#3b82f6',
}
const SEV_BG: Record<string, string> = {
  critical: 'rgba(239,68,68,0.15)', high: 'rgba(249,115,22,0.15)', medium: 'rgba(245,158,11,0.15)',
  low: 'rgba(34,197,94,0.15)', info: 'rgba(59,130,246,0.15)',
}

const STATUSES = ['all', 'completed', 'running', 'pending', 'failed']

export default function AllScans() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [scans, setScans] = useState<ScanRow[]>([])
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') ?? 'all')
  const [search, setSearch] = useState(searchParams.get('q') ?? '')
  const [selected, setSelected] = useState<string[]>([])
  const [diff, setDiff] = useState<DiffResult | null>(null)
  const [diffLoading, setDiffLoading] = useState(false)
  const [diffError, setDiffError] = useState('')

  // Log drawer
  const [drawerScan, setDrawerScan] = useState<ScanDetail | null>(null)
  const [drawerLoading, setDrawerLoading] = useState(false)
  const [parseLoading, setParseLoading] = useState(false)
  const [parseMsg, setParseMsg] = useState('')

  function updateFilter(status: string, q: string) {
    const params: Record<string, string> = {}
    if (status !== 'all') params.status = status
    if (q) params.q = q
    setSearchParams(params, { replace: true })
  }

  const openParam = searchParams.get('open')

  useEffect(() => {
    fetch('/api/v1/scans')
      .then(r => r.json())
      .then((data: ScanRow[]) => {
        setScans(data)
        // Auto-open drawer if ?open=<scan_id> was passed (e.g. from a notification)
        if (openParam) {
          const target = data.find(s => s.id === openParam)
          if (target) openDrawer(target)
          // Remove the param from the URL so back/refresh doesn't re-open
          setSearchParams(prev => { prev.delete('open'); return prev }, { replace: true })
        }
      })
      .finally(() => setLoading(false))
  }, [])  // eslint-disable-line react-hooks/exhaustive-deps

  const filtered = scans.filter(s => {
    if (statusFilter !== 'all' && s.status !== statusFilter) return false
    if (search) {
      const q = search.toLowerCase()
      return s.target.toLowerCase().includes(q) || s.project.toLowerCase().includes(q) || s.scan_type.toLowerCase().includes(q)
    }
    return true
  })

  function toggleSelect(e: React.MouseEvent, id: string) {
    e.stopPropagation()
    setSelected(prev => {
      if (prev.includes(id)) return prev.filter(x => x !== id)
      if (prev.length >= 2) return [prev[1], id]
      return [...prev, id]
    })
    setDiff(null)
    setDiffError('')
  }

  function parseFindings(scanId: string) {
    setParseLoading(true)
    setParseMsg('')
    fetch(`/api/v1/audit/scans/${scanId}/parse`, { method: 'POST' })
      .then(r => r.json())
      .then(d => setParseMsg(`${d.parsed ?? 0} findings parsed`))
      .catch(() => setParseMsg('Parse failed'))
      .finally(() => setParseLoading(false))
  }

  function openDrawer(scan: ScanRow) {
    setParseMsg('')
    setDrawerLoading(true)
    setDrawerScan({ ...scan, raw_output: null, config_json: null })
    fetch(`/api/v1/audit/scans/${scan.id}`)
      .then(r => r.json())
      .then(data => setDrawerScan({ ...scan, raw_output: data.raw_output ?? null, config_json: data.config_json ?? null }))
      .catch(() => setDrawerScan(prev => prev ? { ...prev, raw_output: 'Failed to load output.' } : null))
      .finally(() => setDrawerLoading(false))
  }

  function runDiff() {
    if (selected.length !== 2) return
    setDiffLoading(true)
    setDiffError('')
    fetch(`/api/v1/scans/diff?a=${selected[0]}&b=${selected[1]}`)
      .then(r => r.ok ? r.json() : r.json().then((e: {detail: string}) => Promise.reject(e.detail)))
      .then(setDiff)
      .catch(e => setDiffError(String(e)))
      .finally(() => setDiffLoading(false))
  }

  const scanName = (id: string) => {
    const s = scans.find(x => x.id === id)
    return s ? `${s.scan_type} @ ${s.target}` : id.slice(0, 8)
  }

  return (
    <div className="flex h-full">
      {/* Main content */}
      <div className={`flex-1 p-8 space-y-6 overflow-y-auto transition-all ${drawerScan ? 'mr-[480px]' : ''}`}>
        <div className="flex items-center gap-3">
          <button onClick={() => navigate('/')} className="text-slate-400 hover:text-slate-200 transition-colors">
            <ArrowLeft size={18} />
          </button>
          <div className="flex-1">
            <h1 className="text-2xl font-bold text-white">All Scans</h1>
            <p className="text-slate-400 text-sm mt-0.5">{scans.length} total scans across all projects</p>
          </div>
          {/* Diff controls */}
          {selected.length > 0 && (
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">{selected.length}/2 selected</span>
              {selected.length === 2 && (
                <button
                  onClick={runDiff}
                  disabled={diffLoading}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-cyan-600/20 text-cyan-300 border border-cyan-600/30 hover:bg-cyan-600/30 transition-colors disabled:opacity-50"
                >
                  <GitCompare size={13} />
                  {diffLoading ? 'Comparing…' : 'Diff Scans'}
                </button>
              )}
              <button onClick={() => { setSelected([]); setDiff(null) }} className="text-slate-500 hover:text-slate-300 transition-colors">
                <X size={15} />
              </button>
            </div>
          )}
        </div>

        {/* Selection hint */}
        {selected.length === 0 && (
          <p className="text-xs text-slate-600 -mt-3">
            Click a row to view its output · check the box on two rows to <strong className="text-slate-500">Diff Scans</strong>
          </p>
        )}

        {/* Diff result panel */}
        {diff && (
          <div className="glass rounded-xl border border-cyan-900/20 overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3 border-b border-cyan-900/15">
              <div className="flex items-center gap-2">
                <GitCompare size={14} className="text-cyan-400" />
                <span className="text-xs font-semibold text-white uppercase tracking-wider">Scan Diff</span>
              </div>
              <div className="flex items-center gap-4 text-[11px]">
                <span className="text-slate-500 font-mono">{scanName(diff.scan_a)}</span>
                <span className="text-slate-600">→</span>
                <span className="text-slate-500 font-mono">{scanName(diff.scan_b)}</span>
              </div>
              <button onClick={() => setDiff(null)} className="text-slate-500 hover:text-slate-300 transition-colors">
                <X size={14} />
              </button>
            </div>

            <div className="grid grid-cols-3 divide-x divide-cyan-900/15">
              <DiffBucket label="New" icon={<Plus size={12} />} color="text-red-400" findings={diff.new} />
              <DiffBucket label="Resolved" icon={<Minus size={12} />} color="text-green-400" findings={diff.resolved} />
              <DiffBucket label="Unchanged" icon={<Equal size={12} />} color="text-slate-500" findings={diff.unchanged} />
            </div>
          </div>
        )}

        {diffError && (
          <div className="px-4 py-2 rounded-lg bg-red-900/20 border border-red-700/30 text-xs text-red-400">{diffError}</div>
        )}

        {/* Filters */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search target, project, type…"
              value={search}
              onChange={e => { setSearch(e.target.value); updateFilter(statusFilter, e.target.value) }}
              className="pl-8 pr-4 py-1.5 rounded-lg text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none w-64"
              style={{ background: '#090d14' }}
            />
          </div>
          <div className="flex gap-1 glass rounded-lg p-1">
            {STATUSES.map(s => (
              <button
                key={s}
                onClick={() => { setStatusFilter(s); updateFilter(s, search) }}
                className={`px-3 py-1 rounded text-xs font-medium capitalize transition-colors ${
                  statusFilter === s ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
          <span className="text-xs text-slate-500">{filtered.length} shown</span>
        </div>

        {/* Table */}
        <div className="glass rounded-xl overflow-hidden">
          {loading ? (
            <div className="flex items-center justify-center py-16 text-slate-500 text-sm">Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="flex items-center justify-center py-16 text-slate-500 text-sm">No scans match the current filter.</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-cyan-900/20 text-left">
                  <th className="px-3 py-3 w-8" />
                  <th className="px-5 py-3 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Type</th>
                  <th className="px-5 py-3 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Target</th>
                  <th className="px-5 py-3 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Project</th>
                  <th className="px-5 py-3 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Status</th>
                  <th className="px-5 py-3 text-[11px] font-semibold text-slate-400 uppercase tracking-wider text-right">Findings</th>
                  <th className="px-5 py-3 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyan-900/10">
                {filtered.map(s => {
                  const isSelected = selected.includes(s.id)
                  const selIdx = selected.indexOf(s.id)
                  const isOpen = drawerScan?.id === s.id
                  return (
                    <tr
                      key={s.id}
                      onClick={() => openDrawer(s)}
                      className={`transition-colors cursor-pointer ${isOpen ? 'bg-cyan-950/25' : isSelected ? 'bg-cyan-950/20' : 'hover:bg-cyan-950/10'}`}
                    >
                      <td className="px-3 py-3" onClick={e => toggleSelect(e, s.id)}>
                        <div className={`w-5 h-5 rounded border flex items-center justify-center text-[10px] font-bold transition-colors cursor-pointer hover:border-cyan-600 ${
                          isSelected ? 'border-cyan-500 bg-cyan-500/20 text-cyan-300' : 'border-slate-700 text-transparent'
                        }`}>
                          {isSelected ? selIdx + 1 : ''}
                        </div>
                      </td>
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-1 h-5 rounded-full shrink-0" style={{ backgroundColor: STATUS_COLORS[s.status] || STATUS_COLORS.pending }} />
                          <span className="font-mono text-xs text-slate-300">{s.scan_type}</span>
                          {s.auto_probe && <Zap size={11} className="text-green-400 shrink-0" />}
                        </div>
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-slate-300">{s.target}</td>
                      <td className="px-5 py-3 text-xs text-slate-400">{s.project}</td>
                      <td className="px-5 py-3">
                        <span className={`text-[10px] px-2 py-0.5 rounded font-medium ${STATUS_STYLES[s.status] || STATUS_STYLES.pending}`}>
                          {s.status}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-right">
                        {s.finding_count > 0 ? (
                          <span className="text-xs font-mono text-amber-400">{s.finding_count}</span>
                        ) : (
                          <span className="text-xs text-slate-600">—</span>
                        )}
                      </td>
                      <td className="px-5 py-3 text-xs text-slate-500 font-mono">
                        {s.started_at ? new Date(s.started_at).toLocaleDateString() : '—'}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Log drawer */}
      {drawerScan && (
        <div className="fixed top-0 right-0 h-full w-[480px] flex flex-col border-l border-cyan-900/30 z-30" style={{ background: '#070d17' }}>
          {/* Drawer header */}
          <div className="flex items-start gap-3 px-5 py-4 border-b border-cyan-900/20 shrink-0">
            <TerminalIcon size={16} className="text-cyan-400 mt-0.5 shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-sm font-semibold text-cyan-300">{drawerScan.scan_type}</span>
                <span className={`text-[10px] px-2 py-0.5 rounded font-medium ${STATUS_STYLES[drawerScan.status] || STATUS_STYLES.pending}`}>
                  {drawerScan.status}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5 truncate">{drawerScan.target} · {drawerScan.project}</p>
              {drawerScan.started_at && (
                <p className="text-[11px] text-slate-600 mt-0.5 font-mono">
                  {new Date(drawerScan.started_at).toLocaleString()}
                  {drawerScan.completed_at && ` → ${new Date(drawerScan.completed_at).toLocaleString()}`}
                </p>
              )}
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {drawerScan.raw_output !== null && (
                <button
                  onClick={() => parseFindings(drawerScan.id)}
                  disabled={parseLoading}
                  title="Re-parse output into findings"
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs bg-cyan-600/15 text-cyan-400 border border-cyan-600/25 hover:bg-cyan-600/25 transition-colors disabled:opacity-50"
                >
                  {parseLoading ? <Loader size={11} className="animate-spin" /> : <Cpu size={11} />}
                  {parseLoading ? 'Parsing…' : 'Parse Findings'}
                </button>
              )}
              {parseMsg && <span className="text-xs text-green-400">{parseMsg}</span>}
              <button onClick={() => setDrawerScan(null)} className="text-slate-500 hover:text-slate-200 transition-colors">
                <X size={16} />
              </button>
            </div>
          </div>

          {/* Output */}
          <div className="flex-1 overflow-y-auto px-5 py-4">
            {drawerLoading ? (
              <div className="flex items-center gap-2 text-slate-500 text-sm">
                <Loader size={14} className="animate-spin" />
                Loading output…
              </div>
            ) : drawerScan.raw_output ? (
              <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed">{drawerScan.raw_output}</pre>
            ) : (
              <div className="flex flex-col items-center justify-center h-full gap-3 text-slate-600">
                <TerminalIcon size={32} />
                <p className="text-sm">No output recorded for this scan.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function DiffBucket({ label, icon, color, findings }: {
  label: string
  icon: React.ReactNode
  color: string
  findings: DiffFinding[]
}) {
  return (
    <div className="p-4">
      <div className={`flex items-center gap-1.5 mb-3 ${color}`}>
        {icon}
        <span className="text-[11px] font-bold uppercase tracking-wider">{label}</span>
        <span className="ml-auto text-[11px] font-mono">{findings.length}</span>
      </div>
      {findings.length === 0 ? (
        <p className="text-[11px] text-slate-600 text-center py-4">None</p>
      ) : (
        <div className="space-y-1.5 overflow-y-auto" style={{ maxHeight: '240px' }}>
          {findings.map(f => (
            <div key={f.id} className="flex items-start gap-2">
              <span
                className="text-[9px] font-bold px-1.5 py-0.5 rounded uppercase shrink-0 mt-0.5"
                style={{ background: SEV_BG[f.severity] ?? 'rgba(100,116,139,0.15)', color: SEV_COLOR[f.severity] ?? '#94a3b8' }}
              >
                {f.severity}
              </span>
              <p className="text-[11px] text-slate-300 leading-snug">{f.title}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
