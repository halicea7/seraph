import { useState, useEffect } from 'react'
import { ArrowRight, Plus, Minus } from 'lucide-react'

interface ScanInfo {
  id: string
  scan_type: string
  status: string
  started_at: string | null
  finding_count: number
}

interface DiffFinding {
  id: string
  severity: string
  title: string
  description?: string
  control_id?: string
  framework?: string
}

interface DiffResult {
  scan_a: { id: string; scan_type: string; started_at: string }
  scan_b: { id: string; scan_type: string; started_at: string }
  target: string
  summary: { new: number; resolved: number; unchanged: number }
  new_findings: DiffFinding[]
  resolved_findings: DiffFinding[]
  unchanged_findings: DiffFinding[]
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-amber-400',
  low: 'text-green-400',
  info: 'text-blue-400',
}

interface ScanDiffProps {
  targetId: string
}

export default function ScanDiff({ targetId }: ScanDiffProps) {
  const [scans, setScans] = useState<ScanInfo[]>([])
  const [scanA, setScanA] = useState('')
  const [scanB, setScanB] = useState('')
  const [diff, setDiff] = useState<DiffResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!targetId) return
    fetch(`/api/v1/diff/target/${targetId}/scans`)
      .then(r => r.json())
      .then(data => {
        setScans(data)
        if (data.length >= 2) {
          setScanA(data[1].id)  // older
          setScanB(data[0].id)  // newer
        }
      })
      .catch(() => {})
  }, [targetId])

  async function runDiff() {
    if (!scanA || !scanB || scanA === scanB) {
      setError('Select two different scans to compare')
      return
    }
    setLoading(true)
    setError('')
    try {
      const res = await fetch(`/api/v1/diff/scans/${scanA}/${scanB}`)
      if (!res.ok) throw new Error('Diff failed')
      setDiff(await res.json())
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  if (scans.length < 2) {
    return (
      <div className="text-center text-slate-500 py-8 text-sm">
        Run at least two scans on this target to compare results.
      </div>
    )
  }

  const selectClass = "bg-[#0f1419] border border-slate-700 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-blue-500"

  return (
    <div className="space-y-4">
      {/* Scan selectors */}
      <div className="flex items-center gap-3 flex-wrap">
        <select className={selectClass} value={scanA} onChange={e => setScanA(e.target.value)}>
          {scans.map(s => (
            <option key={s.id} value={s.id}>
              {s.scan_type} ({s.started_at?.slice(0, 10) || 'pending'}) — {s.finding_count} findings
            </option>
          ))}
        </select>
        <ArrowRight size={16} className="text-slate-500 flex-shrink-0" />
        <select className={selectClass} value={scanB} onChange={e => setScanB(e.target.value)}>
          {scans.map(s => (
            <option key={s.id} value={s.id}>
              {s.scan_type} ({s.started_at?.slice(0, 10) || 'pending'}) — {s.finding_count} findings
            </option>
          ))}
        </select>
        <button
          onClick={runDiff}
          disabled={loading}
          className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 text-sm text-white font-medium transition-colors"
        >
          {loading ? 'Comparing...' : 'Compare'}
        </button>
      </div>

      {error && (
        <div className="text-sm text-red-400 bg-red-900/20 rounded-lg px-4 py-2 border border-red-700/30">
          {error}
        </div>
      )}

      {diff && (
        <div className="space-y-4">
          {/* Summary */}
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-green-900/20 border border-green-700/30 rounded-xl p-4 text-center">
              <div className="text-2xl font-bold text-green-400">{diff.summary.new}</div>
              <div className="text-xs text-green-600 mt-1">New Findings</div>
            </div>
            <div className="bg-blue-900/20 border border-blue-700/30 rounded-xl p-4 text-center">
              <div className="text-2xl font-bold text-blue-400">{diff.summary.resolved}</div>
              <div className="text-xs text-blue-600 mt-1">Resolved</div>
            </div>
            <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-4 text-center">
              <div className="text-2xl font-bold text-slate-400">{diff.summary.unchanged}</div>
              <div className="text-xs text-slate-600 mt-1">Unchanged</div>
            </div>
          </div>

          {/* New findings */}
          {diff.new_findings.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold text-green-400 mb-2 flex items-center gap-2">
                <Plus size={14} /> New Findings ({diff.new_findings.length})
              </h4>
              <div className="space-y-1">
                {diff.new_findings.map(f => (
                  <div key={f.id} className="flex items-center gap-3 bg-green-900/10 border border-green-800/30 rounded-lg px-4 py-2">
                    <span className={`text-xs font-semibold uppercase ${SEVERITY_COLORS[f.severity] || 'text-slate-400'}`}>{f.severity}</span>
                    <span className="text-sm text-slate-300">{f.title}</span>
                    {f.control_id && <span className="text-xs text-slate-500 ml-auto font-mono">{f.control_id}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Resolved findings */}
          {diff.resolved_findings.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold text-blue-400 mb-2 flex items-center gap-2">
                <Minus size={14} /> Resolved ({diff.resolved_findings.length})
              </h4>
              <div className="space-y-1">
                {diff.resolved_findings.map(f => (
                  <div key={f.id} className="flex items-center gap-3 bg-blue-900/10 border border-blue-800/30 rounded-lg px-4 py-2 opacity-70">
                    <span className={`text-xs font-semibold uppercase ${SEVERITY_COLORS[f.severity] || 'text-slate-400'}`}>{f.severity}</span>
                    <span className="text-sm text-slate-400 line-through">{f.title}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
