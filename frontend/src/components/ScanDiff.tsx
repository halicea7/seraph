import { useState, useEffect } from 'react'
import { ArrowRight, Plus, Minus } from 'lucide-react'
import { getApiBase } from '@/lib/config'

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
  critical: 'var(--crit)',
  high:     'var(--high)',
  medium:   'var(--accent)',
  low:      'var(--ok)',
  info:     'var(--med)',
}

const ruleStrong = '1px solid var(--rule-strong)'

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
    fetch(`${getApiBase()}/diff/target/${targetId}/scans`)
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
      const res = await fetch(`${getApiBase()}/diff/scans/${scanA}/${scanB}`)
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
      <div style={{ textAlign: 'center', color: 'var(--fg-3)', padding: '32px 0', fontSize: 13 }}>
        Run at least two scans on this target to compare results.
      </div>
    )
  }

  const selectStyle: React.CSSProperties = {
    background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4,
    padding: '6px 10px', fontSize: 13, color: 'var(--fg)',
    outline: 'none', fontFamily: 'var(--font-sans)',
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Scan selectors */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <select style={selectStyle} value={scanA} onChange={e => setScanA(e.target.value)}>
          {scans.map(s => (
            <option key={s.id} value={s.id}>
              {s.scan_type} ({s.started_at?.slice(0, 10) || 'pending'}) — {s.finding_count} findings
            </option>
          ))}
        </select>
        <ArrowRight size={16} style={{ color: 'var(--fg-3)', flexShrink: 0 }} />
        <select style={selectStyle} value={scanB} onChange={e => setScanB(e.target.value)}>
          {scans.map(s => (
            <option key={s.id} value={s.id}>
              {s.scan_type} ({s.started_at?.slice(0, 10) || 'pending'}) — {s.finding_count} findings
            </option>
          ))}
        </select>
        <button
          onClick={runDiff}
          disabled={loading}
          style={{
            padding: '6px 14px', borderRadius: 4, fontSize: 13, fontWeight: 600,
            background: loading ? 'var(--bg-2)' : 'rgba(240,168,58,0.12)',
            border: '1px solid rgba(240,168,58,0.35)',
            color: loading ? 'var(--fg-3)' : 'var(--accent)',
            cursor: loading ? 'not-allowed' : 'pointer',
            fontFamily: 'var(--font-sans)',
          }}
        >
          {loading ? 'Comparing...' : 'Compare'}
        </button>
      </div>

      {error && (
        <div style={{ fontSize: 13, color: 'var(--crit)', background: 'rgba(232,64,64,0.08)', borderRadius: 4, padding: '8px 14px', border: '1px solid rgba(232,64,64,0.3)' }}>
          {error}
        </div>
      )}

      {diff && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Summary */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
            <div style={{ background: 'rgba(84,175,97,0.08)', border: '1px solid rgba(84,175,97,0.3)', borderRadius: 8, padding: 16, textAlign: 'center' }}>
              <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--ok)' }}>{diff.summary.new}</div>
              <div style={{ fontSize: 11, color: 'var(--ok)', opacity: 0.7, marginTop: 4 }}>New Findings</div>
            </div>
            <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 8, padding: 16, textAlign: 'center' }}>
              <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--fg-2)' }}>{diff.summary.resolved}</div>
              <div style={{ fontSize: 11, color: 'var(--fg-3)', marginTop: 4 }}>Resolved</div>
            </div>
            <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 8, padding: 16, textAlign: 'center' }}>
              <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--fg-3)' }}>{diff.summary.unchanged}</div>
              <div style={{ fontSize: 11, color: 'var(--fg-4)', marginTop: 4 }}>Unchanged</div>
            </div>
          </div>

          {/* New findings */}
          {diff.new_findings.length > 0 && (
            <div>
              <h4 style={{ margin: '0 0 8px', fontSize: 13, fontWeight: 600, color: 'var(--ok)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Plus size={14} /> New Findings ({diff.new_findings.length})
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {diff.new_findings.map(f => (
                  <div key={f.id} style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'rgba(84,175,97,0.06)', border: '1px solid rgba(84,175,97,0.2)', borderRadius: 4, padding: '6px 12px' }}>
                    <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: SEVERITY_COLORS[f.severity] ?? 'var(--fg-3)', flexShrink: 0 }}>{f.severity}</span>
                    <span style={{ fontSize: 13, color: 'var(--fg-2)' }}>{f.title}</span>
                    {f.control_id && <span style={{ fontSize: 11, color: 'var(--fg-3)', marginLeft: 'auto', fontFamily: 'var(--font-mono)' }}>{f.control_id}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Resolved findings */}
          {diff.resolved_findings.length > 0 && (
            <div>
              <h4 style={{ margin: '0 0 8px', fontSize: 13, fontWeight: 600, color: 'var(--fg-2)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Minus size={14} /> Resolved ({diff.resolved_findings.length})
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {diff.resolved_findings.map(f => (
                  <div key={f.id} style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, padding: '6px 12px', opacity: 0.7 }}>
                    <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: SEVERITY_COLORS[f.severity] ?? 'var(--fg-3)', flexShrink: 0 }}>{f.severity}</span>
                    <span style={{ fontSize: 13, color: 'var(--fg-3)', textDecoration: 'line-through' }}>{f.title}</span>
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
