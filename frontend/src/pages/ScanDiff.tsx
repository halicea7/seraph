import { useState, useEffect } from 'react'
import { useAppStore } from '@/stores/appStore'
import { getApiBase } from '@/lib/config'
import Icon from '@/components/Icon'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Target {
  id: string
  hostname_or_ip: string
  target_type: string
}

interface ScanOption {
  id: string
  scan_type: string
  started_at: string | null
  finding_count: number
}

interface DiffFinding {
  id: string
  severity: string
  title: string
  description: string
  remediation: string | null
  framework: string | null
  control_id: string | null
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

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--crit)',
  high:     '#e07b39',
  medium:   '#d4a017',
  low:      'var(--accent)',
  info:     'var(--fg-3)',
}

function SeverityBadge({ sev }: { sev: string }) {
  return (
    <span className="mono" style={{
      fontSize: 9, fontWeight: 700, letterSpacing: '0.12em',
      textTransform: 'uppercase', color: SEV_COLOR[sev] ?? 'var(--fg-3)',
      border: `1px solid ${SEV_COLOR[sev] ?? 'var(--rule)'}`,
      padding: '1px 5px', borderRadius: 2, flexShrink: 0,
    }}>{sev}</span>
  )
}

function FindingRow({ f, expanded, onToggle }: { f: DiffFinding; expanded: boolean; onToggle: () => void }) {
  return (
    <div
      onClick={onToggle}
      style={{
        padding: '9px 14px', borderBottom: '1px solid var(--rule)',
        cursor: 'pointer', transition: 'background .1s',
        background: expanded ? 'var(--bg-2)' : 'transparent',
      }}
      onMouseEnter={e => { if (!expanded) (e.currentTarget as HTMLDivElement).style.background = 'var(--bg-2)' }}
      onMouseLeave={e => { if (!expanded) (e.currentTarget as HTMLDivElement).style.background = 'transparent' }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <SeverityBadge sev={f.severity} />
        <span style={{ flex: 1, fontSize: 13, color: 'var(--fg)' }}>{f.title}</span>
        <Icon name={expanded ? 'chev_u' : 'chev_d'} size={11} color="var(--fg-3)" />
      </div>
      {expanded && (
        <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid var(--rule)' }}>
          {f.description && (
            <p style={{ fontSize: 12, color: 'var(--fg-2)', margin: '0 0 8px', lineHeight: 1.6 }}>{f.description}</p>
          )}
          {f.remediation && (
            <div style={{ fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', background: 'var(--bg)', padding: '6px 10px', borderRadius: 3 }}>
              <span style={{ color: 'var(--accent)', marginRight: 6 }}>FIX</span>{f.remediation}
            </div>
          )}
          {(f.framework || f.control_id) && (
            <div style={{ marginTop: 6, display: 'flex', gap: 8 }}>
              {f.framework  && <span className="mono" style={{ fontSize: 10, color: 'var(--fg-4)', background: 'var(--bg)', padding: '2px 6px', borderRadius: 2 }}>{f.framework}</span>}
              {f.control_id && <span className="mono" style={{ fontSize: 10, color: 'var(--fg-4)', background: 'var(--bg)', padding: '2px 6px', borderRadius: 2 }}>{f.control_id}</span>}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function FindingSection({
  label, findings, accentColor, icon, defaultOpen = false,
}: {
  label: string; findings: DiffFinding[]; accentColor: string; icon: string; defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)
  const [expanded, setExpanded] = useState<string | null>(null)

  if (findings.length === 0) return null

  return (
    <div style={{ marginBottom: 12, border: '1px solid var(--rule)', borderLeft: `3px solid ${accentColor}`, borderRadius: 3 }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 10,
          padding: '10px 14px', background: 'var(--bg-2)', border: 'none',
          cursor: 'pointer', textAlign: 'left',
        }}
      >
        <Icon name={icon} size={13} color={accentColor} />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: accentColor }}>{label}</span>
        <span style={{ marginLeft: 6, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg-3)', background: 'var(--bg)', padding: '1px 7px', borderRadius: 10 }}>{findings.length}</span>
        <Icon name={open ? 'chev_u' : 'chev_d'} size={11} color="var(--fg-3)" style={{ marginLeft: 'auto' }} />
      </button>
      {open && findings.map(f => (
        <FindingRow
          key={f.id} f={f}
          expanded={expanded === f.id}
          onToggle={() => setExpanded(p => p === f.id ? null : f.id)}
        />
      ))}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ScanDiff() {
  const { selectedProject } = useAppStore()
  const api = getApiBase()

  const [targets,   setTargets]   = useState<Target[]>([])
  const [targetId,  setTargetId]  = useState('')
  const [scans,     setScans]     = useState<ScanOption[]>([])
  const [scanA,     setScanA]     = useState('')
  const [scanB,     setScanB]     = useState('')
  const [result,    setResult]    = useState<DiffResult | null>(null)
  const [loading,   setLoading]   = useState(false)
  const [error,     setError]     = useState('')

  // Load targets for current project
  useEffect(() => {
    if (!selectedProject) return
    fetch(`${api}/projects/${selectedProject.id}/targets`)
      .then(r => r.json())
      .then(setTargets)
      .catch(() => {})
  }, [selectedProject])

  // Load scans when target changes
  useEffect(() => {
    if (!targetId) { setScans([]); setScanA(''); setScanB(''); setResult(null); return }
    fetch(`${api}/diff/target/${targetId}/scans`)
      .then(r => r.json())
      .then((data: ScanOption[]) => {
        setScans(data)
        setScanA(data[1]?.id ?? '')
        setScanB(data[0]?.id ?? '')
        setResult(null)
      })
      .catch(() => {})
  }, [targetId])

  async function compare() {
    if (!scanA || !scanB || scanA === scanB) { setError('Select two different scans.'); return }
    setError('')
    setLoading(true)
    try {
      const r = await fetch(`${api}/diff/scans/${scanA}/${scanB}`)
      if (!r.ok) throw new Error('API error')
      setResult(await r.json())
    } catch {
      setError('Failed to load diff.')
    } finally {
      setLoading(false)
    }
  }

  function scanLabel(s: ScanOption) {
    const date = s.started_at ? new Date(s.started_at).toLocaleDateString() : 'unknown date'
    return `${s.scan_type} — ${date} (${s.finding_count} findings)`
  }

  const sel: React.CSSProperties = {
    background: 'var(--bg-2)', border: '1px solid var(--rule)',
    color: 'var(--fg)', fontFamily: 'var(--font-mono)', fontSize: 12,
    padding: '6px 10px', borderRadius: 3, width: '100%',
  }

  return (
    <div style={{ padding: '24px 28px', maxWidth: 900, margin: '0 auto' }}>

      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)', marginBottom: 4 }}>Tools</div>
        <h1 className="sec-h" style={{ margin: 0 }}>Scan Diff</h1>
        <p style={{ fontSize: 12, color: 'var(--fg-3)', marginTop: 4 }}>
          Compare two scans on the same target to track new, resolved, and unchanged findings.
        </p>
      </div>

      <div style={{ height: 1, background: 'var(--rule)', marginBottom: 24 }} />

      {/* Selectors */}
      {!selectedProject ? (
        <div style={{ fontSize: 13, color: 'var(--fg-3)' }}>Select a project to begin.</div>
      ) : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: 12, marginBottom: 20, alignItems: 'end' }}>
            <div>
              <label style={{ display: 'block', fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Target</label>
              <select style={sel} value={targetId} onChange={e => setTargetId(e.target.value)}>
                <option value="">— select target —</option>
                {targets.map(t => (
                  <option key={t.id} value={t.id}>{t.hostname_or_ip}</option>
                ))}
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Baseline (A)</label>
              <select style={sel} value={scanA} onChange={e => setScanA(e.target.value)} disabled={scans.length === 0}>
                <option value="">— select scan —</option>
                {scans.map(s => <option key={s.id} value={s.id}>{scanLabel(s)}</option>)}
              </select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Current (B)</label>
              <select style={sel} value={scanB} onChange={e => setScanB(e.target.value)} disabled={scans.length === 0}>
                <option value="">— select scan —</option>
                {scans.map(s => <option key={s.id} value={s.id}>{scanLabel(s)}</option>)}
              </select>
            </div>

            <button
              className="btn btn-primary"
              onClick={compare}
              disabled={loading || !scanA || !scanB}
              style={{ height: 34, padding: '0 18px', fontSize: 12 }}
            >
              {loading ? 'Comparing…' : 'Compare'}
            </button>
          </div>

          {error && <div style={{ fontSize: 12, color: 'var(--crit)', marginBottom: 16 }}>{error}</div>}

          {scans.length === 1 && targetId && (
            <div style={{ fontSize: 12, color: 'var(--fg-3)', marginBottom: 16 }}>
              Only one completed scan found for this target. Run a second scan to enable diffing.
            </div>
          )}
        </>
      )}

      {/* Results */}
      {result && (
        <>
          {/* Summary bar */}
          <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
            {[
              { label: 'New',       count: result.summary.new,       color: 'var(--crit)' },
              { label: 'Resolved',  count: result.summary.resolved,  color: '#4caf6e' },
              { label: 'Unchanged', count: result.summary.unchanged, color: 'var(--fg-3)' },
            ].map(({ label, count, color }) => (
              <div key={label} style={{ flex: 1, background: 'var(--bg-2)', border: '1px solid var(--rule)', borderTop: `3px solid ${color}`, padding: '12px 16px', borderRadius: 3 }}>
                <div style={{ fontSize: 22, fontWeight: 700, color, fontFamily: 'var(--font-mono)' }}>{count}</div>
                <div className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)', marginTop: 2 }}>{label}</div>
              </div>
            ))}
          </div>

          <div style={{ fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', marginBottom: 16 }}>
            {result.target} — comparing scans {result.scan_a.started_at?.slice(0, 10)} → {result.scan_b.started_at?.slice(0, 10)}
          </div>

          <FindingSection label="New"       findings={result.new_findings}       accentColor="var(--crit)" icon="plus"  defaultOpen />
          <FindingSection label="Resolved"  findings={result.resolved_findings}  accentColor="#4caf6e"     icon="check" defaultOpen />
          <FindingSection label="Unchanged" findings={result.unchanged_findings} accentColor="var(--fg-3)" icon="minus" />

          {result.summary.new === 0 && result.summary.resolved === 0 && (
            <div style={{ fontSize: 13, color: 'var(--fg-3)', padding: '20px 0' }}>No changes between these two scans.</div>
          )}
        </>
      )}
    </div>
  )
}
