import { useState, useEffect } from 'react'
import { useAppStore } from '@/stores/appStore'
import { getApiBase } from '@/lib/config'
import Icon from '@/components/Icon'
import EmptyState from '@/components/EmptyState'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Technique {
  technique_id: string
  name: string
  tactic: string
  score: number
  sources: string[]
}

interface TacticGroup {
  tactic: string
  techniques: Technique[]
}

interface Coverage {
  project_id: string
  total_touched: number
  max_score: number
  tactics: TacticGroup[]
  techniques: Technique[]
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Interpolate amber → red by relative score so hotter techniques stand out.
function heatColor(score: number, max: number): string {
  if (max <= 0) return 'var(--bg-3)'
  const t = Math.min(1, score / max)
  // amber (240,168,58) → crit red (232,92,78)
  const r = Math.round(240 + (232 - 240) * t)
  const g = Math.round(168 + (92 - 168) * t)
  const b = Math.round(58 + (78 - 58) * t)
  const alpha = 0.25 + 0.6 * t
  return `rgba(${r},${g},${b},${alpha})`
}

function prettyTactic(slug: string): string {
  return slug.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AttackNavigator() {
  const { selectedProject } = useAppStore()
  const api = getApiBase()

  const [data, setData] = useState<Coverage | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [active, setActive] = useState<Technique | null>(null)

  function load() {
    if (!selectedProject) return
    setLoading(true)
    setError('')
    fetch(`${api}/ai/attack/coverage?project_id=${selectedProject.id}`)
      .then(r => { if (!r.ok) throw new Error('API error'); return r.json() })
      .then((d: Coverage) => setData(d))
      .catch(() => setError('Failed to load coverage. Is the ATT&CK index synced (Settings)?'))
      .finally(() => setLoading(false))
  }

  useEffect(() => { setData(null); setActive(null); load() }, [selectedProject])

  async function exportLayer() {
    if (!selectedProject) return
    try {
      const r = await fetch(
        `${api}/ai/attack/coverage/export?project_id=${selectedProject.id}` +
        `&name=${encodeURIComponent('Seraph — ' + selectedProject.name)}`,
      )
      if (!r.ok) throw new Error('API error')
      const layer = await r.json()
      const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `seraph-attack-layer-${selectedProject.id.slice(0, 8)}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      setError('Failed to export Navigator layer.')
    }
  }

  return (
    <div style={{ padding: '24px 28px', maxWidth: 1100, margin: '0 auto', width: '100%' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 24, gap: 16 }}>
        <div>
          <div className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)', marginBottom: 4 }}>Offense</div>
          <h1 className="sec-h" style={{ margin: 0 }}>ATT&amp;CK Navigator</h1>
          <p style={{ fontSize: 12, color: 'var(--fg-3)', marginTop: 4 }}>
            Technique-coverage heatmap from this engagement&apos;s findings and playbook runs.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
          <button className="btn" onClick={load} disabled={loading || !selectedProject} style={{ height: 32, padding: '0 14px', fontSize: 12 }}>
            <Icon name="history" size={12} style={{ marginRight: 6 }} />{loading ? 'Loading…' : 'Refresh'}
          </button>
          <button className="btn btn-primary" onClick={exportLayer} disabled={!data || data.total_touched === 0} style={{ height: 32, padding: '0 14px', fontSize: 12 }}>
            <Icon name="file" size={12} style={{ marginRight: 6 }} />Export layer
          </button>
        </div>
      </div>

      <div style={{ height: 1, background: 'var(--rule)', marginBottom: 24 }} />

      {!selectedProject ? (
        <EmptyState icon="grid" title="No project selected" hint="Pick an engagement to view its ATT&CK coverage." />
      ) : error ? (
        <div style={{ fontSize: 12, color: 'var(--crit)' }}>{error}</div>
      ) : !data ? (
        <div style={{ fontSize: 13, color: 'var(--fg-3)' }}>Loading coverage…</div>
      ) : data.total_touched === 0 ? (
        <EmptyState
          icon="activity"
          title="No techniques covered yet"
          hint="Tag findings with ATT&CK technique IDs (e.g. T1003) or run playbooks with MITRE techniques to populate this heatmap."
        />
      ) : (
        <>
          {/* Summary */}
          <div style={{ display: 'flex', gap: 16, marginBottom: 20, fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--fg-2)' }}>
            <span><span style={{ color: 'var(--accent)', fontWeight: 700 }}>{data.total_touched}</span> techniques touched</span>
            <span><span style={{ color: 'var(--accent)', fontWeight: 700 }}>{data.tactics.length}</span> tactics</span>
            <span>peak score <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{data.max_score}</span></span>
          </div>

          {/* Matrix: tactic columns */}
          <div style={{ display: 'flex', gap: 10, overflowX: 'auto', paddingBottom: 8, alignItems: 'flex-start' }}>
            {data.tactics.map(group => (
              <div key={group.tactic} style={{ flex: '0 0 180px', minWidth: 180 }}>
                <div className="smcap" style={{
                  fontSize: 10, color: 'var(--fg-2)', padding: '6px 8px',
                  background: 'var(--bg-2)', border: '1px solid var(--rule)',
                  borderRadius: 3, marginBottom: 6, display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                }}>
                  <span>{prettyTactic(group.tactic)}</span>
                  <span style={{ color: 'var(--fg-4)' }}>{group.techniques.length}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {group.techniques.map(t => (
                    <button
                      key={group.tactic + t.technique_id}
                      onClick={() => setActive(t)}
                      title={`${t.technique_id} · score ${t.score}`}
                      style={{
                        textAlign: 'left', cursor: 'pointer',
                        background: heatColor(t.score, data.max_score),
                        border: active?.technique_id === t.technique_id ? '1px solid var(--accent)' : '1px solid var(--rule)',
                        borderRadius: 3, padding: '6px 8px', color: 'var(--fg)',
                      }}
                    >
                      <div className="mono" style={{ fontSize: 10, fontWeight: 700, display: 'flex', justifyContent: 'space-between' }}>
                        <span>{t.technique_id}</span>
                        <span>×{t.score}</span>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--fg)', marginTop: 2, lineHeight: 1.3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {t.name || '—'}
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Detail panel */}
          {active && (
            <div style={{ marginTop: 20, border: '1px solid var(--rule)', borderLeft: '3px solid var(--accent)', borderRadius: 3, padding: '14px 16px', background: 'var(--bg-2)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent)' }}>{active.technique_id}</span>
                <span style={{ fontSize: 14, color: 'var(--fg)' }}>{active.name}</span>
                <button onClick={() => setActive(null)} style={{ marginLeft: 'auto', background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--fg-3)' }}>
                  <Icon name="x" size={13} />
                </button>
              </div>
              <div style={{ display: 'flex', gap: 16, fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--fg-3)' }}>
                <span>tactic: {prettyTactic(active.tactic) || '—'}</span>
                <span>score: {active.score}</span>
                <span>sources: {active.sources.join(', ')}</span>
              </div>
              <a
                href={`https://attack.mitre.org/techniques/${active.technique_id.replace('.', '/')}/`}
                target="_blank" rel="noreferrer"
                style={{ display: 'inline-block', marginTop: 8, fontSize: 11, color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}
              >
                View on attack.mitre.org →
              </a>
            </div>
          )}
        </>
      )}
    </div>
  )
}
