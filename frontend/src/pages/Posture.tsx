import { useState, useEffect } from 'react'
import { useAppStore } from '@/stores/appStore'
import { getApiBase } from '@/lib/config'
import EmptyState from '@/components/EmptyState'
import SparkLine from '@/components/SparkLine'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Point {
  date: string
  new: Record<string, number>
  new_total: number
  cumulative: Record<string, number>
  cumulative_total: number
  controls_total: number
}
interface Posture { project_id: string; days: number; series: Point[] }

const SEVS = ['critical', 'high', 'medium', 'low', 'info'] as const
const SEV_COLOR: Record<string, string> = {
  critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)', info: 'var(--fg-3)',
}
const SEV_HEX: Record<string, string> = {
  critical: '#e85c4e', high: '#f0a83a', medium: '#d4c45a', low: '#6b8a72', info: '#7a7468',
}
const rule = '1px solid var(--rule)'

// ── New-findings stacked bar chart (SVG, viewBox-stretched) ─────────────────────

function NewFindingsBars({ series }: { series: Point[] }) {
  const maxNew = Math.max(1, ...series.map(p => p.new_total))
  const n = series.length
  return (
    <svg viewBox={`0 0 ${n} 100`} preserveAspectRatio="none" style={{ width: '100%', height: 120, display: 'block' }}>
      {series.map((p, i) => {
        let y = 100
        return SEVS.map(sev => {
          const c = p.new[sev] || 0
          if (!c) return null
          const h = (c / maxNew) * 96
          y -= h
          return <rect key={sev} x={i + 0.12} y={y} width={0.76} height={h} fill={SEV_HEX[sev]} />
        })
      })}
    </svg>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Posture() {
  const { selectedProject } = useAppStore()
  const api = getApiBase()
  const [data, setData] = useState<Posture | null>(null)
  const [loading, setLoading] = useState(false)
  const [days, setDays] = useState(90)

  useEffect(() => {
    if (!selectedProject) { setData(null); return }
    setLoading(true)
    fetch(`${api}/stats/posture?project_id=${selectedProject.id}&days=${days}`)
      .then(r => r.ok ? r.json() : null)
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [selectedProject, days])

  const series = data?.series ?? []
  const last = series[series.length - 1]
  const hasData = !!last && (last.cumulative_total > 0)

  return (
    <div style={{ padding: '24px 28px', maxWidth: 1100, margin: '0 auto', width: '100%' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, marginBottom: 22 }}>
        <div>
          <div className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)', marginBottom: 4 }}>Analysis</div>
          <h1 className="sec-h" style={{ margin: 0 }}>Posture Over Time</h1>
          <p style={{ fontSize: 12, color: 'var(--fg-3)', marginTop: 4 }}>
            Finding influx, cumulative trajectory, and coverage drift across the engagement.
          </p>
        </div>
        <div style={{ display: 'flex', border: rule, height: 26, flexShrink: 0 }}>
          {[30, 90, 180].map((d, i) => (
            <button key={d} onClick={() => setDays(d)} style={{
              background: days === d ? 'var(--accent-2)' : 'transparent', color: days === d ? 'var(--accent)' : 'var(--fg-3)',
              border: 'none', borderLeft: i > 0 ? rule : 'none', padding: '0 12px', fontSize: 10,
              textTransform: 'uppercase', letterSpacing: '0.1em', cursor: 'pointer', fontFamily: 'var(--font-mono)',
            }}>{d}d</button>
          ))}
        </div>
      </div>

      <div style={{ height: 1, background: 'var(--rule)', marginBottom: 22 }} />

      {!selectedProject ? (
        <EmptyState icon="activity" title="No project selected" hint="Pick an engagement to see its posture trend." />
      ) : loading && !data ? (
        <div style={{ fontSize: 13, color: 'var(--fg-3)' }}>Loading…</div>
      ) : !hasData ? (
        <EmptyState icon="activity" title="No history yet" hint="Run scans over time and findings will chart here as a trend." />
      ) : (
        <>
          {/* Summary cards with per-severity cumulative sparklines */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 22 }}>
            {SEVS.filter(s => s !== 'info').map(sev => (
              <div key={sev} style={{ border: rule, borderTop: `2px solid ${SEV_COLOR[sev]}`, borderRadius: 3, padding: '12px 14px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                  <span style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--font-mono)', color: SEV_COLOR[sev] }}>{last.cumulative[sev] ?? 0}</span>
                  <span className="smcap" style={{ fontSize: 9, color: 'var(--fg-3)' }}>{sev}</span>
                </div>
                <div style={{ marginTop: 6 }}>
                  <SparkLine values={series.map(p => p.cumulative[sev] ?? 0)} color={SEV_HEX[sev]} width={150} height={28} />
                </div>
              </div>
            ))}
            <div style={{ border: rule, borderTop: '2px solid var(--accent)', borderRadius: 3, padding: '12px 14px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                <span style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{last.controls_total}</span>
                <span className="smcap" style={{ fontSize: 9, color: 'var(--fg-3)' }}>controls</span>
              </div>
              <div style={{ marginTop: 6 }}>
                <SparkLine values={series.map(p => p.controls_total)} color="#f0a83a" width={150} height={28} />
              </div>
            </div>
          </div>

          {/* Cumulative total trajectory */}
          <div style={{ border: rule, borderRadius: 3, padding: '14px 16px', marginBottom: 16 }}>
            <div className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)', marginBottom: 8 }}>Cumulative findings ({last.cumulative_total} total)</div>
            <SparkLine values={series.map(p => p.cumulative_total)} color="#e85c4e" width={1040} height={70} />
          </div>

          {/* New findings per day (stacked) */}
          <div style={{ border: rule, borderRadius: 3, padding: '14px 16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)' }}>New findings per day</span>
              <div style={{ display: 'flex', gap: 10 }}>
                {SEVS.filter(s => s !== 'info').map(sev => (
                  <span key={sev} className="mono" style={{ fontSize: 9, color: SEV_COLOR[sev], display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span style={{ width: 8, height: 8, background: SEV_HEX[sev], display: 'inline-block' }} />{sev}
                  </span>
                ))}
              </div>
            </div>
            <NewFindingsBars series={series} />
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--fg-4)' }}>
              <span>{series[0]?.date}</span>
              <span>{last.date}</span>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
