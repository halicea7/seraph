import { useState, useEffect } from 'react'
import { Brain } from 'lucide-react'
import Icon from '../components/Icon'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import type { Finding } from '../types'
import { getFindings, getStats, type PlatformStats } from '../api/client'
import { useAuth } from '../contexts/AuthContext'
import { useAppStore } from '@/stores/appStore'
import { useAINarrative } from '../contexts/AINarrativeContext'
import { getApiBase } from '@/lib/config'

// ── Constants ─────────────────────────────────────────────────────────────────

const rule = '1px solid var(--rule)'
const ruleStrong = '1px solid var(--rule-strong)'

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--crit)',
  high:     'var(--high)',
  medium:   'var(--med)',
  low:      'var(--low)',
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function Section({ title, right, children }: { title: string; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="rule" style={{ background: 'var(--bg)' }}>
      <div className="sec-h">
        <span className="title">{title}</span>
        {right && <span style={{ display: 'flex', gap: 8, alignItems: 'center' }}>{right}</span>}
      </div>
      {children}
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label style={{ display: 'block', marginBottom: 6 }}>{label}</label>
      {children}
    </div>
  )
}

function SegBtns({ options, value, onChange }: { options: string[]; value: string; onChange: (v: string) => void }) {
  return (
    <div style={{ display: 'flex', border: rule, height: 26 }}>
      {options.map((o, i) => (
        <button key={o} onClick={() => onChange(o)} style={{
          background: value === o ? 'var(--accent-2)' : 'transparent',
          color: value === o ? 'var(--accent)' : 'var(--fg-3)',
          border: 'none', borderLeft: i > 0 ? rule : 'none',
          padding: '0 10px', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em',
          cursor: 'pointer', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap',
        }}>{o}</button>
      ))}
    </div>
  )
}

function Pill({ tone, children }: { tone: 'pass' | 'fail' | 'warn' | 'info'; children: React.ReactNode }) {
  const map = {
    pass: { color: 'var(--ok)',   bg: 'rgba(107,138,114,0.1)' },
    fail: { color: 'var(--crit)', bg: 'rgba(232,92,78,0.1)' },
    warn: { color: 'var(--high)', bg: 'rgba(240,168,58,0.1)' },
    info: { color: 'var(--fg-2)', bg: 'var(--bg-2)' },
  }
  const s = map[tone]
  return (
    <span className="mono" style={{
      fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.12em',
      padding: '1px 6px', color: s.color, background: s.bg, border: `1px solid ${s.color}33`,
    }}>{children}</span>
  )
}

function KV({ items }: { items: { k: string; v: string }[] }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {items.map((it, i) => (
        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px dashed var(--rule)', padding: '4px 0', alignItems: 'baseline' }}>
          <span className="mono" style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fg-3)' }}>{it.k}</span>
          <span className="mono tnum" style={{ fontSize: 12, color: 'var(--fg)', textAlign: 'right', marginLeft: 12 }}>{it.v}</span>
        </div>
      ))}
    </div>
  )
}

function PageHeader({ title, sub, right }: { title: string; sub: string; right?: React.ReactNode }) {
  return (
    <div style={{
      borderBottom: '1px solid var(--rule)', padding: '18px var(--pad)',
      display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: 16, flexShrink: 0,
    }}>
      <div>
        <h1 className="mono" style={{ margin: 0, fontWeight: 500, fontSize: 22, letterSpacing: '-0.01em' }}>{title}</h1>
        <div style={{ color: 'var(--fg-3)', fontSize: 12, marginTop: 6 }}>{sub}</div>
      </div>
      {right && <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>{right}</div>}
    </div>
  )
}

// ── Preview sub-components ────────────────────────────────────────────────────

function ExecReport({ auditor, findings, project }: { auditor: string; findings: Finding[]; project: { name: string; created_at?: string } | null }) {
  const counts = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high:     findings.filter(f => f.severity === 'high').length,
    medium:   findings.filter(f => f.severity === 'medium').length,
    low:      findings.filter(f => f.severity === 'low').length,
  }
  const total = findings.length
  const projName = project?.name ?? 'Untitled Project'
  const startDate = project?.created_at ? new Date(project.created_at).toISOString().slice(0, 10) : '—'
  const endDate = new Date().toISOString().slice(0, 10)

  const critHigh = findings.filter(f => f.severity === 'critical' || f.severity === 'high')
  const sevOrder = ['critical', 'high', 'medium', 'low']
  const sortedFindings = [...findings].sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity))

  const riskLevel = counts.critical > 0 ? 'Critical' : counts.high > 3 ? 'High' : counts.high > 0 ? 'Medium-High' : counts.medium > 0 ? 'Medium' : 'Low'

  return (
    <div style={{ fontFamily: 'var(--font-serif)', color: 'var(--fg)' }}>
      <div className="mono" style={{ fontSize: 10, letterSpacing: '0.22em', color: 'var(--fg-3)', textTransform: 'uppercase' }}>
        EXECUTIVE SUMMARY · CONFIDENTIAL
      </div>
      <h1 style={{ fontFamily: 'var(--font-serif)', fontWeight: 500, fontSize: 36, letterSpacing: '-0.01em', lineHeight: 1.15, margin: '12px 0 6px' }}>
        {projName}
      </h1>
      <h2 style={{ fontFamily: 'var(--font-sans)', fontWeight: 400, fontSize: 16, color: 'var(--fg-3)', margin: '0 0 32px' }}>
        Penetration Test Report · {startDate} to {endDate}
      </h2>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 0, border: '1px solid var(--rule)', marginBottom: 28 }}>
        {([
          { k: 'critical', v: counts.critical, c: 'var(--crit)' },
          { k: 'high',     v: counts.high,     c: 'var(--high)' },
          { k: 'medium',   v: counts.medium,   c: 'var(--med)' },
          { k: 'low',      v: counts.low,      c: 'var(--low)' },
        ] as const).map((d, i) => (
          <div key={d.k} style={{ padding: 14, borderLeft: i > 0 ? '1px solid var(--rule)' : 'none' }}>
            <div className="mono" style={{ fontSize: 9.5, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.16em' }}>{d.k}</div>
            <div className="mono tnum" style={{ fontSize: 30, color: d.c, fontWeight: 500, marginTop: 4 }}>{d.v}</div>
          </div>
        ))}
      </div>

      {total === 0 ? (
        <p style={{ fontSize: 15, lineHeight: 1.7, color: 'var(--fg-3)' }}>
          No findings have been recorded for this project yet. Generate a report after completing scans.
        </p>
      ) : (
        <>
          <p style={{ fontSize: 15, lineHeight: 1.7, marginTop: 0 }}>
            This report documents a security assessment of <strong>{projName}</strong> conducted between {startDate} and {endDate}.
            A total of <strong>{total} finding{total !== 1 ? 's' : ''}</strong> were identified across the assessed scope,
            with an overall risk rating of <strong>{riskLevel}</strong>.
            {counts.critical > 0 && ` The engagement identified ${counts.critical} critical-severity issue${counts.critical !== 1 ? 's' : ''} requiring immediate remediation.`}
          </p>
          {critHigh.length > 0 && (
            <p style={{ fontSize: 15, lineHeight: 1.7 }}>
              The highest-priority finding is <strong>{critHigh[0].title}</strong>
              {critHigh[0].cve_id ? ` (${critHigh[0].cve_id})` : ''}.
              {critHigh.length > 1 && ` An additional ${critHigh.length - 1} critical or high severity finding${critHigh.length > 2 ? 's' : ''} ${critHigh.length > 2 ? 'require' : 'requires'} prompt attention.`}
            </p>
          )}
        </>
      )}

      {critHigh.length > 0 && (
        <>
          <h3 style={{ fontFamily: 'var(--font-mono)', fontSize: 12, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--accent)', marginTop: 32 }}>
            Top-line recommendations
          </h3>
          <ol style={{ fontSize: 14.5, lineHeight: 1.65, paddingLeft: 18 }}>
            {sortedFindings.slice(0, 5).map((f, i) => {
              const rem = f.remediation ?? 'Refer to the technical findings section for detailed remediation guidance.'
              return (
                <li key={i}>
                  <strong>{f.title}</strong>
                  {f.cve_id ? ` (${f.cve_id})` : ''} — {rem.replace(/\n/g, ' ').slice(0, 160)}{rem.length > 160 ? '…' : ''}
                </li>
              )
            })}
          </ol>
        </>
      )}

      <div style={{ marginTop: 40, paddingTop: 18, borderTop: '1px solid var(--rule)', display: 'flex', justifyContent: 'space-between' }}>
        <div>
          <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.12em' }}>auditor</div>
          <div className="mono" style={{ fontSize: 13, marginTop: 4 }}>{auditor || 'Seraph (Automated)'}</div>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.12em' }}>findings</div>
          <div className="mono" style={{ fontSize: 13, marginTop: 4 }}>{total}</div>
        </div>
      </div>
    </div>
  )
}

function TechReport({ findings }: { findings: Finding[] }) {
  const sevOrder = ['critical', 'high', 'medium', 'low']
  const sorted = [...findings].sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity))
  const [idx, setIdx] = useState(0)
  const f = sorted[idx] ?? null

  if (!f) {
    return (
      <div style={{ textAlign: 'center', color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', fontSize: 12, paddingTop: 40 }}>
        No findings loaded. Select a project with findings to preview technical detail.
      </div>
    )
  }

  const foundDate = f.created_at ? new Date(f.created_at).toISOString().slice(0, 16).replace('T', ' ') : '—'

  return (
    <div style={{ fontFamily: 'var(--font-serif)', color: 'var(--fg)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 2 }}>
        <div className="mono" style={{ fontSize: 10, letterSpacing: '0.22em', color: 'var(--fg-3)', textTransform: 'uppercase' }}>
          TECHNICAL FINDINGS · {sorted.length} ITEM{sorted.length !== 1 ? 'S' : ''}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button onClick={() => setIdx(i => Math.max(0, i - 1))} disabled={idx === 0}
            style={{ background: 'none', border: '1px solid var(--rule)', padding: '2px 8px', fontSize: 10, color: 'var(--fg-3)', cursor: idx === 0 ? 'not-allowed' : 'pointer', fontFamily: 'var(--font-mono)' }}>
            ←
          </button>
          <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', lineHeight: '22px' }}>{idx + 1} / {sorted.length}</span>
          <button onClick={() => setIdx(i => Math.min(sorted.length - 1, i + 1))} disabled={idx === sorted.length - 1}
            style={{ background: 'none', border: '1px solid var(--rule)', padding: '2px 8px', fontSize: 10, color: 'var(--fg-3)', cursor: idx === sorted.length - 1 ? 'not-allowed' : 'pointer', fontFamily: 'var(--font-mono)' }}>
            →
          </button>
        </div>
      </div>
      <h1 style={{ fontFamily: 'var(--font-serif)', fontWeight: 500, fontSize: 26, margin: '10px 0 20px', lineHeight: 1.25 }}>
        {f.title}
      </h1>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 24 }}>
        <KV items={[
          { k: 'identifier', v: f.cve_id ?? '—' },
          { k: 'severity',   v: f.severity ? f.severity.charAt(0).toUpperCase() + f.severity.slice(1) : '—' },
          { k: 'cvss 3.1',   v: f.cvss_score != null ? String(f.cvss_score) : '—' },
          { k: 'framework',  v: f.framework ?? '—' },
        ]} />
        <KV items={[
          { k: 'status',  v: f.status ?? 'open' },
          { k: 'found',   v: foundDate },
          { k: 'control', v: f.control_id ?? '—' },
          { k: 'tags',    v: f.tags ? f.tags.split(',')[0].trim() : '—' },
        ]} />
      </div>

      <h3 style={{ fontFamily: 'var(--font-mono)', fontSize: 11.5, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--accent)', marginTop: 0 }}>
        Description
      </h3>
      <p style={{ fontSize: 14.5, lineHeight: 1.7 }}>
        {f.description ?? 'No description available.'}
      </p>

      {f.remediation && (
        <>
          <h3 style={{ fontFamily: 'var(--font-mono)', fontSize: 11.5, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--accent)' }}>
            Remediation
          </h3>
          <p style={{ fontSize: 14.5, lineHeight: 1.7 }}>{f.remediation}</p>
        </>
      )}

      {f.evidence && (
        <>
          <h3 style={{ fontFamily: 'var(--font-mono)', fontSize: 11.5, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--accent)' }}>
            Evidence
          </h3>
          <div className="term rule" style={{ padding: 12, fontSize: 11.5, fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {f.evidence}
          </div>
        </>
      )}
    </div>
  )
}

function FindingsMatrix({ findings }: { findings: Finding[] }) {
  return (
    <table className="data" style={{ background: 'var(--bg)', width: '100%' }}>
      <thead>
        <tr>
          <th>ID</th>
          <th>Sev</th>
          <th>CVSS</th>
          <th>Title</th>
          <th>CVE</th>
          <th>State</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f) => (
          <tr key={f.id} className="zebra">
            <td className="mono" style={{ color: 'var(--fg-3)', fontSize: 10 }}>{f.id.slice(0, 8)}</td>
            <td>
              <span style={{
                display: 'inline-block', width: 8, height: 8,
                background: SEV_COLOR[f.severity] ?? 'var(--fg-4)',
              }} />
            </td>
            <td className="mono tnum">{f.cvss_score ?? '—'}</td>
            <td style={{ fontSize: 12 }}>{f.title}</td>
            <td className="mono" style={{ fontSize: 10.5, color: 'var(--fg-3)' }}>{f.cve_id ?? '—'}</td>
            <td>
              <Pill tone={f.status === 'remediated' ? 'pass' : f.status === 'open' ? 'fail' : 'warn'}>
                {f.status ?? 'open'}
              </Pill>
            </td>
          </tr>
        ))}
        {findings.length === 0 && (
          <tr>
            <td colSpan={6} style={{ textAlign: 'center', color: 'var(--fg-3)', padding: 24, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
              no findings loaded
            </td>
          </tr>
        )}
      </tbody>
    </table>
  )
}

function EvidencePreview({ projectId }: { projectId: string }) {
  const [items, setItems] = useState<Array<{ id: string; filename: string; type: string; created_at?: string; url?: string }>>([])
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    if (!projectId) { setLoaded(true); return }
    fetch(`${getApiBase()}/evidence?project_id=${projectId}`)
      .then(r => r.ok ? r.json() : [])
      .then(data => { setItems(Array.isArray(data) ? data : []); setLoaded(true) })
      .catch(() => setLoaded(true))
  }, [projectId])

  if (!loaded) {
    return <div style={{ textAlign: 'center', color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', fontSize: 11, paddingTop: 40 }}>Loading evidence…</div>
  }

  return (
    <div>
      <h1 style={{ fontFamily: 'var(--font-serif)', fontWeight: 500, fontSize: 26, margin: '0 0 6px' }}>Evidence pack</h1>
      <p className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>
        {items.length > 0
          ? `${items.length} artifact${items.length !== 1 ? 's' : ''} attached to this engagement`
          : 'No evidence uploaded for this project'}
      </p>
      {items.length === 0 ? (
        <div style={{ marginTop: 32, padding: 24, border: '1px dashed var(--rule)', textAlign: 'center', color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
          Evidence files (screenshots, terminal captures, loot) can be attached to findings<br />in the Vuln Tracker view.
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginTop: 24 }}>
          {items.map((item, i) => (
            <div key={item.id ?? i} className="rule" style={{ padding: 8 }}>
              <div className="hatch" style={{ aspectRatio: '4/3', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                {item.url
                  ? <img src={item.url} alt={item.filename} style={{ maxWidth: '100%', maxHeight: '100%', objectFit: 'contain' }} />
                  : <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.14em' }}>
                      {item.type ?? 'file'}
                    </span>
                }
              </div>
              <div className="mono" style={{ fontSize: 10.5, marginTop: 6, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.filename}</div>
              {item.created_at && (
                <div className="mono" style={{ fontSize: 9.5, color: 'var(--fg-3)', marginTop: 2 }}>
                  {new Date(item.created_at).toISOString().slice(0, 16).replace('T', ' ')}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── AI Generate state ─────────────────────────────────────────────────────────

interface GenState {
  running: boolean
  done: boolean
  p: number
  lines: string[]
}

// ── Main component ────────────────────────────────────────────────────────────

type PreviewTab = 'exec' | 'tech' | 'findings' | 'evid' | 'report' | 'ai'
type Template = 'executive_summary' | 'technical_detail' | 'compliance_mapped'
type NarrativeStyle = 'executive' | 'technical'
type Audience = 'Exec' | 'Tech' | 'Both'
type Branding = 'Seraph' | 'Plain' | 'Custom'

export default function Reports() {
  const { user } = useAuth()
  const { generating: generatingNarrative, progress: narrativeProgress, generate } = useAINarrative()
  const { selectedProject: sp, projects } = useAppStore()
  const projectId = sp?.id ?? ''

  // Config sidebar state
  const [template, setTemplate] = useState<Template>('technical_detail')
  const [auditor, setAuditor] = useState<string>(user?.full_name || user?.username || 'Margot Chen')
  const [audience, setAudience] = useState<Audience>('Both')
  const [branding, setBranding] = useState<Branding>('Custom')
  const [includes, setIncludes] = useState<Record<string, boolean>>({
    'Executive summary': true,
    'Finding details': true,
    'Evidence (screenshots)': true,
    'Terminal captures': true,
    'Attack narrative': true,
    'Remediation': true,
    'CVSS matrix': true,
    'Appendix · scope': true,
  })

  // AI narrative sidebar state
  const [narrativeStyle, setNarrativeStyle] = useState<NarrativeStyle>('executive')
  const [narrative, setNarrative] = useState<string>('')
  const [localReport, setLocalReport] = useState<string>('')
  const [narrativeSavedAt, setNarrativeSavedAt] = useState<string>('')
  const [narrativeError, setNarrativeError] = useState<string>('')
  const [localGen, setLocalGen] = useState<GenState>({ running: false, done: false, p: 0, lines: [] })
  const [aiModels, setAiModels] = useState<string[]>([])
  const [aiModel, setAiModel] = useState<string>('')

  // Data
  const [findings, setFindings] = useState<Finding[]>([])
  const [_stats, setStats] = useState<PlatformStats | null>(null)
  const [loading, setLoading] = useState(false)
  const [generating, setGenerating] = useState(false)

  // Preview tab
  const [previewTab, setPreviewTab] = useState<PreviewTab>('exec')

  // ── Effects ──────────────────────────────────────────────────────────────────

  useEffect(() => {
    loadStats()
  }, [])

  useEffect(() => {
    if (user && !auditor) setAuditor(user.full_name || user.username)
  }, [user])

  useEffect(() => {
    if (projectId) {
      loadFindings(projectId)
      loadSavedNarrative(projectId, narrativeStyle)
    }
  }, [projectId])

  useEffect(() => {
    if (projectId) loadSavedNarrative(projectId, narrativeStyle)
  }, [narrativeStyle])

  useEffect(() => {
    if (!__IS_ELECTRON__) return
    window.electronAPI!.ollamaModels()
      .then(models => {
        setAiModels(models)
        if (models.length && !aiModel) setAiModel(models[0])
      })
      .catch(() => {})
  }, [])

  // ── Loaders ──────────────────────────────────────────────────────────────────

  async function loadStats() {
    try { setStats(await getStats()) } catch { /* ignore */ }
  }

  async function loadSavedNarrative(pid: string, style: string) {
    try {
      const res = await fetch(`${getApiBase()}/ai/narrate/${pid}`)
      if (!res.ok) return
      const data = await res.json()
      const saved = data[style]
      if (saved) { setNarrative(saved.content); setNarrativeSavedAt(saved.generated_at) }
      else { setNarrative(''); setNarrativeSavedAt('') }
    } catch { /* ignore */ }
  }

  async function loadFindings(pid: string) {
    setLoading(true)
    try { setFindings(await getFindings(pid)) } catch { setFindings([]) } finally { setLoading(false) }
  }

  // ── Handlers ─────────────────────────────────────────────────────────────────

  async function handleLocalGenerate() {
    if (localGen.running) return
    if (!projectId) return
    setLocalGen({ running: true, done: false, p: 0, lines: [] })

    // Run progress animation steps while fetching data in parallel
    let animIdx = 0
    const GEN_STEPS = [
      'fetching findings from API ...',
      'fetching scan data from API ...',
      'counting severity distribution ...',
      'drafting executive summary ...',
      'building findings table ...',
      'composing recommendations ...',
      'formatting markdown report ...',
      'finalising document ...',
      'report ready.',
    ]
    const stepInterval = setInterval(() => {
      animIdx++
      setLocalGen(g => ({
        ...g,
        p: Math.min(90, Math.round((animIdx / GEN_STEPS.length) * 90)),
        lines: [...g.lines, GEN_STEPS[animIdx - 1]],
      }))
      if (animIdx >= GEN_STEPS.length) clearInterval(stepInterval)
    }, 480 + Math.random() * 320)

    try {
      // Fetch findings and scans in parallel
      const [findingsRes, scansRes] = await Promise.allSettled([
        fetch(`${getApiBase()}/findings?project_id=${projectId}`),
        fetch(`${getApiBase()}/scans?project_id=${projectId}`),
      ])

      let reportFindings: Finding[] = []
      if (findingsRes.status === 'fulfilled' && findingsRes.value.ok) {
        const data = await findingsRes.value.json()
        reportFindings = Array.isArray(data) ? data : (data.findings ?? data.items ?? [])
      } else {
        reportFindings = findings
      }
      // Update findings state so Executive / Technical / Findings Matrix tabs populate
      if (reportFindings.length > 0) setFindings(reportFindings)

      let scans: any[] = []
      if (scansRes.status === 'fulfilled' && scansRes.value.ok) {
        const data = await scansRes.value.json()
        scans = Array.isArray(data) ? data : (data.scans ?? data.items ?? [])
      }

      // Severity counts
      const counts = {
        critical: reportFindings.filter(f => f.severity === 'critical').length,
        high:     reportFindings.filter(f => f.severity === 'high').length,
        medium:   reportFindings.filter(f => f.severity === 'medium').length,
        low:      reportFindings.filter(f => f.severity === 'low').length,
      }
      const total = reportFindings.length
      const projName = selectedProj?.name ?? projectId

      // Build the markdown report
      const now = new Date().toISOString().slice(0, 10)
      const lines: string[] = []

      lines.push(`# Penetration Test Report`)
      lines.push(``)
      lines.push(`**Project:** ${projName}  `)
      lines.push(`**Date:** ${now}  `)
      lines.push(`**Auditor:** ${auditor || 'Seraph (Automated)'}  `)
      lines.push(`**Classification:** CONFIDENTIAL`)
      lines.push(``)
      lines.push(`---`)
      lines.push(``)

      // Executive Summary
      lines.push(`## Executive Summary`)
      lines.push(``)
      lines.push(`This report documents findings from a penetration test of project **${projName}**. ` +
        `A total of **${total}** finding${total !== 1 ? 's' : ''} were identified across the assessed scope.`)
      lines.push(``)
      lines.push(`| Severity | Count |`)
      lines.push(`|----------|-------|`)
      lines.push(`| Critical | ${counts.critical} |`)
      lines.push(`| High     | ${counts.high} |`)
      lines.push(`| Medium   | ${counts.medium} |`)
      lines.push(`| Low      | ${counts.low} |`)
      lines.push(`| **Total**| **${total}** |`)
      lines.push(``)

      // Scope
      lines.push(`## Scope`)
      lines.push(``)
      if (scans.length > 0) {
        lines.push(`The following ${scans.length} scan(s) were conducted during this engagement:`)
        lines.push(``)
        lines.push(`| # | Target | Type | Status |`)
        lines.push(`|---|--------|------|--------|`)
        scans.slice(0, 20).forEach((s: any, idx: number) => {
          lines.push(`| ${idx + 1} | ${s.target ?? s.host ?? '—'} | ${s.scan_type ?? s.type ?? '—'} | ${s.status ?? '—'} |`)
        })
      } else {
        lines.push(`Scope details were not available at the time of report generation.`)
      }
      lines.push(``)

      // Findings
      lines.push(`## Findings`)
      lines.push(``)
      if (reportFindings.length === 0) {
        lines.push(`No findings recorded for this project.`)
      } else {
        lines.push(`| # | Severity | Title | Description |`)
        lines.push(`|---|----------|-------|-------------|`)
        // Sort: critical → high → medium → low
        const sevOrder = ['critical', 'high', 'medium', 'low']
        const sorted = [...reportFindings].sort((a, b) =>
          (sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity))
        )
        sorted.forEach((f, idx) => {
          const desc = (f.description ?? '').replace(/\n/g, ' ').slice(0, 120)
          lines.push(`| ${idx + 1} | ${f.severity?.toUpperCase() ?? '—'} | ${f.title ?? '—'} | ${desc}${(f.description ?? '').length > 120 ? '…' : ''} |`)
        })
      }
      lines.push(``)

      // Recommendations
      lines.push(`## Recommendations`)
      lines.push(``)
      const critHigh = reportFindings.filter(f => f.severity === 'critical' || f.severity === 'high')
      if (critHigh.length > 0) {
        lines.push(`The following high-priority items should be addressed immediately:`)
        lines.push(``)
        critHigh.slice(0, 10).forEach((f, idx) => {
          const rem = f.remediation ?? 'Refer to finding details for remediation guidance.'
          lines.push(`${idx + 1}. **${f.title}** — ${rem.replace(/\n/g, ' ').slice(0, 200)}`)
        })
      } else {
        lines.push(`No critical or high severity findings were identified. Continue to monitor and remediate any medium/low items in accordance with your security policy.`)
      }
      lines.push(``)
      lines.push(`---`)
      lines.push(``)
      lines.push(`*Generated by Seraph on ${now}*`)

      const reportMd = lines.join('\n')

      clearInterval(stepInterval)
      setLocalReport(reportMd)
      setLocalGen(g => ({ ...g, p: 100, lines: [...g.lines, 'report ready.'], running: false, done: true }))
      setPreviewTab('exec')
    } catch (err: any) {
      clearInterval(stepInterval)
      setLocalGen(g => ({ ...g, running: false, done: true, lines: [...g.lines, `error: ${err.message}`] }))
    }
  }

  async function handleGenerateNarrative() {
    if (!projectId) return
    setNarrativeError('')
    try {
      const result = await generate(projectId, narrativeStyle)
      if (result) {
        setNarrative(result.narrative)
        setNarrativeSavedAt(result.savedAt)
        setPreviewTab('ai')
      }
    } catch (err: any) { setNarrativeError(err.message || 'Unknown error') }
  }

  async function handleExportPDF() {
    if (!projectId) return
    setGenerating(true)
    try {
      const res = await fetch(`${getApiBase()}/audit/reports/pdf/${projectId}`)
      if (!res.ok) { const data = await res.json().catch(() => ({})); throw new Error(data.detail || `HTTP ${res.status}`) }
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url; a.download = `seraph_report_${projectId.slice(0, 8)}.pdf`; a.click()
      URL.revokeObjectURL(url)
    } catch (err: any) { alert(`PDF export failed: ${err.message}`) } finally { setGenerating(false) }
  }

  async function handleGenerateReport(format: 'html' | 'markdown') {
    if (!projectId) return
    setGenerating(true)
    try {
      const isHtmlNative = template === 'executive_summary' || template === 'technical_detail' || template === 'compliance_mapped'
      let blob: Blob
      if (isHtmlNative && format === 'html') {
        const res = await fetch(`${getApiBase()}/audit/reports/generate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ project_id: projectId, report_type: template, auditor: auditor || 'Seraph (Automated)' }),
        })
        const data = await res.json()
        blob = new Blob([data.html || ''], { type: 'text/html' })
      } else {
        const params = new URLSearchParams({ format, auditor: auditor || 'Seraph (Automated)' })
        blob = await (await fetch(`${getApiBase()}/audit/reports/download/${projectId}?${params}`)).blob()
      }
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `seraph_${template}_${projectId.slice(0, 8)}.${format === 'markdown' ? 'md' : 'html'}`
      a.click()
      URL.revokeObjectURL(url)
    } catch { /* ignore */ } finally { setGenerating(false) }
  }

  // ── Derived ───────────────────────────────────────────────────────────────────

  const selectedProj = projects.find(p => p.id === projectId)
  const hasNewFindings = !!(selectedProj?.latest_finding_at && (!narrativeSavedAt || new Date(selectedProj.latest_finding_at) > new Date(narrativeSavedAt)))
  const displayFindings = template === 'executive_summary'
    ? findings.filter(f => f.severity === 'critical' || f.severity === 'high')
    : findings

  const PREVIEW_TABS = [
    { id: 'exec' as PreviewTab, label: 'Executive' },
    { id: 'tech' as PreviewTab, label: `Technical · ${displayFindings.length}` },
    { id: 'findings' as PreviewTab, label: 'Findings matrix' },
    { id: 'evid' as PreviewTab, label: 'Evidence' },
    { id: 'report' as PreviewTab, label: 'Report' },
    { id: 'ai' as PreviewTab, label: 'AI' },
  ]

  const selStyle: React.CSSProperties = {
    background: 'var(--bg-2)', border: ruleStrong, borderRadius: 3,
    padding: '5px 10px', fontSize: 12, color: 'var(--fg)',
    fontFamily: 'var(--font-mono)', outline: 'none', width: '100%',
    boxSizing: 'border-box',
  }

  const inputStyle: React.CSSProperties = {
    background: 'var(--bg-2)', border: ruleStrong, borderRadius: 3,
    padding: '5px 10px', fontSize: 12, color: 'var(--fg)',
    fontFamily: 'var(--font-sans)', outline: 'none', width: '100%',
    boxSizing: 'border-box',
  }

  // ── Render ────────────────────────────────────────────────────────────────────

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg)', color: 'var(--fg)' }}>

      {/* AI Narrative global progress (from context) */}
      {narrativeProgress !== null && (
        <div style={{
          position: 'fixed', top: 16, right: 16, zIndex: 50, width: 280,
          borderRadius: 6, overflow: 'hidden', border: '1px solid rgba(168,85,247,0.3)',
          background: 'rgba(10,5,20,0.92)', boxShadow: '0 0 24px rgba(168,85,247,0.25)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px' }}>
            <Brain size={12} style={{ color: '#a855f7', flexShrink: 0 }} />
            <span style={{ fontSize: 12, color: '#c084fc', fontWeight: 500, flex: 1, fontFamily: 'var(--font-sans)' }}>Generating narrative…</span>
            {narrativeProgress >= 0 && (
              <span style={{ fontSize: 10, color: '#a855f7', fontFamily: 'var(--font-mono)' }}>{Math.round(narrativeProgress)}%</span>
            )}
          </div>
          <div style={{ height: 5, width: '100%', background: 'rgba(168,85,247,0.15)' }}>
            {narrativeProgress === -1 ? (
              <div style={{ height: '100%', width: '100%', position: 'relative', overflow: 'hidden' }}>
                <div style={{ position: 'absolute', height: '100%', width: '40%', background: 'linear-gradient(90deg, transparent, rgba(168,85,247,0.9), transparent)', animation: 'seraph-shimmer 1.4s ease-in-out infinite' }} />
              </div>
            ) : (
              <div style={{ height: '100%', width: `${narrativeProgress}%`, background: 'linear-gradient(90deg, #7c3aed, #a855f7)', transition: 'width 0.2s' }} />
            )}
          </div>
        </div>
      )}

      {/* Page header */}
      <PageHeader
        title="Reports"
        sub="Render HTML / Markdown / PDF deliverables. AI narrative compiled locally via Ollama."
        right={
          <>
            <button
              className="btn"
              onClick={() => handleGenerateReport('html')}
              disabled={generating || !projectId}
            >
              <Icon name="download" size={11} /> HTML
            </button>
            <button
              className="btn"
              onClick={() => handleGenerateReport('markdown')}
              disabled={generating || !projectId}
            >
              <Icon name="download" size={11} /> Markdown
            </button>
            <button
              className="btn btn-primary"
              onClick={handleExportPDF}
              disabled={generating || !projectId}
            >
              <Icon name="download" size={11} color="#1a1408" /> Render PDF
            </button>
          </>
        }
      />

      {/* 2-pane layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', flex: 1, minHeight: 0, overflow: 'hidden' }}>

        {/* ── Left pane: config sidebar ── */}
        <div style={{ borderRight: '1px solid var(--rule)', overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>

          <Section title="REPORT CONFIG">
            <div style={{ padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 14 }}>
              <Field label="Template">
                <select
                  value={template}
                  onChange={e => setTemplate(e.target.value as Template)}
                  style={selStyle}
                >
                  <option value="executive_summary">Pentest · Formal</option>
                  <option value="technical_detail">Pentest · Concise</option>
                  <option value="compliance_mapped">Compliance · CIS</option>
                  <option value="technical_detail">Internal handoff</option>
                </select>
              </Field>

              <Field label="Auditor">
                <input
                  type="text"
                  value={auditor}
                  onChange={e => setAuditor(e.target.value)}
                  placeholder="Margot Chen"
                  style={inputStyle}
                />
              </Field>

              <Field label="Audience">
                <SegBtns options={['Exec', 'Tech', 'Both']} value={audience} onChange={v => setAudience(v as Audience)} />
              </Field>

              <Field label="Include">
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {Object.keys(includes).map(s => (
                    <label key={s} style={{ display: 'flex', gap: 8, textTransform: 'none', fontSize: 11.5, letterSpacing: 0, color: 'var(--fg-2)', fontFamily: 'var(--font-sans)', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={includes[s]}
                        onChange={e => setIncludes(prev => ({ ...prev, [s]: e.target.checked }))}
                        style={{ width: 12, height: 12, accentColor: 'var(--accent)', flexShrink: 0, marginTop: 1 }}
                      />
                      {s}
                    </label>
                  ))}
                </div>
              </Field>

              <Field label="Branding">
                <SegBtns options={['Seraph', 'Plain', 'Custom']} value={branding} onChange={v => setBranding(v as Branding)} />
              </Field>
            </div>
          </Section>

          <Section title="AI NARRATIVE · LOCAL">
            <div style={{ padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 10 }}>

              {/* Narrative style selector */}
              <SegBtns
                options={['executive', 'technical']}
                value={narrativeStyle}
                onChange={v => setNarrativeStyle(v as NarrativeStyle)}
              />

              {/* Generate narrative — data-driven, no AI */}
              <button
                onClick={handleLocalGenerate}
                disabled={localGen.running || !projectId}
                className="btn btn-primary"
                style={{ width: '100%', justifyContent: 'center' }}
              >
                <Icon name="bolt" size={11} color="#1a1408" />
                {localGen.running ? 'Generating…' : 'Generate narrative'}
              </button>

              {/* Model selector */}
              {aiModels.length > 0 ? (
                <select
                  value={aiModel}
                  onChange={e => setAiModel(e.target.value)}
                  style={{
                    width: '100%', background: 'var(--bg-2)', border: ruleStrong, padding: '4px 8px',
                    fontSize: 11, color: 'var(--fg)', fontFamily: 'var(--font-mono)', outline: 'none',
                    boxSizing: 'border-box',
                  }}
                >
                  {aiModels.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              ) : (
                <span className="mono" style={{ fontSize: 10, color: 'var(--fg-4)' }}>no models found</span>
              )}

              {/* AI Interpretation — calls local Ollama */}
              <button
                onClick={handleGenerateNarrative}
                disabled={generatingNarrative || !projectId || !aiModel}
                title={hasNewFindings ? 'New findings since last narrative — regenerate' : 'Generate AI narrative using local LLM'}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, width: '100%',
                  padding: '5px 10px', background: 'none', border: '1px solid rgba(168,85,247,0.4)',
                  fontSize: 11, color: aiModel && !generatingNarrative ? '#a855f7' : 'var(--fg-4)',
                  cursor: generatingNarrative || !projectId || !aiModel ? 'not-allowed' : 'pointer',
                  fontFamily: 'var(--font-mono)', position: 'relative',
                }}
              >
                <Brain size={11} />
                {generatingNarrative ? 'Running…' : 'AI Interpretation'}
                {hasNewFindings && !generatingNarrative && (
                  <span style={{ position: 'absolute', top: 3, right: 8, width: 5, height: 5, borderRadius: '50%', background: 'var(--crit)' }} />
                )}
              </button>

              {/* Progress + streaming log */}
              {(localGen.running || localGen.done) && (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.12em' }}>
                      {localGen.done ? 'complete' : 'streaming'}
                    </span>
                    <span className="mono tnum" style={{ fontSize: 10, color: localGen.done ? 'var(--ok)' : 'var(--accent)' }}>
                      {localGen.p}%
                    </span>
                  </div>
                  <div style={{ height: 4, background: 'var(--rule-2)' }}>
                    <div style={{
                      width: `${localGen.p}%`, height: '100%',
                      background: localGen.done ? 'var(--ok)' : 'var(--accent)',
                      transition: 'width 0.3s',
                    }} />
                  </div>
                  <div className="term rule" style={{ marginTop: 10, padding: 10, fontSize: 10.5, maxHeight: 160, overflowY: 'auto', background: 'var(--bg-term)' }}>
                    {localGen.lines.map((l, i) => (
                      <div key={i} className={i === localGen.lines.length - 1 && localGen.running ? 'stdout' : 'muted'}>→ {l}</div>
                    ))}
                    {localGen.running && (
                      <div style={{ display: 'flex', alignItems: 'center' }}>
                        <span className="muted">awaiting</span>
                        <span className="cursor" />
                      </div>
                    )}
                  </div>

                  {narrativeError && (
                    <div style={{ marginTop: 10, fontSize: 11, color: 'var(--crit)', fontFamily: 'var(--font-sans)' }}>
                      {narrativeError}
                    </div>
                  )}
                  {narrative && (
                    <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 0 }}>
                      {[
                        { k: 'model',     v: aiModel || '—' },
                        { k: 'style',     v: narrativeStyle },
                        { k: 'words',     v: String(narrative.trim().split(/\s+/).length) },
                        { k: 'generated', v: narrativeSavedAt ? new Date(narrativeSavedAt).toLocaleString() : 'just now' },
                      ].map(row => (
                        <div key={row.k} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px dashed var(--rule)', padding: '3px 0' }}>
                          <span className="mono" style={{ fontSize: 9.5, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fg-3)' }}>{row.k}</span>
                          <span className="mono" style={{ fontSize: 10.5, color: 'var(--fg)', textAlign: 'right', marginLeft: 8, maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.v}</span>
                        </div>
                      ))}
                      <button
                        onClick={() => { navigator.clipboard.writeText(narrative); setPreviewTab('ai') }}
                        style={{ marginTop: 8, fontSize: 10, color: 'var(--fg-3)', background: 'none', border: ruleStrong, padding: '3px 8px', cursor: 'pointer', fontFamily: 'var(--font-mono)', alignSelf: 'flex-end' }}
                      >
                        View in AI tab
                      </button>
                    </div>
                  )}
                </div>
              )}

              {/* Loading indicator */}
              {loading && (
                <div style={{ marginTop: 8, fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', textAlign: 'center' }}>
                  loading findings…
                </div>
              )}
            </div>
          </Section>
        </div>

        {/* ── Right pane: preview ── */}
        <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          {/* Tab bar */}
          <div style={{ display: 'flex', borderBottom: '1px solid var(--rule)', flexShrink: 0 }}>
            {PREVIEW_TABS.map(t => (
              <button
                key={t.id}
                onClick={() => setPreviewTab(t.id)}
                className="mono"
                style={{
                  background: 'transparent', border: 'none',
                  color: previewTab === t.id ? 'var(--fg)' : 'var(--fg-3)',
                  fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.12em',
                  padding: '10px 14px', cursor: 'pointer',
                  borderBottom: previewTab === t.id ? '1px solid var(--accent)' : '1px solid transparent',
                  marginBottom: -1,
                }}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* Preview content */}
          <div style={{ flex: 1, overflowY: 'auto', background: 'var(--bg-2)' }}>
            <div style={{
              maxWidth: 760, margin: '0 auto', padding: '48px 64px',
              background: 'var(--bg)', boxShadow: '0 0 0 1px var(--rule)',
              borderLeft: '1px solid var(--rule)', borderRight: '1px solid var(--rule)',
              minHeight: '100%',
            }}>
              {previewTab === 'exec' && <ExecReport auditor={auditor} findings={findings} project={selectedProj ?? null} />}
              {previewTab === 'tech' && <TechReport findings={findings} />}
              {previewTab === 'findings' && <FindingsMatrix findings={displayFindings} />}
              {previewTab === 'evid' && <EvidencePreview projectId={projectId} />}
              {previewTab === 'report' && (
                localReport
                  ? <div style={{ fontFamily: 'var(--font-serif)', fontSize: 14.5, lineHeight: 1.75, color: 'var(--fg)' }}>
                      <ReactMarkdown
                        remarkPlugins={[remarkGfm]}
                        components={{
                          h1: ({ children }) => <h1 style={{ fontFamily: 'var(--font-serif)', fontWeight: 500, fontSize: 32, letterSpacing: '-0.01em', margin: '0 0 8px' }}>{children}</h1>,
                          h2: ({ children }) => <h2 style={{ fontFamily: 'var(--font-mono)', fontSize: 12, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--accent)', margin: '32px 0 12px', fontWeight: 500 }}>{children}</h2>,
                          h3: ({ children }) => <h3 style={{ fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'var(--fg-2)', margin: '20px 0 8px', fontWeight: 500 }}>{children}</h3>,
                          p: ({ children }) => <p style={{ margin: '0 0 12px', fontSize: 14.5, lineHeight: 1.75 }}>{children}</p>,
                          table: ({ children }) => <table style={{ width: '100%', borderCollapse: 'collapse', margin: '12px 0', fontSize: 13 }}>{children}</table>,
                          th: ({ children }) => <th style={{ textAlign: 'left', padding: '6px 10px', borderBottom: '1px solid var(--rule-strong)', fontFamily: 'var(--font-mono)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fg-3)' }}>{children}</th>,
                          td: ({ children }) => <td style={{ padding: '6px 10px', borderBottom: '1px solid var(--rule)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{children}</td>,
                          ol: ({ children }) => <ol style={{ paddingLeft: 20, margin: '0 0 12px' }}>{children}</ol>,
                          li: ({ children }) => <li style={{ margin: '4px 0', fontSize: 14.5, lineHeight: 1.65 }}>{children}</li>,
                          hr: () => <hr style={{ border: 'none', borderTop: '1px solid var(--rule)', margin: '24px 0' }} />,
                          strong: ({ children }) => <strong style={{ fontWeight: 600 }}>{children}</strong>,
                          em: ({ children }) => <em style={{ color: 'var(--fg-3)', fontStyle: 'italic' }}>{children}</em>,
                        }}
                      >
                        {localReport}
                      </ReactMarkdown>
                    </div>
                  : <div style={{ textAlign: 'center', color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', fontSize: 12, paddingTop: 40 }}>No report generated yet — click "Generate narrative" in the sidebar.</div>
              )}
              {previewTab === 'ai' && (
                narrative
                  ? <div style={{ fontFamily: 'var(--font-serif)', fontSize: 14.5, lineHeight: 1.75, color: 'var(--fg)' }}>
                      <ReactMarkdown
                        remarkPlugins={[remarkGfm]}
                        components={{
                          h1: ({ children }) => <h1 style={{ fontFamily: 'var(--font-serif)', fontWeight: 500, fontSize: 30, margin: '0 0 8px' }}>{children}</h1>,
                          h2: ({ children }) => <h2 style={{ fontFamily: 'var(--font-mono)', fontSize: 12, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--accent)', margin: '28px 0 10px', fontWeight: 500 }}>{children}</h2>,
                          h3: ({ children }) => <h3 style={{ fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'var(--fg-2)', margin: '18px 0 6px', fontWeight: 500 }}>{children}</h3>,
                          p: ({ children }) => <p style={{ margin: '0 0 12px', fontSize: 14.5, lineHeight: 1.75 }}>{children}</p>,
                          ul: ({ children }) => <ul style={{ paddingLeft: 20, margin: '0 0 12px' }}>{children}</ul>,
                          ol: ({ children }) => <ol style={{ paddingLeft: 20, margin: '0 0 12px' }}>{children}</ol>,
                          li: ({ children }) => <li style={{ margin: '4px 0', fontSize: 14.5, lineHeight: 1.65 }}>{children}</li>,
                          table: ({ children }) => <table style={{ width: '100%', borderCollapse: 'collapse', margin: '12px 0', fontSize: 13 }}>{children}</table>,
                          th: ({ children }) => <th style={{ textAlign: 'left', padding: '6px 10px', borderBottom: '1px solid var(--rule-strong)', fontFamily: 'var(--font-mono)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--fg-3)' }}>{children}</th>,
                          td: ({ children }) => <td style={{ padding: '6px 10px', borderBottom: '1px solid var(--rule)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>{children}</td>,
                          hr: () => <hr style={{ border: 'none', borderTop: '1px solid var(--rule)', margin: '24px 0' }} />,
                          strong: ({ children }) => <strong style={{ fontWeight: 600 }}>{children}</strong>,
                          code: ({ children }) => <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent)', background: 'var(--bg-3)', padding: '1px 4px' }}>{children}</code>,
                        }}
                      >
                        {narrative}
                      </ReactMarkdown>
                    </div>
                  : <div style={{ textAlign: 'center', color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', fontSize: 12, paddingTop: 40 }}>No AI narrative yet — select a model and click "AI Interpretation".</div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
