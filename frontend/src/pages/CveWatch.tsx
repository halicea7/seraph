import { useState, useEffect, useCallback } from 'react'
import Icon from '../components/Icon'
import EmptyState from '../components/EmptyState'
import { getApiBase } from '@/lib/config'
import { useAppStore } from '@/stores/appStore'
import { useToast } from '@/contexts/ToastContext'

// ── Types ─────────────────────────────────────────────────────────────────────

interface WatchedService {
  id: string
  target_id: string
  service_term: string
  last_checked: string | null
  known_cves: string[]
}

interface Target { id: string; hostname_or_ip: string; project_id: string }

interface CveFinding {
  id: string
  severity: string
  title: string
  description: string
  cve_id: string | null
  created_at: string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const rule = '1px solid var(--rule)'
const SEV_COLOR: Record<string, string> = {
  critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)', info: 'var(--fg-3)',
}

function ageOf(iso: string | null): string {
  if (!iso) return '—'
  const ms = Date.now() - new Date(iso).getTime()
  if (ms < 0) return '0h'
  const h = Math.floor(ms / 3_600_000)
  if (h < 24) return `${h}h`
  return `${Math.floor(h / 24)}d`
}

function PageHeader({ title, sub, right }: { title: string; sub: string; right?: React.ReactNode }) {
  return (
    <div style={{ borderBottom: rule, padding: '24px var(--pad) 18px', display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: 16, flexShrink: 0 }}>
      <div>
        <h1 className="mono" style={{ margin: 0, fontWeight: 500, fontSize: 22, letterSpacing: '-0.01em' }}>{title}</h1>
        <div style={{ color: 'var(--fg-3)', fontSize: 12, marginTop: 6 }}>{sub}</div>
      </div>
      {right && <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>{right}</div>}
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

// ── Main ──────────────────────────────────────────────────────────────────────

export default function CveWatch() {
  const { selectedProject: sp } = useAppStore()
  const projectId = sp?.id ?? ''
  const { show: toast } = useToast()

  const [targets, setTargets] = useState<Target[]>([])
  const [watched, setWatched] = useState<WatchedService[]>([])
  const [cveFindings, setCveFindings] = useState<CveFinding[]>([])
  const [loading, setLoading] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const [tab, setTab] = useState('All')

  // add-watch form
  const [newTerm, setNewTerm] = useState('')
  const [newTargetId, setNewTargetId] = useState('')

  const loadData = useCallback(async () => {
    if (!projectId) return
    setLoading(true)
    try {
      const [tRes, wRes, fRes] = await Promise.all([
        fetch(`${getApiBase()}/projects/${projectId}/targets`),
        fetch(`${getApiBase()}/cve-watch?project_id=${projectId}`),
        fetch(`${getApiBase()}/findings?project_id=${projectId}`),
      ])
      const tData: Target[] = tRes.ok ? await tRes.json() : []
      setTargets(tData)
      if (tData.length && !newTargetId) setNewTargetId(tData[0].id)
      setWatched(wRes.ok ? await wRes.json() : [])
      const fData: CveFinding[] = fRes.ok ? (await fRes.json()).filter((f: CveFinding) => f.cve_id) : []
      setCveFindings(fData)
    } finally { setLoading(false) }
  }, [projectId, newTargetId])

  useEffect(() => { loadData() }, [loadData])

  async function addWatched() {
    if (!newTerm.trim() || !newTargetId) { toast('Enter a service term and target', 'error'); return }
    const r = await fetch(`${getApiBase()}/cve-watch`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_id: newTargetId, service_term: newTerm.trim() }),
    })
    if (r.ok) { setNewTerm(''); toast('Now watching for CVEs', 'success'); loadData() }
    else toast('Failed to add watch', 'error')
  }

  async function deleteWatched(id: string) {
    await fetch(`${getApiBase()}/cve-watch/${id}`, { method: 'DELETE' })
    setWatched(w => w.filter(x => x.id !== id))
  }

  async function checkOne(id: string) {
    await fetch(`${getApiBase()}/cve-watch/${id}/check`, { method: 'POST' })
    toast('CVE check queued', 'info')
    setTimeout(loadData, 2500)
  }

  async function syncAll() {
    setSyncing(true)
    try {
      await fetch(`${getApiBase()}/cve-watch/check-all`, { method: 'POST' })
      toast('Checking all watched services against NVD…', 'info')
      setTimeout(loadData, 3000)
    } finally { setSyncing(false) }
  }

  const targetName = (id: string) => targets.find(t => t.id === id)?.hostname_or_ip ?? '—'

  // Real filters on real findings.
  const now = Date.now()
  const filtered = cveFindings.filter(f => {
    if (tab === 'Critical') return f.severity === 'critical'
    if (tab === 'High') return f.severity === 'high'
    if (tab === 'Last 24h') return f.created_at && (now - new Date(f.created_at).getTime()) < 86_400_000
    return true
  })

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg)', color: 'var(--fg)' }}>
      <PageHeader
        title="CVE Watch"
        sub="Watch service versions for newly-published CVEs (NVD). Discovered CVEs surface as findings."
        right={
          <button className="btn btn-primary" onClick={syncAll} disabled={syncing || watched.length === 0}>
            <Icon name="refresh" size={12} color="currentColor" />
            {syncing ? 'Syncing…' : 'Sync now'}
          </button>
        }
      />

      {!projectId ? (
        <EmptyState icon="eye" title="No project selected" hint="Pick an engagement to watch its services for CVEs." />
      ) : (
        <div style={{ flex: 1, overflowY: 'auto', display: 'flex', minHeight: 0 }}>
          {/* Watched services rail */}
          <div style={{ width: 320, flexShrink: 0, borderRight: rule, padding: '16px var(--pad)', overflowY: 'auto' }}>
            <div className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)', marginBottom: 10 }}>Watched services ({watched.length})</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 14 }}>
              <select value={newTargetId} onChange={e => setNewTargetId(e.target.value)} style={{ background: 'var(--bg)', border: rule, color: 'var(--fg)', fontFamily: 'var(--font-mono)', fontSize: 11, padding: '6px 8px' }}>
                {targets.length === 0 && <option value="">— no targets —</option>}
                {targets.map(t => <option key={t.id} value={t.id}>{t.hostname_or_ip}</option>)}
              </select>
              <div style={{ display: 'flex', gap: 6 }}>
                <input value={newTerm} onChange={e => setNewTerm(e.target.value)} onKeyDown={e => e.key === 'Enter' && addWatched()}
                  placeholder="e.g. Apache httpd 2.4.52" style={{ flex: 1, background: 'var(--bg)', border: rule, color: 'var(--fg)', fontFamily: 'var(--font-mono)', fontSize: 11, padding: '6px 8px' }} />
                <button className="btn btn-sm" onClick={addWatched}><Icon name="plus" size={11} /></button>
              </div>
            </div>

            {watched.length === 0 ? (
              <div style={{ fontSize: 11, color: 'var(--fg-4)' }}>Nothing watched yet. Add a service version above (often auto-populated by scans).</div>
            ) : watched.map(w => (
              <div key={w.id} style={{ border: rule, borderRadius: 3, padding: '8px 10px', marginBottom: 6 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                  <span className="mono" style={{ fontSize: 11.5, color: 'var(--fg)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={w.service_term}>{w.service_term}</span>
                  <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                    <button className="btn btn-sm" title="Check now" onClick={() => checkOne(w.id)} style={{ padding: '2px 5px' }}><Icon name="refresh" size={10} /></button>
                    <button title="Delete" onClick={() => deleteWatched(w.id)} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--fg-4)' }}><Icon name="trash" size={11} /></button>
                  </div>
                </div>
                <div className="mono" style={{ fontSize: 9.5, color: 'var(--fg-4)', marginTop: 3 }}>
                  {targetName(w.target_id)} · {w.known_cves.length} known CVE{w.known_cves.length !== 1 ? 's' : ''} · checked {ageOf(w.last_checked)} ago
                </div>
              </div>
            ))}
          </div>

          {/* Detected CVEs */}
          <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px var(--pad)', borderBottom: rule }}>
              <span className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)' }}>Detected CVEs ({filtered.length})</span>
              <SegBtns options={['All', 'Critical', 'High', 'Last 24h']} value={tab} onChange={setTab} />
            </div>
            {loading ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '80px 0' }}><Icon name="refresh" size={24} color="var(--accent)" /></div>
            ) : filtered.length === 0 ? (
              <EmptyState icon="eye" title="No CVEs detected" hint="CVEs found against watched services (or carrying a CVE id in scans) appear here." />
            ) : (
              <table className="data">
                <thead>
                  <tr>
                    <th style={{ width: 30 }}></th>
                    <th style={{ width: 160 }}>CVE</th>
                    <th style={{ width: 90 }}>Severity</th>
                    <th>Title</th>
                    <th style={{ width: 70 }}>Age</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(f => {
                    const c = SEV_COLOR[f.severity] ?? 'var(--fg-3)'
                    return (
                      <tr key={f.id}>
                        <td style={{ textAlign: 'center' }}><span style={{ display: 'inline-block', width: 10, height: 10, background: c }} /></td>
                        <td>{f.cve_id
                          ? <a href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" rel="noreferrer" className="mono" style={{ color: 'var(--accent)', fontSize: 12 }}>{f.cve_id}</a>
                          : <span className="mono" style={{ color: 'var(--fg-3)', fontSize: 12 }}>—</span>}</td>
                        <td><span className="mono" style={{ color: c, fontSize: 11, textTransform: 'uppercase' }}>{f.severity}</span></td>
                        <td style={{ fontSize: 13 }}>{f.title}</td>
                        <td><span className="mono" style={{ color: 'var(--fg-3)', fontSize: 11 }}>{ageOf(f.created_at)}</span></td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
