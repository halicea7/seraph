import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import Icon from '../components/Icon'
import EmptyState from '../components/EmptyState'
import FindingsTable from '../components/FindingsTable'
import { getTargets } from '../api/client'
import type { TargetSummary, ScanCategory, Finding } from '../types'
import { useAppStore } from '@/stores/appStore'
import { useToast } from '@/contexts/ToastContext'
import { getApiBase, wsUrl } from '@/lib/config'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Profile {
  id: string
  name: string
  description: string
  scan_categories: Array<{ category_id: string; config: Record<string, unknown> }>
  schedule: string | null
}

interface CoverageControl { control_id: string; worst_severity: string; count: number }
interface CoverageFramework {
  framework: string
  controls_touched: number
  severity_counts: Record<string, number>
  controls: CoverageControl[]
}
interface Coverage { project_id: string; total_findings: number; frameworks: CoverageFramework[] }

type TermLine = { kind: 'prompt' | 'stdout' | 'stderr' | 'ok'; text: string }
type RunState = 'idle' | 'running' | 'done'

const REMOTE_CATEGORIES = new Set(['host_hardening', 'openscap', 'log_monitoring'])

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)',
  low: 'var(--low)', info: 'var(--fg-3)',
}

const rule = '1px solid var(--rule)'
const fieldLabel: React.CSSProperties = {
  display: 'block', fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)',
  textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5,
}
const inputStyle: React.CSSProperties = {
  width: '100%', background: 'var(--bg)', border: rule, color: 'var(--fg)',
  fontFamily: 'var(--font-mono)', fontSize: 12, padding: '6px 9px', borderRadius: 3,
}

// ── Section wrapper ─────────────────────────────────────────────────────────────

function Section({ n, title, hint, children }: { n: number; title: string; hint?: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 22 }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginBottom: 12 }}>
        <span className="mono" style={{ fontSize: 11, color: 'var(--accent)', border: '1px solid var(--accent)', borderRadius: 3, padding: '1px 7px' }}>{n}</span>
        <h2 className="sec-h" style={{ margin: 0, fontSize: 15 }}>{title}</h2>
        {hint && <span style={{ fontSize: 11, color: 'var(--fg-4)' }}>{hint}</span>}
      </div>
      {children}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AuditBuilder() {
  const { selectedProject: sp } = useAppStore()
  const projectId = sp?.id ?? ''
  const { show: toast } = useToast()
  const navigate = useNavigate()

  // Setup / catalog
  const [targets, setTargets] = useState<TargetSummary[]>([])
  const [selectedTarget, setSelectedTarget] = useState('')
  const [categories, setCategories] = useState<Record<string, ScanCategory>>({})
  const [toolStatus, setToolStatus] = useState<Record<string, { available: boolean }>>({})
  const [sshCredentials, setSshCredentials] = useState<Array<{ id: string; username: string; target_host: string; notes: string }>>([])
  const [selectedCredentialId, setSelectedCredentialId] = useState('')
  const [showAddKey, setShowAddKey] = useState(false)
  const [newKey, setNewKey] = useState({ username: '', target_host: '', secret: '' })
  const [savingKey, setSavingKey] = useState(false)

  // Selection
  const [selectedCategories, setSelectedCategories] = useState<Set<string>>(new Set())
  const [categoryConfigs, setCategoryConfigs] = useState<Record<string, Record<string, unknown>>>({})

  // Generate / run
  const [scanId, setScanId] = useState<string | null>(null)
  const [generatedScript, setGeneratedScript] = useState('')
  const [generating, setGenerating] = useState(false)
  const [runState, setRunState] = useState<RunState>('idle')
  const [termLines, setTermLines] = useState<TermLine[]>([])
  const wsRef = useRef<WebSocket | null>(null)
  const termEndRef = useRef<HTMLDivElement | null>(null)
  const retestRef = useRef<{ findingId: string; title: string } | null>(null)

  // Results
  const [findings, setFindings] = useState<Finding[]>([])
  const [loadingFindings, setLoadingFindings] = useState(false)
  const [coverage, setCoverage] = useState<Coverage | null>(null)

  // Scoring (lynis / hardening only)
  const [hardeningProfiles, setHardeningProfiles] = useState<Array<{ id: string; name: string }>>([])
  const [selectedHardeningProfile, setSelectedHardeningProfile] = useState('cis_l1')
  const [complianceReport, setComplianceReport] = useState<Record<string, unknown> | null>(null)
  const [scoring, setScoring] = useState(false)
  const [scoreError, setScoreError] = useState('')

  // Reuse / automation
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [profileName, setProfileName] = useState('')
  const [savingProfile, setSavingProfile] = useState(false)

  // Offline import
  const [showImport, setShowImport] = useState(false)
  const [ciscatTargetId, setCiscatTargetId] = useState('')
  const [ciscatImporting, setCiscatImporting] = useState(false)

  const needsSSH = [...selectedCategories].some(c => REMOTE_CATEGORIES.has(c))
  const ranHardening = [...selectedCategories].some(c => REMOTE_CATEGORIES.has(c) && c === 'host_hardening')

  // ── Loaders ───────────────────────────────────────────────────────────────────
  const loadFindings = useCallback(async () => {
    if (!projectId) return
    setLoadingFindings(true)
    try {
      // Deduped + SLA-annotated view of this project's scan findings.
      const r = await fetch(`${getApiBase()}/findings/grouped?project_id=${projectId}`)
      setFindings(r.ok ? (await r.json()).findings ?? [] : [])
    } catch { /* ignore */ } finally { setLoadingFindings(false) }
  }, [projectId])

  const loadCoverage = useCallback(async () => {
    if (!projectId) return
    try {
      const r = await fetch(`${getApiBase()}/audit/coverage?project_id=${projectId}`)
      if (r.ok) setCoverage(await r.json())
    } catch { /* ignore */ }
  }, [projectId])

  const loadKeys = useCallback(() => {
    if (!projectId) return
    fetch(`${getApiBase()}/credentials/keys?project_id=${projectId}`).then(r => r.ok ? r.json() : []).then(setSshCredentials).catch(() => {})
  }, [projectId])

  async function addSshKey() {
    if (!projectId || !newKey.secret.trim()) { toast('Paste or load a private key first', 'error'); return }
    setSavingKey(true)
    try {
      const r = await fetch(`${getApiBase()}/credentials`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_id: projectId, cred_type: 'key', source: 'manual', username: newKey.username, target_host: newKey.target_host, secret: newKey.secret, notes: 'Added from Audit Builder' }),
      })
      if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || 'failed') }
      const created = await r.json()
      setNewKey({ username: '', target_host: '', secret: '' }); setShowAddKey(false)
      loadKeys()
      if (created?.id) setSelectedCredentialId(created.id)
      toast('SSH key added', 'success')
    } catch (e) { toast(e instanceof Error ? e.message : 'Failed to add key', 'error') }
    finally { setSavingKey(false) }
  }

  useEffect(() => {
    fetch(`${getApiBase()}/audit/categories`).then(r => r.json()).then((data: Record<string, ScanCategory>) => {
      setCategories(data)
      const defaults: Record<string, Record<string, unknown>> = {}
      for (const [id, cat] of Object.entries(data)) {
        defaults[id] = {}
        for (const [key, schema] of Object.entries(cat.config_schema)) defaults[id][key] = schema.default ?? ''
      }
      setCategoryConfigs(defaults)
    }).catch(() => {})
    fetch(`${getApiBase()}/settings/tools`).then(r => r.json()).then(setToolStatus).catch(() => {})
    fetch(`${getApiBase()}/hardening/profiles`).then(r => r.ok ? r.json() : []).then(setHardeningProfiles).catch(() => {})
    return () => { wsRef.current?.close() }
  }, [])

  useEffect(() => {
    if (!projectId) return
    getTargets(projectId).then(data => {
      setTargets(data)
      if (data.length) { setSelectedTarget(data[0].id); setCiscatTargetId(data[0].id) }
    }).catch(() => {})
    loadKeys()
    fetch(`${getApiBase()}/profiles`).then(r => r.ok ? r.json() : []).then((data: Profile[]) => {
      setProfiles(data.map(p => ({ ...p, scan_categories: typeof p.scan_categories === 'string' ? JSON.parse(p.scan_categories as unknown as string) : p.scan_categories })))
    }).catch(() => {})
    loadFindings()
    loadCoverage()
  }, [projectId, loadFindings, loadCoverage, loadKeys])

  useEffect(() => { termEndRef.current?.scrollIntoView({ block: 'end' }) }, [termLines])

  // ── Selection helpers ───────────────────────────────────────────────────────
  function toggleCategory(id: string) {
    setSelectedCategories(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
    // selection changed → previous script is stale
    setGeneratedScript(''); setScanId(null); setRunState('idle'); setTermLines([])
  }

  function setCfg(catId: string, key: string, val: unknown) {
    setCategoryConfigs(prev => ({ ...prev, [catId]: { ...prev[catId], [key]: val } }))
  }

  // ── Generate ────────────────────────────────────────────────────────────────
  async function handleGenerate() {
    if (!projectId || !selectedTarget || selectedCategories.size === 0) {
      toast('Select a target and at least one check first', 'error'); return
    }
    if (needsSSH && !selectedCredentialId) {
      toast('Selected checks run over SSH — pick a credential', 'error'); return
    }
    setGenerating(true)
    try {
      const scan_categories = [...selectedCategories].map(id => ({ category_id: id, config: categoryConfigs[id] || {} }))
      const res = await fetch(`${getApiBase()}/audit/generate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_id: projectId, target_id: selectedTarget, scan_categories, credential_id: needsSSH ? selectedCredentialId : null }),
      })
      if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.detail ?? `HTTP ${res.status}`) }
      const data = await res.json()
      setGeneratedScript(data.script); setScanId(data.scan_id)
      setRunState('idle'); setTermLines([]); setComplianceReport(null)
    } catch (e) { toast(e instanceof Error ? e.message : 'Generation failed', 'error') }
    finally { setGenerating(false) }
  }

  // ── Run (live, over /ws/execute — backend auto-parses to findings on exit) ────
  function runScan(sid: string, script: string) {
    wsRef.current?.close()
    setRunState('running'); setTermLines([{ kind: 'prompt', text: `executing audit ${sid.slice(0, 8)} against target…` }])
    const ws = new WebSocket(wsUrl(`/ws/execute/${sid}`))
    wsRef.current = ws
    ws.onopen = () => ws.send(JSON.stringify({ action: 'run', script }))
    ws.onmessage = ev => {
      const msg = JSON.parse(ev.data) as { type: string; data?: string; code?: number }
      if (msg.type === 'stdout') setTermLines(p => [...p, { kind: 'stdout', text: msg.data ?? '' }])
      else if (msg.type === 'stderr') setTermLines(p => [...p, { kind: 'stderr', text: msg.data ?? '' }])
      else if (msg.type === 'error') setTermLines(p => [...p, { kind: 'stderr', text: msg.data ?? 'error' }])
      else if (msg.type === 'exit') {
        setRunState('done')
        setTermLines(p => [...p, { kind: msg.code === 0 ? 'ok' : 'stderr', text: `exit ${msg.code ?? 0}` }])
        loadFindings(); loadCoverage()
        const retest = retestRef.current
        if (retest) {
          retestRef.current = null
          ;(async () => {
            try {
              const er = await fetch(`${getApiBase()}/findings/${retest.findingId}/retest/evaluate`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scan_id: sid }),
              })
              const ev2 = await er.json()
              toast(ev2.still_present
                ? `Retest: “${retest.title}” still present`
                : `Retest: “${retest.title}” not found — marked remediated`,
                ev2.still_present ? 'info' : 'success')
              loadFindings()
            } catch { toast('Retest evaluation failed', 'error') }
          })()
        } else {
          toast(msg.code === 0 ? 'Audit complete — findings updated' : `Audit exited ${msg.code}`, msg.code === 0 ? 'success' : 'info')
        }
      }
    }
    ws.onerror = () => { setTermLines(p => [...p, { kind: 'stderr', text: '[websocket error]' }]); setRunState('done') }
    ws.onclose = () => setRunState(s => (s === 'running' ? 'done' : s))
  }

  function handleRun() {
    if (!scanId || !generatedScript) return
    retestRef.current = null
    runScan(scanId, generatedScript)
  }

  async function handleRetest(finding: Finding) {
    try {
      const r = await fetch(`${getApiBase()}/findings/${finding.id}/retest`, { method: 'POST' })
      const d = await r.json()
      if (!r.ok) throw new Error(d.detail || 'Retest not available for this finding')
      retestRef.current = { findingId: finding.id, title: finding.title }
      setGeneratedScript(d.script); setScanId(d.scan_id); setComplianceReport(null)
      toast(`Re-running the check for “${finding.title}”…`, 'info')
      runScan(d.scan_id, d.script)
    } catch (e) { toast(e instanceof Error ? e.message : 'Retest failed', 'error') }
  }

  function stopRun() { wsRef.current?.close(); setRunState('done') }

  // ── Offline: download + import ────────────────────────────────────────────────
  async function handleDownload() {
    if (!scanId) return
    const res = await fetch(`${getApiBase()}/audit/script/${scanId}/download`)
    const blob = await res.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `seraph_audit_${scanId.slice(0, 8)}.sh`
    a.click(); URL.revokeObjectURL(a.href)
  }

  function handleImportResults() {
    const input = document.createElement('input')
    input.type = 'file'; input.accept = '.json,.jsonl'
    input.onchange = async e => {
      const file = (e.target as HTMLInputElement).files?.[0]
      if (!file || !projectId) return
      const fd = new FormData(); fd.append('file', file); fd.append('project_id', projectId)
      try {
        const r = await fetch(`${getApiBase()}/audit/import`, { method: 'POST', body: fd })
        if (!r.ok) throw new Error('import failed')
        toast('Results imported', 'success'); loadFindings(); loadCoverage()
      } catch { toast('Import failed', 'error') }
    }
    input.click()
  }

  async function handleCiscatImport(file: File) {
    if (!projectId || !ciscatTargetId) { toast('Pick a target for the CIS-CAT import', 'error'); return }
    setCiscatImporting(true)
    try {
      const fd = new FormData(); fd.append('file', file); fd.append('project_id', projectId); fd.append('target_id', ciscatTargetId)
      const r = await fetch(`${getApiBase()}/audit/import/ciscat`, { method: 'POST', body: fd })
      if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(e.detail || 'import failed') }
      const d = await r.json()
      toast(`CIS-CAT: ${d.imported} imported (${d.fail} fail / ${d.pass} pass)`, 'success')
      loadFindings(); loadCoverage()
    } catch (e) { toast(e instanceof Error ? e.message : 'CIS-CAT import failed', 'error') }
    finally { setCiscatImporting(false) }
  }

  // ── Score (hardening / lynis only) ────────────────────────────────────────────
  async function handleScoreScan() {
    if (!scanId || !projectId) return
    setScoring(true); setScoreError('')
    try {
      const res = await fetch(`${getApiBase()}/hardening/score`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: scanId, profile_id: selectedHardeningProfile, project_id: projectId }),
      })
      if (!res.ok) { const e = await res.json().catch(() => ({})); setScoreError(e.detail || 'Scoring failed'); return }
      setComplianceReport(await res.json())
    } catch (e) { setScoreError(e instanceof Error ? e.message : 'Scoring failed') }
    finally { setScoring(false) }
  }

  // ── Profiles ──────────────────────────────────────────────────────────────────
  async function handleSaveProfile() {
    if (!profileName.trim() || selectedCategories.size === 0) return
    setSavingProfile(true)
    try {
      await fetch(`${getApiBase()}/profiles`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: profileName.trim(),
          description: `Audit Builder — ${[...selectedCategories].join(', ')}`,
          scan_categories: [...selectedCategories].map(id => ({ category_id: id, config: categoryConfigs[id] || {} })),
        }),
      })
      setProfileName('')
      const r = await fetch(`${getApiBase()}/profiles`); if (r.ok) setProfiles(await r.json())
      toast('Profile saved', 'success')
    } catch { toast('Save failed', 'error') } finally { setSavingProfile(false) }
  }

  function applyProfile(p: Profile) {
    const next = new Set<string>(); const cfgs = { ...categoryConfigs }
    for (const c of p.scan_categories) { next.add(c.category_id); cfgs[c.category_id] = { ...cfgs[c.category_id], ...c.config } }
    setSelectedCategories(next); setCategoryConfigs(cfgs)
    setGeneratedScript(''); setScanId(null)
    toast(`Loaded profile “${p.name}”`, 'success')
  }

  // ── Render ────────────────────────────────────────────────────────────────────
  if (!projectId) {
    return (
      <div style={{ padding: '24px 28px' }}>
        <h1 className="sec-h" style={{ margin: '0 0 16px' }}>Audit Builder</h1>
        <EmptyState icon="shield" title="No project selected" hint="Pick an engagement to build and run a compliance audit." />
      </div>
    )
  }

  const catList = Object.values(categories)

  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden' }}>
      {/* Main workflow column */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '22px 26px', minWidth: 0 }}>
        <div style={{ marginBottom: 22 }}>
          <div className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)', marginBottom: 4 }}>Defense</div>
          <h1 className="sec-h" style={{ margin: 0 }}>Audit Builder</h1>
          <p style={{ fontSize: 12, color: 'var(--fg-3)', marginTop: 4 }}>
            Pick compliance checks → generate a script → run it live → review findings, score, and report.
          </p>
        </div>

        {/* 1 · Target */}
        <Section n={1} title="Target">
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <div style={{ minWidth: 240 }}>
              <label style={fieldLabel}>Host / target</label>
              <select style={inputStyle} value={selectedTarget} onChange={e => setSelectedTarget(e.target.value)}>
                {targets.length === 0 && <option value="">— no targets in project —</option>}
                {targets.map(t => <option key={t.id} value={t.id}>{t.hostname_or_ip}</option>)}
              </select>
            </div>
            {needsSSH && (
              <div style={{ minWidth: 260 }}>
                <label style={fieldLabel}>SSH credential (remote checks)</label>
                <div style={{ display: 'flex', gap: 6 }}>
                  <select style={{ ...inputStyle, borderColor: selectedCredentialId ? 'var(--rule)' : 'var(--high)' }} value={selectedCredentialId} onChange={e => setSelectedCredentialId(e.target.value)}>
                    <option value="">{sshCredentials.length ? '— select key —' : '— no SSH keys yet —'}</option>
                    {sshCredentials.map(c => <option key={c.id} value={c.id}>{c.username}@{c.target_host || '?'} {c.notes ? `(${c.notes})` : ''}</option>)}
                  </select>
                  <button className="btn btn-sm" onClick={() => setShowAddKey(s => !s)} title="Add an SSH key" style={{ flexShrink: 0 }}>
                    <Icon name={showAddKey ? 'x' : 'plus'} size={12} />
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Inline "drop your key here" — adds an encrypted SSH key credential */}
          {needsSSH && showAddKey && (
            <div style={{ marginTop: 12, border: rule, borderLeft: '3px solid var(--accent)', borderRadius: 3, padding: 12, background: 'var(--bg-2)', maxWidth: 560 }}>
              <div className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)', marginBottom: 8 }}>Add SSH key</div>
              <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                <input style={{ ...inputStyle, flex: 1 }} placeholder="username (e.g. root)" value={newKey.username} onChange={e => setNewKey(k => ({ ...k, username: e.target.value }))} />
                <input style={{ ...inputStyle, flex: 1 }} placeholder="target host (optional)" value={newKey.target_host} onChange={e => setNewKey(k => ({ ...k, target_host: e.target.value }))} />
              </div>
              <textarea
                value={newKey.secret}
                onChange={e => setNewKey(k => ({ ...k, secret: e.target.value }))}
                rows={5}
                placeholder={'-----BEGIN OPENSSH PRIVATE KEY-----\n…paste the private key, or load from file…\n-----END OPENSSH PRIVATE KEY-----'}
                style={{ ...inputStyle, fontFamily: 'var(--font-mono)', fontSize: 11, resize: 'vertical' }}
              />
              <div style={{ display: 'flex', gap: 8, marginTop: 8, alignItems: 'center' }}>
                <label className="btn btn-sm" style={{ cursor: 'pointer', display: 'inline-flex', alignItems: 'center' }}>
                  <Icon name="upload" size={11} style={{ marginRight: 5 }} /> Load from file
                  <input type="file" accept=".pem,.key,.ppk,.txt,id_rsa,id_ed25519" style={{ display: 'none' }}
                    onChange={async e => { const f = e.target.files?.[0]; if (f) { const text = await f.text(); setNewKey(k => ({ ...k, secret: text })) } }} />
                </label>
                <button className="btn btn-primary btn-sm" onClick={addSshKey} disabled={savingKey || !newKey.secret.trim()}>{savingKey ? 'Saving…' : 'Save key'}</button>
                <span style={{ fontSize: 10.5, color: 'var(--fg-4)' }}>Stored encrypted in the Credential Vault.</span>
              </div>
            </div>
          )}
        </Section>

        {/* 2 · Checks */}
        <Section n={2} title="Checks" hint={`${selectedCategories.size} selected`}>
          {catList.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--fg-4)' }}>Loading check catalog…</div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
              {catList.map(cat => {
                const sel = selectedCategories.has(cat.id)
                const remote = REMOTE_CATEGORIES.has(cat.id)
                const missingTools = cat.tools.filter(t => toolStatus[t] && !toolStatus[t].available)
                return (
                  <div key={cat.id} style={{ border: `1px solid ${sel ? 'var(--accent)' : 'var(--rule)'}`, borderRadius: 4, background: sel ? 'var(--accent-2)' : 'var(--bg-2)', overflow: 'hidden' }}>
                    <button onClick={() => toggleCategory(cat.id)} style={{ width: '100%', textAlign: 'left', background: 'transparent', border: 'none', cursor: 'pointer', padding: '11px 12px', display: 'flex', gap: 9, alignItems: 'flex-start' }}>
                      <Icon name={sel ? 'check' : 'plus'} size={13} color={sel ? 'var(--accent)' : 'var(--fg-3)'} style={{ marginTop: 2 }} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                          <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)' }}>{cat.name}</span>
                          {remote && <span className="mono" style={{ fontSize: 8.5, color: 'var(--high)', border: '1px solid var(--high)', borderRadius: 2, padding: '0 4px' }}>SSH</span>}
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--fg-3)', marginTop: 3, lineHeight: 1.4 }}>{cat.description}</div>
                        <div style={{ display: 'flex', gap: 5, marginTop: 6, flexWrap: 'wrap' }}>
                          {cat.tools.map(t => {
                            const avail = !toolStatus[t] || toolStatus[t].available
                            return <span key={t} className="mono" style={{ fontSize: 9, color: avail ? 'var(--fg-3)' : 'var(--crit)', border: `1px solid ${avail ? 'var(--rule)' : 'var(--crit)'}`, borderRadius: 2, padding: '0 5px' }}>{t}</span>
                          })}
                        </div>
                        {missingTools.length > 0 && <div style={{ fontSize: 10, color: 'var(--crit)', marginTop: 5 }}>missing: {missingTools.join(', ')} — install in Settings → Tools</div>}
                      </div>
                    </button>
                    {sel && Object.keys(cat.config_schema).length > 0 && (
                      <div style={{ borderTop: rule, padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 8 }}>
                        {Object.entries(cat.config_schema).map(([key, schema]) => {
                          const val = categoryConfigs[cat.id]?.[key]
                          return (
                            <div key={key}>
                              <label style={fieldLabel}>{key.replace(/_/g, ' ')}</label>
                              {schema.type === 'select' ? (
                                <select style={inputStyle} value={String(val ?? '')} onChange={e => setCfg(cat.id, key, e.target.value)}>
                                  {(schema.options ?? []).map(o => <option key={o} value={o}>{o}</option>)}
                                </select>
                              ) : schema.type === 'boolean' ? (
                                <label style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 12, color: 'var(--fg-2)', cursor: 'pointer' }}>
                                  <input type="checkbox" checked={!!val} onChange={e => setCfg(cat.id, key, e.target.checked)} /> enabled
                                </label>
                              ) : schema.type === 'multiselect' ? (
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                                  {(schema.options ?? []).map(o => {
                                    const arr = Array.isArray(val) ? (val as string[]) : []
                                    const on = arr.includes(o)
                                    return (
                                      <button key={o} onClick={() => setCfg(cat.id, key, on ? arr.filter(x => x !== o) : [...arr, o])}
                                        className="mono" style={{ fontSize: 10, cursor: 'pointer', padding: '2px 7px', borderRadius: 2, border: `1px solid ${on ? 'var(--accent)' : 'var(--rule)'}`, background: on ? 'var(--accent-2)' : 'transparent', color: on ? 'var(--accent)' : 'var(--fg-3)' }}>{o}</button>
                                    )
                                  })}
                                </div>
                              ) : (
                                <input style={inputStyle} value={String(val ?? '')} placeholder={schema.placeholder} onChange={e => setCfg(cat.id, key, e.target.value)} />
                              )}
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </Section>

        {/* 3 · Generate & Run */}
        <Section n={3} title="Generate & run">
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 12 }}>
            <button className="btn btn-primary" onClick={handleGenerate} disabled={generating || selectedCategories.size === 0} style={{ height: 32, padding: '0 16px', fontSize: 12 }}>
              <Icon name="cog" size={12} style={{ marginRight: 6 }} />{generating ? 'Generating…' : 'Generate script'}
            </button>
            {generatedScript && runState !== 'running' && (
              <button className="btn btn-primary" onClick={handleRun} style={{ height: 32, padding: '0 16px', fontSize: 12 }}>
                <Icon name="play" size={12} style={{ marginRight: 6 }} />Run audit
              </button>
            )}
            {runState === 'running' && (
              <button className="btn" onClick={stopRun} style={{ height: 32, padding: '0 14px', fontSize: 12 }}>
                <Icon name="stop" size={12} style={{ marginRight: 6 }} />Stop
              </button>
            )}
            {scanId && <button className="btn" onClick={handleDownload} style={{ height: 32, padding: '0 12px', fontSize: 12 }}><Icon name="download" size={12} style={{ marginRight: 6 }} />Download .sh</button>}
            <button className="btn" onClick={handleImportResults} style={{ height: 32, padding: '0 12px', fontSize: 12 }}><Icon name="upload" size={12} style={{ marginRight: 6 }} />Import results</button>
            <button className="btn" onClick={() => setShowImport(s => !s)} style={{ height: 32, padding: '0 12px', fontSize: 12 }}>CIS-CAT…</button>
          </div>

          {showImport && (
            <div style={{ border: rule, borderRadius: 3, padding: 12, marginBottom: 12, display: 'flex', gap: 10, alignItems: 'flex-end', flexWrap: 'wrap', background: 'var(--bg-2)' }}>
              <div><label style={fieldLabel}>CIS-CAT target</label>
                <select style={{ ...inputStyle, minWidth: 180 }} value={ciscatTargetId} onChange={e => setCiscatTargetId(e.target.value)}>
                  {targets.map(t => <option key={t.id} value={t.id}>{t.hostname_or_ip}</option>)}
                </select>
              </div>
              <label className="btn" style={{ height: 32, padding: '0 14px', fontSize: 12, cursor: 'pointer', display: 'inline-flex', alignItems: 'center' }}>
                {ciscatImporting ? 'Importing…' : 'Choose XML/JSON/CSV'}
                <input type="file" accept=".xml,.json,.csv" style={{ display: 'none' }} onChange={e => { const f = e.target.files?.[0]; if (f) handleCiscatImport(f) }} />
              </label>
              <span style={{ fontSize: 11, color: 'var(--fg-4)' }}>Import a CIS-CAT Assessor report run elsewhere.</span>
            </div>
          )}

          {generatedScript && (
            <pre className="mono" style={{ margin: '0 0 12px', padding: 12, background: 'var(--bg-term)', border: rule, borderRadius: 3, fontSize: 11, color: 'var(--fg-2)', maxHeight: 180, overflow: 'auto', whiteSpace: 'pre-wrap' }}>{generatedScript}</pre>
          )}

          {termLines.length > 0 && (
            <div style={{ border: rule, borderRadius: 3, background: 'var(--bg-term)', maxHeight: 320, overflow: 'auto', padding: 10 }}>
              {termLines.map((l, i) => (
                <div key={i} className="mono" style={{ fontSize: 11, whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: l.kind === 'stderr' ? 'var(--crit)' : l.kind === 'ok' ? 'var(--low)' : l.kind === 'prompt' ? 'var(--accent)' : 'var(--fg-2)' }}>{l.text}</div>
              ))}
              <div ref={termEndRef} />
            </div>
          )}
        </Section>

        {/* 4 · Results */}
        <Section n={4} title="Results">
          {ranHardening && scanId && (
            <div style={{ border: rule, borderLeft: '3px solid var(--accent)', borderRadius: 3, padding: 12, marginBottom: 14, background: 'var(--bg-2)' }}>
              <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end', flexWrap: 'wrap' }}>
                <div><label style={fieldLabel}>Hardening profile</label>
                  <select style={{ ...inputStyle, minWidth: 160 }} value={selectedHardeningProfile} onChange={e => setSelectedHardeningProfile(e.target.value)}>
                    {hardeningProfiles.length === 0
                      ? ['cis_l1', 'cis_l2', 'stig'].map(p => <option key={p} value={p}>{p}</option>)
                      : hardeningProfiles.map(p => <option key={p.id} value={p.id}>{p.name || p.id}</option>)}
                  </select>
                </div>
                <button className="btn btn-primary" onClick={handleScoreScan} disabled={scoring} style={{ height: 32, padding: '0 14px', fontSize: 12 }}>{scoring ? 'Scoring…' : 'Score lynis run'}</button>
                {scoreError && <span style={{ fontSize: 11, color: 'var(--crit)' }}>{scoreError}</span>}
              </div>
              {complianceReport && (
                <div style={{ marginTop: 12, display: 'flex', gap: 20, alignItems: 'center', flexWrap: 'wrap' }}>
                  <div><div style={{ fontSize: 26, fontWeight: 700, color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>{String((complianceReport as Record<string, unknown>).overall_score ?? '—')}</div><div className="smcap" style={{ fontSize: 9, color: 'var(--fg-3)' }}>score</div></div>
                  {'warnings' in complianceReport && <div style={{ fontSize: 12, color: 'var(--fg-2)' }}>{(complianceReport.warnings as unknown[])?.length ?? 0} warnings · {(complianceReport.suggestions as unknown[])?.length ?? 0} suggestions</div>}
                </div>
              )}
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <span className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)' }}>Findings ({findings.length})</span>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-sm" onClick={loadFindings}><Icon name="refresh" size={11} /></button>
              <button className="btn btn-sm" onClick={() => navigate('/reports')}><Icon name="file" size={11} style={{ marginRight: 5 }} />Report</button>
            </div>
          </div>
          {findings.length === 0 && !loadingFindings
            ? <EmptyState icon="flag" title="No findings yet" hint="Run a check above (or import results) to populate findings." pad={28} />
            : <FindingsTable findings={findings} loading={loadingFindings} onRetest={handleRetest} />}
        </Section>
      </div>

      {/* Right rail · coverage + profiles */}
      <div style={{ width: 320, flexShrink: 0, borderLeft: rule, overflowY: 'auto', padding: '22px 18px', background: 'var(--bg)' }}>
        <div className="sec-h" style={{ margin: '0 0 12px', fontSize: 13 }}>Framework coverage</div>
        {!coverage || coverage.frameworks.length === 0 ? (
          <EmptyState icon="shield" title="No coverage yet" hint="Findings get tagged to CIS / NIST / OWASP / PCI / MITRE as you run audits." pad={24} />
        ) : (
          coverage.frameworks.map(fw => (
            <div key={fw.framework} style={{ border: rule, borderRadius: 3, marginBottom: 10, overflow: 'hidden' }}>
              <div style={{ padding: '8px 10px', background: 'var(--bg-2)', borderBottom: rule }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--fg)', fontWeight: 600 }}>{fw.framework}</span>
                  <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>{fw.controls_touched} ctrl</span>
                </div>
                <div style={{ display: 'flex', gap: 5, marginTop: 6, flexWrap: 'wrap' }}>
                  {Object.entries(fw.severity_counts).map(([sev, n]) => (
                    <span key={sev} className="mono" style={{ fontSize: 9, color: SEV_COLOR[sev], border: `1px solid ${SEV_COLOR[sev]}`, borderRadius: 2, padding: '0 4px' }}>{sev[0].toUpperCase()}{n}</span>
                  ))}
                </div>
              </div>
              <div style={{ maxHeight: 160, overflow: 'auto' }}>
                {fw.controls.slice(0, 30).map(c => (
                  <div key={c.control_id} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, padding: '4px 10px', borderBottom: '1px solid var(--rule-2)' }}>
                    <span className="mono" style={{ fontSize: 10, color: 'var(--fg-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={c.control_id}>{c.control_id}</span>
                    <span className="mono" style={{ fontSize: 9, color: SEV_COLOR[c.worst_severity], flexShrink: 0 }}>{c.worst_severity} ·{c.count}</span>
                  </div>
                ))}
              </div>
            </div>
          ))
        )}

        {/* Profiles */}
        <div className="sec-h" style={{ margin: '18px 0 10px', fontSize: 13 }}>Profiles</div>
        <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
          <input style={{ ...inputStyle, fontSize: 11 }} placeholder="Save current selection as…" value={profileName} onChange={e => setProfileName(e.target.value)} />
          <button className="btn btn-sm" onClick={handleSaveProfile} disabled={savingProfile || !profileName.trim() || selectedCategories.size === 0}><Icon name="download" size={11} /></button>
        </div>
        {profiles.length === 0
          ? <div style={{ fontSize: 11, color: 'var(--fg-4)' }}>No saved profiles.</div>
          : profiles.map(p => (
            <button key={p.id} onClick={() => applyProfile(p)} title="Load this selection" style={{ width: '100%', textAlign: 'left', background: 'transparent', border: rule, borderRadius: 3, padding: '7px 9px', marginBottom: 5, cursor: 'pointer' }}>
              <div style={{ fontSize: 11.5, color: 'var(--fg)' }}>{p.name}</div>
              <div className="mono" style={{ fontSize: 9.5, color: 'var(--fg-4)' }}>{p.scan_categories?.length ?? 0} checks{p.schedule ? ` · cron ${p.schedule}` : ''}</div>
            </button>
          ))}
      </div>
    </div>
  )
}
