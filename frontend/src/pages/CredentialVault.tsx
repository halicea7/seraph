import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import Icon from '../components/Icon'
import type { Credential, CredType, CredSource } from '../types/index'
import { getApiBase } from '@/lib/config'
import { useAppStore } from '@/stores/appStore'
import { useToast } from '@/contexts/ToastContext'

const CRED_TYPES: CredType[] = ['password', 'hash', 'key', 'token', 'other']
const CRED_SOURCES: CredSource[] = ['manual', 'c2_loot', 'osint', 'brute_force']

const TYPE_STYLE: Record<CredType, { color: string; bg: string; border: string }> = {
  password: { color: 'var(--accent)', bg: 'rgba(240,168,58,0.08)',  border: 'rgba(240,168,58,0.25)' },
  hash:     { color: '#a855f7',      bg: 'rgba(168,85,247,0.08)',  border: 'rgba(168,85,247,0.25)' },
  key:      { color: 'var(--accent)', bg: 'rgba(240,168,58,0.08)', border: 'rgba(240,168,58,0.25)' },
  token:    { color: 'var(--med)',   bg: 'rgba(240,168,58,0.06)',  border: 'rgba(240,168,58,0.15)' },
  other:    { color: 'var(--fg-3)', bg: 'rgba(100,116,139,0.08)', border: 'rgba(100,116,139,0.2)' },
}

const SOURCE_COLOR: Record<CredSource, string> = {
  manual:      'var(--fg-3)',
  c2_loot:     'var(--crit)',
  osint:       'var(--accent)',
  brute_force: '#f97316',
}

const SOURCE_LABELS: Record<CredSource, string> = {
  manual:      'Manual',
  c2_loot:     'C2 Loot',
  osint:       'OSINT',
  brute_force: 'Brute Force',
}

const EMPTY_FORM = {
  username: '',
  secret: '',
  cred_type: 'password' as CredType,
  source: 'manual' as CredSource,
  target_host: '',
  notes: '',
}

const rule = '1px solid var(--rule)'

function KPICell({
  label, value, sub, accentVar, divider,
}: {
  label: string; value: number | string; sub?: string; accentVar?: string; divider?: boolean
}) {
  const color = accentVar ? `var(${accentVar})` : 'var(--fg)'
  return (
    <div style={{ padding: '18px var(--pad)', borderLeft: divider ? rule : 'none' }}>
      <div className="smcap">{label}</div>
      <div className="mono tnum" style={{ fontSize: 32, color, marginTop: 6, lineHeight: 1, letterSpacing: '-0.02em', fontWeight: 500 }}>
        {String(value).padStart(2, '0')}
      </div>
      {sub && <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', marginTop: 8, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{sub}</div>}
    </div>
  )
}

function TypePill({ type }: { type: CredType }) {
  const s = TYPE_STYLE[type]
  return (
    <span style={{
      fontSize: 9, padding: '2px 7px', fontWeight: 700, textTransform: 'uppercase',
      letterSpacing: '0.08em', fontFamily: 'var(--font-mono)',
      color: s.color, background: s.bg, border: `1px solid ${s.border}`,
    }}>{type}</span>
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

export default function CredentialVault() {
  const { selectedProject: sp } = useAppStore()
  const projectId = sp?.id ?? ''
  const toast = useToast()
  const navigate = useNavigate()
  const importInputRef = useRef<HTMLInputElement>(null)
  const [credentials, setCredentials] = useState<Credential[]>([])
  const [showModal, setShowModal] = useState(false)
  const [form, setForm] = useState(EMPTY_FORM)
  const [saving, setSaving] = useState(false)
  const [revealedIds, setRevealedIds] = useState<Set<string>>(new Set())
  // Secrets are never in `credentials` — fetched on demand via /reveal(-batch) and cached here.
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, string>>({})
  const [copied, setCopied] = useState<string | null>(null)
  const [filterType, setFilterType] = useState<string>('all')
  const [filterSource, setFilterSource] = useState<string>('all')
  const [search, setSearch] = useState('')

  useEffect(() => {
    loadCredentials()
  }, [projectId])

  async function loadCredentials() {
    const url = projectId
      ? `${getApiBase()}/credentials?project_id=${projectId}`
      : `${getApiBase()}/credentials`
    const res = await fetch(url)
    setCredentials(await res.json())
  }

  async function handleSave() {
    if (!projectId) return
    setSaving(true)
    await fetch(`${getApiBase()}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...form, project_id: projectId }),
    })
    setSaving(false)
    setShowModal(false)
    setForm(EMPTY_FORM)
    loadCredentials()
  }

  async function handleDelete(id: string) {
    await fetch(`${getApiBase()}/credentials/${id}`, { method: 'DELETE' })
    setCredentials(prev => prev.filter(c => c.id !== id))
  }

  // Import a hash file — one hash per line (raw hash kept intact, NTLM colons preserved).
  async function handleImportHashes(file: File) {
    if (!projectId) { toast.error('Select a project before importing'); return }
    const text = await file.text()
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean)
    if (lines.length === 0) { toast.error('No hashes found in file'); return }
    let created = 0
    for (const secret of lines) {
      const res = await fetch(`${getApiBase()}/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: '', secret, cred_type: 'hash', source: 'manual',
          target_host: '', notes: `Imported from ${file.name}`, project_id: projectId,
        }),
      })
      if (res.ok) created++
    }
    toast.success(`Imported ${created} hash${created !== 1 ? 'es' : ''}`)
    loadCredentials()
  }

  // Export stored hashes as a plain hashcat input file (one hash per line).
  // Secrets aren't on `credentials` any more — fetch them via the audited
  // batch-reveal endpoint right before export.
  async function handleExportHashcat() {
    const hashes = credentials.filter(c => c.cred_type === 'hash' && c.has_secret)
    if (hashes.length === 0) { toast.error('No hashes to export'); return }
    const res = await fetch(`${getApiBase()}/credentials/reveal-batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: hashes.map(c => c.id) }),
    })
    const revealed: { id: string; secret: string }[] = await res.json()
    const blob = new Blob([revealed.map(r => r.secret).join('\n') + '\n'], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `hashes-${sp?.name ?? 'all'}.txt`
    a.click()
    URL.revokeObjectURL(url)
    toast.success(`Exported ${revealed.length} hash${revealed.length !== 1 ? 'es' : ''}`)
  }

  // Hand off stored hashes to the Password Auditing page, pre-selected for cracking.
  function handleSendToCracking() {
    const credIds = credentials.filter(c => c.cred_type === 'hash').map(c => c.id)
    if (credIds.length === 0) { toast.error('No hashes to crack'); return }
    navigate('/cracking', { state: { credIds } })
  }

  async function fetchSecret(id: string): Promise<string> {
    if (revealedSecrets[id] !== undefined) return revealedSecrets[id]
    const res = await fetch(`${getApiBase()}/credentials/${id}/reveal`, { method: 'POST' })
    const data = await res.json()
    setRevealedSecrets(prev => ({ ...prev, [id]: data.secret ?? '' }))
    return data.secret ?? ''
  }

  async function toggleReveal(id: string) {
    if (revealedIds.has(id)) {
      setRevealedIds(prev => { const next = new Set(prev); next.delete(id); return next })
      return
    }
    await fetchSecret(id)
    setRevealedIds(prev => new Set(prev).add(id))
  }

  async function copySecret(id: string, key: string) {
    const secret = await fetchSecret(id)
    navigator.clipboard.writeText(secret)
    setCopied(key)
    setTimeout(() => setCopied(null), 1500)
  }

  function copyText(text: string, key: string) {
    navigator.clipboard.writeText(text)
    setCopied(key)
    setTimeout(() => setCopied(null), 1500)
  }

  const filtered = credentials.filter(c => {
    if (filterType !== 'all' && c.cred_type !== filterType) return false
    if (filterSource !== 'all' && c.source !== filterSource) return false
    if (search) {
      const q = search.toLowerCase()
      if (!c.username.toLowerCase().includes(q) && !c.target_host.toLowerCase().includes(q) && !c.notes.toLowerCase().includes(q)) return false
    }
    return true
  })

  // KPI computations
  const total = credentials.length
  const byType = CRED_TYPES.reduce<Record<string, number>>((a, t) => ({ ...a, [t]: credentials.filter(c => c.cred_type === t).length }), {})
  const fromC2 = credentials.filter(c => c.source === 'c2_loot').length
  const uniqueHosts = new Set(credentials.map(c => c.target_host).filter(Boolean)).size

  // Password audit summary from real data
  const sourceBreakdown = CRED_SOURCES.map(s => ({
    label: SOURCE_LABELS[s],
    count: credentials.filter(c => c.source === s).length,
    color: SOURCE_COLOR[s],
  })).filter(s => s.count > 0)

  const typeBreakdown = CRED_TYPES.map(t => ({
    label: t,
    count: credentials.filter(c => c.cred_type === t).length,
    style: TYPE_STYLE[t],
  })).filter(t => t.count > 0)

  const inputStyle: React.CSSProperties = {
    width: '100%',
    boxSizing: 'border-box',
    background: 'var(--bg)',
    border: rule,
    padding: '6px 10px',
    fontSize: 12,
    color: 'var(--fg)',
    fontFamily: 'var(--font-sans)',
    outline: 'none',
  }

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column' }}>
      {/* Page header */}
      <div style={{ padding: '18px var(--pad)', borderBottom: rule, display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: 16 }}>
        <div>
          <div className="smcap" style={{ marginBottom: 4 }}>{sp?.name ?? 'All Projects'}</div>
          <h1 className="mono" style={{ margin: 0, fontWeight: 500, fontSize: 22, letterSpacing: '-0.01em' }}>Credential Vault</h1>
          <div style={{ color: 'var(--fg-3)', fontSize: 12, marginTop: 6 }}>
            Captured passwords, hashes, keys, and tokens. AES-256 at rest, redacted by default.
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>
          <input
            ref={importInputRef}
            type="file"
            accept=".txt,.hash,.lst,text/plain"
            style={{ display: 'none' }}
            onChange={e => {
              const file = e.target.files?.[0]
              if (file) handleImportHashes(file)
              e.target.value = ''
            }}
          />
          <button className="btn" onClick={() => importInputRef.current?.click()} disabled={!projectId}>
            <Icon name="upload" size={11} /> Import hashes
          </button>
          <button className="btn" onClick={handleExportHashcat}>
            <Icon name="download" size={11} /> Export hashcat
          </button>
          <button
            className="btn btn-primary"
            onClick={() => setShowModal(true)}
            disabled={!projectId}
          >
            <Icon name="plus" size={11} color="#1a1408" /> Add credential
          </button>
        </div>
      </div>

      {/* KPI strip */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', borderBottom: rule }}>
        <KPICell label="Credentials · captured" value={total} sub={`${uniqueHosts} host${uniqueHosts !== 1 ? 's' : ''}`} />
        <KPICell label="Passwords" value={byType.password ?? 0} sub="plaintext / cracked" accentVar="--ok" divider />
        <KPICell label="Hashes" value={byType.hash ?? 0} sub="ntlm · kerberos · etc" accentVar="--warn" divider />
        <KPICell label="Keys + tokens" value={(byType.key ?? 0) + (byType.token ?? 0)} sub="ssh · api · bearer" divider />
        <KPICell label="From C2 loot" value={fromC2} sub={fromC2 === 0 ? 'none harvested' : 'session harvest'} accentVar={fromC2 > 0 ? '--crit' : undefined} divider />
      </div>

      {/* Filter strip */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px var(--pad)', borderBottom: rule, background: 'var(--bg-2)', flexWrap: 'wrap' }}>
        <SegBtns
          options={['all', ...CRED_TYPES.filter(t => byType[t] > 0)]}
          value={filterType}
          onChange={setFilterType}
        />

        <div style={{ width: 1, height: 18, background: 'var(--rule)' }} />

        <SegBtns
          options={['all', ...CRED_SOURCES.filter(s => credentials.some(c => c.source === s))]}
          value={filterSource}
          onChange={setFilterSource}
        />

        <input
          type="text"
          placeholder="Search…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ marginLeft: 8, width: 150 }}
        />

        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
          <button className="btn btn-sm" onClick={loadCredentials}>
            <Icon name="refresh" size={9} /> Refresh
          </button>
          <button className="btn btn-sm" onClick={() => setRevealedIds(new Set())}>
            <Icon name="eye_off" size={9} /> Hide all
          </button>
        </div>

        <span className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>
          {filtered.length} of {total}
        </span>
      </div>

      {/* Table */}
      <div style={{ overflowY: 'auto' }}>
        {filtered.length === 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '60px 20px', color: 'var(--fg-3)' }}>
            <Icon name="shield" size={32} color="var(--rule-strong)" />
            <p style={{ margin: '12px 0 0', fontSize: 13, fontFamily: 'var(--font-mono)' }}>
              {credentials.length === 0 ? 'No credentials stored yet' : 'No credentials match current filters'}
            </p>
          </div>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th style={{ width: 36 }}>#</th>
                <th style={{ width: 160 }}>User</th>
                <th style={{ width: 100 }}>Kind</th>
                <th>Secret</th>
                <th style={{ width: 110 }}>Source</th>
                <th style={{ width: 160 }}>Target host</th>
                <th style={{ width: 80 }}></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((cred, idx) => {
                const revealed = revealedIds.has(cred.id)
                return (
                  <tr key={cred.id}>
                    <td className="mono tnum" style={{ color: 'var(--fg-4)' }}>{String(idx + 1).padStart(2, '0')}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                        <span className="mono" style={{ fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {cred.username || '—'}
                        </span>
                        {cred.username && (
                          <button
                            onClick={() => copyText(cred.username, `u-${cred.id}`)}
                            style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied === `u-${cred.id}` ? 'var(--ok)' : 'var(--fg-4)', padding: 0, flexShrink: 0 }}
                          >
                            <Icon name={copied === `u-${cred.id}` ? 'check' : 'copy'} size={11} color="currentColor" />
                          </button>
                        )}
                      </div>
                    </td>
                    <td><TypePill type={cred.cred_type} /></td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                        <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {revealed ? (revealedSecrets[cred.id] ?? '') : '••••••••••••'}
                        </span>
                        <button
                          onClick={() => toggleReveal(cred.id)}
                          style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0, flexShrink: 0 }}
                        >
                          <Icon name={revealed ? 'eye_off' : 'eye'} size={11} color="currentColor" />
                        </button>
                        {cred.has_secret && (
                          <button
                            onClick={() => copySecret(cred.id, `s-${cred.id}`)}
                            style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied === `s-${cred.id}` ? 'var(--ok)' : 'var(--fg-4)', padding: 0, flexShrink: 0 }}
                          >
                            <Icon name={copied === `s-${cred.id}` ? 'check' : 'copy'} size={11} color="currentColor" />
                          </button>
                        )}
                      </div>
                    </td>
                    <td style={{ fontSize: 11, fontWeight: 500, color: SOURCE_COLOR[cred.source] }}>{SOURCE_LABELS[cred.source]}</td>
                    <td className="mono" style={{ fontSize: 11, color: 'var(--fg-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {cred.target_host || '—'}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn btn-sm" title="Copy secret" onClick={() => copySecret(cred.id, `c-${cred.id}`)}>
                          <Icon name="copy" size={9} />
                        </button>
                        <button
                          className="btn btn-sm"
                          title="Delete"
                          onClick={() => handleDelete(cred.id)}
                          onMouseEnter={e => (e.currentTarget.style.color = 'var(--crit)')}
                          onMouseLeave={e => (e.currentTarget.style.color = '')}
                        >
                          <Icon name="trash" size={9} />
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Bottom strip — cracking queue + audit */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', borderTop: rule }}>
        {/* Cracking queue */}
        <div style={{ border: 'none' }}>
          <div className="sec-h">
            <span className="title">Hashcat Queue</span>
            <span className="mono" style={{ fontSize: 10, color: 'var(--fg-4)' }}>no active jobs</span>
          </div>
          {byType.hash === 0 ? (
            <div style={{ padding: 'var(--pad)', fontSize: 12, color: 'var(--fg-3)' }}>
              No hashes stored. Harvest them from a C2 session or add manually.
            </div>
          ) : (
            <div style={{ padding: 'var(--pad)' }}>
              <div style={{ fontSize: 12, color: 'var(--fg-3)', marginBottom: 12 }}>
                {byType.hash} hash{byType.hash !== 1 ? 'es' : ''} stored. Hashcat integration is configured via Settings → Tools.
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <button className="btn btn-sm" onClick={handleExportHashcat}>
                  <Icon name="download" size={9} /> Export hashcat
                </button>
                <button className="btn btn-sm btn-primary" onClick={handleSendToCracking}>
                  <Icon name="target" size={9} color="#1a1408" /> Send to cracking
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Credential audit */}
        <div style={{ borderLeft: rule }}>
          <div className="sec-h">
            <span className="title">Credential Audit</span>
          </div>
          <div style={{ padding: 'var(--pad)' }}>
            {total === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--fg-3)' }}>No credentials yet.</div>
            ) : (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px 12px', marginBottom: 12 }}>
                  {typeBreakdown.map(t => (
                    <div key={t.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px dashed var(--rule)' }}>
                      <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{t.label}</span>
                      <TypePill type={t.label as CredType} />
                    </div>
                  ))}
                </div>
                <div style={{ marginTop: 8, padding: '10px 12px', background: 'var(--bg-2)', border: rule }}>
                  <div className="smcap" style={{ marginBottom: 8 }}>By source</div>
                  {sourceBreakdown.map(s => (
                    <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '3px 0', borderBottom: '1px dashed var(--rule)' }}>
                      <span className="mono" style={{ fontSize: 11, color: s.color }}>{s.label}</span>
                      <span className="mono tnum" style={{ fontSize: 11, color: 'var(--fg-3)' }}>×{s.count}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* Add Credential Modal */}
      {showModal && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.75)' }}>
          <div style={{ background: 'var(--bg-2)', border: rule, padding: 24, width: '100%', maxWidth: 420, boxShadow: '0 8px 32px rgba(0,0,0,0.5)' }}>
            <h2 style={{ margin: '0 0 18px', fontSize: 14, fontWeight: 700, color: 'var(--fg)', display: 'flex', alignItems: 'center', gap: 8, fontFamily: 'var(--font-mono)' }}>
              <Icon name="key" size={14} color="var(--accent)" /> Add Credential
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div>
                  <label style={{ display: 'block', fontSize: 10, color: 'var(--fg-3)', marginBottom: 5, fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Kind</label>
                  <select value={form.cred_type} onChange={e => setForm(f => ({ ...f, cred_type: e.target.value as CredType }))} style={inputStyle}>
                    {CRED_TYPES.map(t => <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>)}
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: 10, color: 'var(--fg-3)', marginBottom: 5, fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Source</label>
                  <select value={form.source} onChange={e => setForm(f => ({ ...f, source: e.target.value as CredSource }))} style={inputStyle}>
                    {CRED_SOURCES.map(s => <option key={s} value={s}>{SOURCE_LABELS[s]}</option>)}
                  </select>
                </div>
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 10, color: 'var(--fg-3)', marginBottom: 5, fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Username / Account</label>
                <input value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} style={inputStyle} placeholder="administrator" />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 10, color: 'var(--fg-3)', marginBottom: 5, fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  {form.cred_type === 'key' ? 'Private key (PEM)' : 'Secret (password / hash)'}
                </label>
                {form.cred_type === 'key' ? (
                  <>
                    <textarea
                      value={form.secret}
                      onChange={e => setForm(f => ({ ...f, secret: e.target.value }))}
                      style={{ ...inputStyle, resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: 11 }}
                      rows={6}
                      placeholder={'-----BEGIN OPENSSH PRIVATE KEY-----\n…paste or load a private key…\n-----END OPENSSH PRIVATE KEY-----'}
                    />
                    <label className="btn btn-sm" style={{ marginTop: 6, cursor: 'pointer', display: 'inline-flex', alignItems: 'center' }}>
                      <Icon name="upload" size={11} style={{ marginRight: 5 }} /> Load from file
                      <input type="file" accept=".pem,.key,.ppk,.txt,id_rsa,id_ed25519" style={{ display: 'none' }}
                        onChange={async e => { const f = e.target.files?.[0]; if (f) { const text = await f.text(); setForm(s => ({ ...s, secret: text })) } }} />
                    </label>
                  </>
                ) : (
                  <input type="password" value={form.secret} onChange={e => setForm(f => ({ ...f, secret: e.target.value }))} style={inputStyle} placeholder="••••••••" />
                )}
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 10, color: 'var(--fg-3)', marginBottom: 5, fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Target host</label>
                <input value={form.target_host} onChange={e => setForm(f => ({ ...f, target_host: e.target.value }))} style={inputStyle} placeholder="192.168.1.10" />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: 10, color: 'var(--fg-3)', marginBottom: 5, fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Notes</label>
                <textarea value={form.notes} onChange={e => setForm(f => ({ ...f, notes: e.target.value }))} style={{ ...inputStyle, resize: 'vertical' }} rows={2} placeholder="Found in /etc/shadow…" />
              </div>
            </div>

            <div style={{ display: 'flex', gap: 8, marginTop: 18 }}>
              <button onClick={() => { setShowModal(false); setForm(EMPTY_FORM) }} className="btn btn-ghost" style={{ flex: 1, justifyContent: 'center' }}>
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving || !form.secret}
                className="btn btn-primary"
                style={{ flex: 1, justifyContent: 'center', opacity: saving || !form.secret ? 0.5 : 1, cursor: saving || !form.secret ? 'not-allowed' : 'pointer' }}
              >
                {saving ? 'Saving…' : 'Save credential'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
