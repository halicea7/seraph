import { useState } from 'react'
import type React from 'react'
import { X, Plus, Trash2, ChevronDown, ChevronRight, Shield, Database } from 'lucide-react'
import { getApiBase } from '@/lib/config'

interface NessusScanItem { id: number; name: string; status: string; host_count: number }
interface NessusHostItem { host_id: number; hostname: string; critical: number; high: number; medium: number; low: number; info: number }

interface TargetInput {
  hostname_or_ip: string
  target_type: string
  ports: string
  notes: string
}

interface ScopeData {
  include: string[]
  exclude: string[]
}

interface ProjectModalProps {
  onClose: () => void
  onSave: (project: { name: string; description: string }, targets: TargetInput[], scope: ScopeData, nessusData?: { scan_id: number; host_ids: number[] }) => Promise<void>
}

const TARGET_TYPES = [
  { value: 'linux_host', label: 'Linux Host' },
  { value: 'windows_host', label: 'Windows Host' },
  { value: 'web_app', label: 'Web Application' },
  { value: 'cloud_aws', label: 'Cloud (AWS)' },
  { value: 'cloud_azure', label: 'Cloud (Azure)' },
  { value: 'cloud_gcp', label: 'Cloud (GCP)' },
  { value: 'network', label: 'Network' },
  { value: 'api_endpoint', label: 'API Endpoint' },
]

const inputStyle: React.CSSProperties = {
  width: '100%', padding: '7px 10px', fontSize: 12, background: 'var(--bg)',
  border: '1px solid var(--rule)', color: 'var(--fg)', outline: 'none',
  fontFamily: 'var(--font-mono)', borderRadius: 0,
}

export default function ProjectModal({ onClose, onSave }: ProjectModalProps) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [targets, setTargets] = useState<TargetInput[]>([
    { hostname_or_ip: '', target_type: 'linux_host', ports: '', notes: '' }
  ])
  const [scope, setScope] = useState<ScopeData>({ include: [], exclude: [] })
  const [scopeIncludeInput, setScopeIncludeInput] = useState('')
  const [scopeExcludeInput, setScopeExcludeInput] = useState('')
  const [scopeExpanded, setScopeExpanded] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  // Nessus seed
  const [nessusExpanded, setNessusExpanded] = useState(false)
  const [nessusStep, setNessusStep] = useState<'scans' | 'hosts'>('scans')
  const [nessusScans, setNessusScans] = useState<NessusScanItem[]>([])
  const [nessusLoadingScans, setNessusLoadingScans] = useState(false)
  const [nessusError, setNessusError] = useState('')
  const [nessusSelectedScan, setNessusSelectedScan] = useState<NessusScanItem | null>(null)
  const [nessusScanHosts, setNessusScanHosts] = useState<NessusHostItem[]>([])
  const [nessusLoadingHosts, setNessusLoadingHosts] = useState(false)
  const [nessusSelectedHostIds, setNessusSelectedHostIds] = useState<Set<number>>(new Set())

  function addTarget() {
    setTargets(prev => [...prev, { hostname_or_ip: '', target_type: 'linux_host', ports: '', notes: '' }])
  }

  function removeTarget(idx: number) {
    setTargets(prev => prev.filter((_, i) => i !== idx))
  }

  function updateTarget(idx: number, field: keyof TargetInput, value: string) {
    setTargets(prev => prev.map((t, i) => i === idx ? { ...t, [field]: value } : t))
  }

  function addScopeRule(type: 'include' | 'exclude') {
    const val = type === 'include' ? scopeIncludeInput.trim() : scopeExcludeInput.trim()
    if (!val) return
    setScope(s => ({ ...s, [type]: [...s[type], val] }))
    if (type === 'include') setScopeIncludeInput('')
    else setScopeExcludeInput('')
  }

  function removeScopeRule(type: 'include' | 'exclude', idx: number) {
    setScope(s => ({ ...s, [type]: s[type].filter((_, i) => i !== idx) }))
  }

  async function openNessusSection() {
    setNessusExpanded(true)
    if (nessusScans.length > 0) return
    setNessusLoadingScans(true)
    setNessusError('')
    try {
      const res = await fetch(`${getApiBase()}/nessus/scans`)
      if (!res.ok) { setNessusError('Failed to load scans. Check Settings → Nessus.'); return }
      setNessusScans(await res.json())
    } catch { setNessusError('Could not reach backend.') }
    finally { setNessusLoadingScans(false) }
  }

  async function selectNessusScan(scan: NessusScanItem) {
    setNessusSelectedScan(scan)
    setNessusStep('hosts')
    setNessusLoadingHosts(true)
    setNessusError('')
    try {
      const res = await fetch(`${getApiBase()}/nessus/scans/${scan.id}`)
      if (!res.ok) { setNessusError('Failed to load hosts.'); return }
      const data = await res.json()
      const hosts: NessusHostItem[] = data.hosts || []
      setNessusScanHosts(hosts)
      setNessusSelectedHostIds(new Set(hosts.map(h => h.host_id)))
    } catch { setNessusError('Failed to load hosts.') }
    finally { setNessusLoadingHosts(false) }
  }

  async function handleSave() {
    if (!name.trim()) { setError('Project name is required'); return }
    const validTargets = targets.filter(t => t.hostname_or_ip.trim())
    const nessusData = nessusExpanded && nessusSelectedScan && nessusSelectedHostIds.size > 0
      ? { scan_id: nessusSelectedScan.id, host_ids: [...nessusSelectedHostIds] }
      : undefined
    setSaving(true)
    setError('')
    try {
      await onSave({ name: name.trim(), description: description.trim() }, validTargets, scope, nessusData)
      onClose()
    } catch (e: any) {
      setError(e.message || 'Failed to save project')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)' }}>
      <div style={{ background: 'var(--bg-2)', border: '1px solid var(--rule-strong)', width: '100%', maxWidth: 640, maxHeight: '90vh', display: 'flex', flexDirection: 'column', boxShadow: '0 24px 64px rgba(0,0,0,0.6)' }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 20px', borderBottom: '1px solid var(--rule)' }}>
          <h2 style={{ margin: 0, fontSize: 14, fontWeight: 600, color: 'var(--fg)', fontFamily: 'var(--font-sans)' }}>New Project</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', display: 'flex' }}>
            <X size={16} />
          </button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 16 }}>
          {error && (
            <div style={{ padding: '8px 12px', fontSize: 11, color: 'var(--crit)', border: '1px solid rgba(232,92,78,0.3)', background: 'rgba(232,92,78,0.06)' }}>
              {error}
            </div>
          )}

          {/* Project Info */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div>
              <label style={{ display: 'block', fontSize: 10, color: 'var(--fg-3)', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.12em', fontFamily: 'var(--font-mono)' }}>Project Name *</label>
              <input
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. ACME Corp Q2 Assessment"
                style={inputStyle}
                autoFocus
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 10, color: 'var(--fg-3)', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.12em', fontFamily: 'var(--font-mono)' }}>Description</label>
              <textarea
                value={description}
                onChange={e => setDescription(e.target.value)}
                placeholder="Engagement scope, objectives..."
                rows={2}
                style={{ ...inputStyle, height: 'auto', resize: 'vertical' }}
              />
            </div>
          </div>

          {/* Targets */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
              <label style={{ fontSize: 9, fontWeight: 700, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.14em', fontFamily: 'var(--font-mono)' }}>Targets</label>
              <button
                onClick={addTarget}
                style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: 'var(--accent)', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}
              >
                <Plus size={13} /> Add Target
              </button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {targets.map((target, idx) => (
                <div key={idx} style={{ background: 'var(--bg)', border: '1px solid var(--rule)', padding: 12 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                    <span style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>Target {idx + 1}</span>
                    {targets.length > 1 && (
                      <button onClick={() => removeTarget(idx)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', display: 'flex' }}
                        onMouseEnter={e => (e.currentTarget.style.color = 'var(--crit)')}
                        onMouseLeave={e => (e.currentTarget.style.color = 'var(--fg-4)')}>
                        <Trash2 size={13} />
                      </button>
                    )}
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                    {[
                      { label: 'Hostname / IP', field: 'hostname_or_ip' as const, placeholder: '192.168.1.1 or target.example.com' },
                      { label: 'Port Range', field: 'ports' as const, placeholder: 'e.g. 1-1024' },
                      { label: 'Notes', field: 'notes' as const, placeholder: 'Any context...' },
                    ].map(f => (
                      <div key={f.field}>
                        <label style={{ display: 'block', fontSize: 9, color: 'var(--fg-4)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.1em', fontFamily: 'var(--font-mono)' }}>{f.label}</label>
                        <input type="text" value={target[f.field]} onChange={e => updateTarget(idx, f.field, e.target.value)} placeholder={f.placeholder} style={inputStyle} />
                      </div>
                    ))}
                    <div>
                      <label style={{ display: 'block', fontSize: 9, color: 'var(--fg-4)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.1em', fontFamily: 'var(--font-mono)' }}>Type</label>
                      <select value={target.target_type} onChange={e => updateTarget(idx, 'target_type', e.target.value)} style={inputStyle}>
                        {TARGET_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                      </select>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Scope (optional) */}
          <div>
            <button
              type="button"
              onClick={() => setScopeExpanded(e => !e)}
              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 9, fontWeight: 700, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.14em', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}
            >
              {scopeExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              <Shield size={12} style={{ color: 'var(--accent)' }} /> Scope (optional)
            </button>
            {scopeExpanded && (
              <div style={{ marginTop: 10, background: 'var(--bg)', border: '1px solid var(--rule)', padding: 12, display: 'flex', flexDirection: 'column', gap: 14 }}>
                <p style={{ fontSize: 11, color: 'var(--fg-3)', margin: 0, fontFamily: 'var(--font-sans)' }}>
                  Restrict which IPs/hostnames can be added as targets. Supports CIDRs, exact hostnames, wildcards.
                </p>
                {(['include', 'exclude'] as const).map(type => (
                  <div key={type}>
                    <label style={{ display: 'block', fontSize: 9, fontWeight: 600, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 6, fontFamily: 'var(--font-mono)' }}>
                      {type === 'include' ? '✓ Include (allowed)' : '✗ Exclude (blocked)'}
                    </label>
                    <div style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
                      <input
                        style={{ ...inputStyle, flex: 1 }}
                        placeholder={type === 'include' ? '192.168.1.0/24 or example.com' : '192.168.1.1'}
                        value={type === 'include' ? scopeIncludeInput : scopeExcludeInput}
                        onChange={e => type === 'include' ? setScopeIncludeInput(e.target.value) : setScopeExcludeInput(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addScopeRule(type) } }}
                      />
                      <button type="button" onClick={() => addScopeRule(type)}
                        style={{ padding: '0 10px', background: 'none', border: '1px solid var(--rule-strong)', color: 'var(--fg-2)', cursor: 'pointer', fontSize: 14 }}>
                        +
                      </button>
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {scope[type].map((rule, idx) => (
                        <span key={idx} style={{
                          display: 'flex', alignItems: 'center', gap: 4, fontSize: 10,
                          padding: '1px 6px', fontFamily: 'var(--font-mono)', border: '1px solid',
                          color: type === 'include' ? 'var(--ok)' : 'var(--crit)',
                          borderColor: type === 'include' ? 'rgba(107,138,114,0.4)' : 'rgba(232,92,78,0.4)',
                          background: type === 'include' ? 'rgba(107,138,114,0.06)' : 'rgba(232,92,78,0.06)',
                        }}>
                          {rule}
                          <button type="button" onClick={() => removeScopeRule(type, idx)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', padding: 0, lineHeight: 1 }}>×</button>
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Nessus Seed */}
          <div>
            <button
              type="button"
              onClick={() => nessusExpanded ? setNessusExpanded(false) : openNessusSection()}
              style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 9, fontWeight: 700, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.14em', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}
            >
              {nessusExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
              <Database size={12} style={{ color: 'var(--accent)' }} /> Seed from Nessus Scan (optional)
            </button>
            {nessusExpanded && (
              <div style={{ marginTop: 10, background: 'var(--bg)', border: '1px solid var(--rule)', padding: 12 }}>
                {nessusError && (
                  <div style={{ fontSize: 11, color: 'var(--crit)', fontFamily: 'var(--font-mono)', marginBottom: 10 }}>{nessusError}</div>
                )}

                {/* Step: scan list */}
                {nessusStep === 'scans' && (
                  nessusLoadingScans ? (
                    <div style={{ padding: '20px 0', textAlign: 'center', fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>Loading scans…</div>
                  ) : nessusScans.length === 0 ? (
                    <div style={{ fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>No scans found. Configure Nessus in Settings first.</div>
                  ) : (
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                      <thead>
                        <tr style={{ borderBottom: '1px solid var(--rule)' }}>
                          <th style={{ textAlign: 'left', padding: '4px 8px', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Scan</th>
                          <th style={{ textAlign: 'left', padding: '4px 8px', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--fg-3)', width: 60 }}>Hosts</th>
                          <th style={{ width: 70 }}></th>
                        </tr>
                      </thead>
                      <tbody>
                        {nessusScans.map(s => (
                          <tr key={s.id} style={{ borderBottom: '1px solid var(--rule-2)', cursor: 'pointer' }} onClick={() => selectNessusScan(s)}>
                            <td style={{ padding: '6px 8px', color: 'var(--fg)', fontFamily: 'var(--font-sans)' }}>{s.name}</td>
                            <td style={{ padding: '6px 8px', color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>{s.host_count}</td>
                            <td style={{ padding: '6px 8px' }}>
                              <button type="button" onClick={e => { e.stopPropagation(); selectNessusScan(s) }}
                                style={{ fontSize: 10, padding: '2px 8px', background: 'none', border: '1px solid var(--rule-strong)', color: 'var(--accent)', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}>
                                Select →
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )
                )}

                {/* Step: host selection */}
                {nessusStep === 'hosts' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <button type="button" onClick={() => { setNessusStep('scans'); setNessusSelectedScan(null) }}
                        style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', fontSize: 11, fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: 4, padding: 0 }}>
                        ← Back
                      </button>
                      <span style={{ fontSize: 12, color: 'var(--fg)', fontFamily: 'var(--font-sans)' }}>{nessusSelectedScan?.name}</span>
                    </div>
                    {nessusLoadingHosts ? (
                      <div style={{ padding: '16px 0', textAlign: 'center', fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>Loading hosts…</div>
                    ) : (
                      <>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                          <thead>
                            <tr style={{ borderBottom: '1px solid var(--rule)' }}>
                              <th style={{ width: 28, padding: '4px 6px' }}>
                                <input type="checkbox"
                                  checked={nessusSelectedHostIds.size === nessusScanHosts.length && nessusScanHosts.length > 0}
                                  onChange={e => setNessusSelectedHostIds(e.target.checked ? new Set(nessusScanHosts.map(h => h.host_id)) : new Set())}
                                />
                              </th>
                              <th style={{ textAlign: 'left', padding: '4px 6px', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--fg-3)', textTransform: 'uppercase' }}>Host</th>
                              <th style={{ width: 36, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--crit)' }}>C</th>
                              <th style={{ width: 36, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 9, color: '#f97316' }}>H</th>
                              <th style={{ width: 36, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--accent)' }}>M</th>
                              <th style={{ width: 36, textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--ok)' }}>L</th>
                            </tr>
                          </thead>
                          <tbody>
                            {nessusScanHosts.map(h => (
                              <tr key={h.host_id} style={{ borderBottom: '1px solid var(--rule-2)', cursor: 'pointer' }}
                                onClick={() => setNessusSelectedHostIds(prev => { const n = new Set(prev); n.has(h.host_id) ? n.delete(h.host_id) : n.add(h.host_id); return n })}>
                                <td style={{ padding: '5px 6px' }} onClick={e => e.stopPropagation()}>
                                  <input type="checkbox" checked={nessusSelectedHostIds.has(h.host_id)}
                                    onChange={() => setNessusSelectedHostIds(prev => { const n = new Set(prev); n.has(h.host_id) ? n.delete(h.host_id) : n.add(h.host_id); return n })} />
                                </td>
                                <td style={{ padding: '5px 6px', fontFamily: 'var(--font-mono)', color: 'var(--fg)' }}>{h.hostname}</td>
                                <td style={{ textAlign: 'center', color: h.critical > 0 ? 'var(--crit)' : 'var(--fg-4)' }}>{h.critical || '—'}</td>
                                <td style={{ textAlign: 'center', color: h.high > 0 ? '#f97316' : 'var(--fg-4)' }}>{h.high || '—'}</td>
                                <td style={{ textAlign: 'center', color: h.medium > 0 ? 'var(--accent)' : 'var(--fg-4)' }}>{h.medium || '—'}</td>
                                <td style={{ textAlign: 'center', color: h.low > 0 ? 'var(--ok)' : 'var(--fg-4)' }}>{h.low || '—'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                        <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>
                          {nessusSelectedHostIds.size}/{nessusScanHosts.length} hosts selected — will be imported as targets after project is created
                        </div>
                      </>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 10, padding: '12px 20px', borderTop: '1px solid var(--rule)' }}>
          <button
            onClick={onClose}
            style={{ padding: '6px 14px', fontSize: 12, color: 'var(--fg-3)', background: 'none', border: '1px solid var(--rule-strong)', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            style={{ padding: '6px 14px', fontSize: 12, fontWeight: 600, background: 'var(--accent)', color: '#1a1408', border: 'none', cursor: saving ? 'default' : 'pointer', opacity: saving ? 0.6 : 1, fontFamily: 'var(--font-mono)', letterSpacing: '0.06em', textTransform: 'uppercase' }}
          >
            {saving ? 'Creating...' : 'Create Project'}
          </button>
        </div>
      </div>
    </div>
  )
}
