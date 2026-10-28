import { useState, useEffect, useRef } from 'react'
import { getApiBase } from '@/lib/config'
import Icon from '../components/Icon'

// ── Types ──────────────────────────────────────────────────────────────────────

interface AgentRecord {
  id: string
  name: string
  target_id: string | null
  target_hostname: string | null
  token: string
  short_code: string | null
  hostname: string | null
  platform: string | null
  status: 'online' | 'offline'
  last_seen: string | null
  created_at: string
}

interface AgentJob {
  id: string
  agent_id: string
  scan_id: string | null
  categories: string | null
  status: 'pending' | 'running' | 'completed' | 'failed'
  created_at: string
  started_at: string | null
  completed_at: string | null
  exit_code: number | null
  output: string | null
}

interface Target { id: string; hostname_or_ip: string; project_id: string }
interface ScanCategory { id: string; label: string }

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtTime(iso: string | null) {
  if (!iso) return '—'
  const d = new Date(iso)
  const diff = Date.now() - d.getTime()
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return d.toLocaleDateString()
}

const JOB_STATUS_COLOR: Record<string, string> = {
  pending:   'var(--fg-3)',
  running:   'var(--accent)',
  completed: 'var(--ok)',
  failed:    'var(--crit)',
}

const JOB_STATUS_ICON: Record<string, string> = {
  pending:   'clock',
  running:   'refresh',
  completed: 'check',
  failed:    'x',
}

const rule = '1px solid var(--rule)'
const ruleStrong = '1px solid var(--rule-strong)'

const inputStyle: React.CSSProperties = {
  width: '100%', boxSizing: 'border-box',
  background: 'var(--bg)', border: ruleStrong, borderRadius: 3,
  padding: '6px 10px', fontSize: 12, color: 'var(--fg)',
  fontFamily: 'var(--font-sans)', outline: 'none',
}

// ── CmdBlock ──────────────────────────────────────────────────────────────────

function CmdBlock({ cmd, label }: { cmd: string; label: string }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(cmd).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000) })
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
      <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: 'var(--font-sans)' }}>{label}</span>
      <div style={{ position: 'relative' }}>
        <pre style={{ margin: 0, background: 'var(--bg)', border: ruleStrong, borderRadius: 3, padding: '10px 44px 10px 12px', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent)', overflowX: 'auto' }}>
          {cmd}
        </pre>
        <button
          onClick={copy}
          title="Copy"
          style={{ position: 'absolute', right: 8, top: 8, background: 'none', border: 'none', cursor: 'pointer', color: copied ? 'var(--ok)' : 'var(--fg-3)', padding: 4 }}
        >
          <Icon name={copied ? 'check' : 'copy'} size={13} color="currentColor" />
        </button>
      </div>
    </div>
  )
}

// ── New Agent Modal ───────────────────────────────────────────────────────────

function NewAgentModal({ targets, onClose, onCreated }: { targets: Target[]; onClose: () => void; onCreated: (a: AgentRecord) => void }) {
  const [name, setName] = useState('')
  const [targetId, setTargetId] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function submit() {
    if (!name.trim()) { setError('Name is required'); return }
    setError(''); setSaving(true)
    try {
      const res = await fetch(`${getApiBase()}/agents`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), target_id: targetId || null }),
      })
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail ?? 'Failed') }
      onCreated(await res.json()); onClose()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally { setSaving(false) }
  }

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16, background: 'rgba(0,0,0,0.75)' }}>
      <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 6, padding: 24, width: '100%', maxWidth: 360, display: 'flex', flexDirection: 'column', gap: 16 }}>
        <h2 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: 'var(--fg)', display: 'flex', alignItems: 'center', gap: 8, fontFamily: 'var(--font-sans)' }}>
          <Icon name="cpu" size={14} color="var(--accent)" /> New Agent
        </h2>

        {error && (
          <div style={{ fontSize: 12, color: 'var(--crit)', background: 'rgba(232,64,64,0.08)', border: '1px solid rgba(232,64,64,0.3)', borderRadius: 3, padding: '7px 12px', fontFamily: 'var(--font-sans)' }}>
            {error}
          </div>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div>
            <label style={{ display: 'block', fontSize: 10, color: 'var(--fg-3)', marginBottom: 5, fontFamily: 'var(--font-sans)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Agent name</label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. prod-web-01" style={inputStyle} onKeyDown={e => e.key === 'Enter' && submit()} autoFocus />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: 10, color: 'var(--fg-3)', marginBottom: 5, fontFamily: 'var(--font-sans)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Target (optional)</label>
            <select value={targetId} onChange={e => setTargetId(e.target.value)} style={inputStyle}>
              <option value="">— no target —</option>
              {targets.map(t => <option key={t.id} value={t.id}>{t.hostname_or_ip}</option>)}
            </select>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={submit} disabled={saving} style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, padding: '7px 0', borderRadius: 4, background: 'var(--accent)', color: 'var(--bg)', border: 'none', fontSize: 12, fontWeight: 700, cursor: saving ? 'not-allowed' : 'pointer', fontFamily: 'var(--font-sans)', opacity: saving ? 0.6 : 1 }}>
            <Icon name="plus" size={13} color="currentColor" /> {saving ? 'Creating…' : 'Create Agent'}
          </button>
          <button onClick={onClose} style={{ padding: '7px 16px', borderRadius: 4, background: 'none', border: ruleStrong, fontSize: 12, color: 'var(--fg-3)', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Deploy Modal ───────────────────────────────────────────────────────────────

function DeployModal({ agent, onClose }: { agent: AgentRecord; onClose: () => void }) {
  const shortUrl = agent.short_code
    ? `${window.location.origin}/a/${agent.short_code}`
    : `${window.location.origin}/api/v1/agents/${agent.id}/install-script`
  const installCmd = `curl -sSL ${shortUrl} | sudo bash`
  const uninstallCmd = `curl -sSL ${window.location.origin}/api/v1/agents/uninstall-script | sudo bash`

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16, background: 'rgba(0,0,0,0.75)' }}>
      <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 6, padding: 24, width: '100%', maxWidth: 520, display: 'flex', flexDirection: 'column', gap: 16 }}>
        <h2 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: 'var(--fg)', display: 'flex', alignItems: 'center', gap: 8, fontFamily: 'var(--font-sans)' }}>
          <Icon name="terminal" size={14} color="var(--accent)" /> Deploy Agent: {agent.name}
        </h2>
        <p style={{ margin: 0, fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>
          Run the install command on the target host as root. Sets up a systemd service that calls home every 60s.
        </p>
        <CmdBlock cmd={installCmd} label="Install" />
        <CmdBlock cmd={uninstallCmd} label="Uninstall" />
        <div style={{ fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)', display: 'flex', flexDirection: 'column', gap: 3 }}>
          <p style={{ margin: 0 }}>• Requires: python3, systemd, sudo/root access</p>
          <p style={{ margin: 0 }}>• Runs as root so lynis/openscap work correctly</p>
          <p style={{ margin: 0 }}>• Logs: <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>journalctl -u seraph-agent -f</span></p>
        </div>
        <button onClick={onClose} style={{ padding: '7px 0', borderRadius: 4, background: 'none', border: ruleStrong, fontSize: 12, color: 'var(--fg-3)', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}>
          Close
        </button>
      </div>
    </div>
  )
}

// ── Run Audit Modal ───────────────────────────────────────────────────────────

function RunAuditModal({ agent, categories, onClose, onJobCreated }: { agent: AgentRecord; categories: ScanCategory[]; onClose: () => void; onJobCreated: () => void }) {
  const [selCats, setSelCats] = useState<string[]>([])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  function toggleCat(id: string) {
    setSelCats(prev => prev.includes(id) ? prev.filter(c => c !== id) : [...prev, id])
  }

  async function submit() {
    if (selCats.length === 0) { setError('Select at least one category'); return }
    setError(''); setSaving(true)
    try {
      const res = await fetch(`${getApiBase()}/agents/${agent.id}/jobs`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ categories: selCats }),
      })
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail ?? 'Failed') }
      onJobCreated(); onClose()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally { setSaving(false) }
  }

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16, background: 'rgba(0,0,0,0.75)' }}>
      <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 6, padding: 24, width: '100%', maxWidth: 440, display: 'flex', flexDirection: 'column', gap: 16 }}>
        <h2 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: 'var(--fg)', display: 'flex', alignItems: 'center', gap: 8, fontFamily: 'var(--font-sans)' }}>
          <Icon name="play" size={14} color="var(--ok)" /> Run Audit: {agent.name}
        </h2>
        <p style={{ margin: 0, fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>
          Select audit categories. The job will be queued and picked up by the agent on its next poll.
        </p>

        {error && (
          <div style={{ fontSize: 12, color: 'var(--crit)', background: 'rgba(232,64,64,0.08)', border: '1px solid rgba(232,64,64,0.3)', borderRadius: 3, padding: '7px 12px', fontFamily: 'var(--font-sans)' }}>
            {error}
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, maxHeight: 240, overflowY: 'auto' }}>
          {categories.map(cat => {
            const isSel = selCats.includes(cat.id)
            return (
              <label
                key={cat.id}
                style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 10px', borderRadius: 3, cursor: 'pointer', border: isSel ? '1px solid rgba(240,168,58,0.4)' : ruleStrong, background: isSel ? 'rgba(240,168,58,0.08)' : 'var(--bg)', fontSize: 12, color: isSel ? 'var(--accent)' : 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}
              >
                <input type="checkbox" style={{ display: 'none' }} checked={isSel} onChange={() => toggleCat(cat.id)} />
                <span style={{ width: 12, height: 12, borderRadius: 2, border: isSel ? '1px solid rgba(240,168,58,0.6)' : ruleStrong, background: isSel ? 'rgba(240,168,58,0.2)' : 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  {isSel && <Icon name="check" size={8} color="var(--accent)" />}
                </span>
                {cat.label}
              </label>
            )
          })}
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={submit} disabled={saving || selCats.length === 0} style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, padding: '7px 0', borderRadius: 4, background: saving || selCats.length === 0 ? 'var(--bg)' : 'var(--accent)', color: saving || selCats.length === 0 ? 'var(--fg-3)' : 'var(--bg)', border: 'none', fontSize: 12, fontWeight: 700, cursor: saving || selCats.length === 0 ? 'not-allowed' : 'pointer', fontFamily: 'var(--font-sans)', opacity: saving || selCats.length === 0 ? 0.5 : 1 }}>
            <Icon name="play" size={13} color="currentColor" /> {saving ? 'Queueing…' : `Queue Audit (${selCats.length})`}
          </button>
          <button onClick={onClose} style={{ padding: '7px 16px', borderRadius: 4, background: 'none', border: ruleStrong, fontSize: 12, color: 'var(--fg-3)', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Agent Card ─────────────────────────────────────────────────────────────────

function AgentCard({ agent, categories, onDelete, onJobQueued }: { agent: AgentRecord; categories: ScanCategory[]; onDelete: (id: string) => void; onJobQueued: () => void }) {
  const [expanded, setExpanded] = useState(false)
  const [jobs, setJobs] = useState<AgentJob[]>([])
  const [loadingJobs, setLoadingJobs] = useState(false)
  const [showDeploy, setShowDeploy] = useState(false)
  const [showAudit, setShowAudit] = useState(false)
  const [expandedJobId, setExpandedJobId] = useState<string | null>(null)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const isOnline = agent.status === 'online'

  function loadJobs() {
    if (loadingJobs) return
    setLoadingJobs(true)
    fetch(`${getApiBase()}/agents/${agent.id}/jobs`)
      .then(r => r.json()).then(data => setJobs(data.slice(0, 5))).finally(() => setLoadingJobs(false))
  }

  function toggle() {
    if (!expanded) loadJobs()
    setExpanded(e => !e)
  }

  return (
    <>
      <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px' }}>
          {/* Status dot */}
          <div style={{ position: 'relative', flexShrink: 0 }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: isOnline ? 'var(--ok)' : 'var(--fg-3)', display: 'inline-block', boxShadow: isOnline ? '0 0 6px rgba(84,175,97,0.6)' : 'none' }} />
          </div>

          {/* Name + meta */}
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
              <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--fg)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'var(--font-sans)' }}>{agent.name}</span>
              {agent.platform && (
                <span style={{ fontSize: 10, padding: '1px 6px', borderRadius: 3, border: ruleStrong, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>{agent.platform}</span>
              )}
            </div>
            <div style={{ fontSize: 11, color: 'var(--fg-3)', marginTop: 2, fontFamily: 'var(--font-sans)' }}>
              {agent.hostname || <span style={{ fontStyle: 'italic' }}>hostname unknown</span>}
              {agent.target_hostname && ` · target: ${agent.target_hostname}`}
            </div>
          </div>

          {/* Last seen */}
          <div style={{ textAlign: 'right', flexShrink: 0 }}>
            <div style={{ fontSize: 11, color: isOnline ? 'var(--ok)' : 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>
              {isOnline ? 'online' : 'offline'}
            </div>
            <div style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>{fmtTime(agent.last_seen)}</div>
          </div>

          {/* Action buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0 }}>
            <button onClick={() => setShowDeploy(true)} title="Deploy" style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '4px 10px', borderRadius: 3, background: 'none', border: ruleStrong, fontSize: 11, color: 'var(--accent)', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}>
              <Icon name="terminal" size={10} color="currentColor" /> Deploy
            </button>
            <button onClick={() => setShowAudit(true)} title="Run Audit" style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '4px 10px', borderRadius: 3, background: 'none', border: '1px solid rgba(84,175,97,0.3)', fontSize: 11, color: 'var(--ok)', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}>
              <Icon name="play" size={10} color="currentColor" /> Audit
            </button>
            {confirmDelete ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11 }}>
                <button onClick={() => onDelete(agent.id)} style={{ color: 'var(--crit)', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 700, fontFamily: 'var(--font-sans)' }}>Yes</button>
                <span style={{ color: 'var(--fg-3)' }}>/</span>
                <button onClick={() => setConfirmDelete(false)} style={{ color: 'var(--fg-3)', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}>No</button>
              </div>
            ) : (
              <button onClick={() => setConfirmDelete(true)} title="Delete" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 4 }}
                onMouseEnter={e => (e.currentTarget.style.color = 'var(--crit)')}
                onMouseLeave={e => (e.currentTarget.style.color = 'var(--fg-3)')}>
                <Icon name="trash" size={13} color="currentColor" />
              </button>
            )}
            <button onClick={toggle} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 4 }}>
              <Icon name={expanded ? 'chev_u' : 'chev_d'} size={13} color="currentColor" />
            </button>
          </div>
        </div>

        {/* Recent Jobs */}
        {expanded && (
          <div style={{ borderTop: rule, padding: '10px 14px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.1em', fontFamily: 'var(--font-sans)' }}>Recent Jobs</span>
              <button onClick={loadJobs} title="Refresh" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0 }}>
                <Icon name="refresh" size={11} color="currentColor" />
              </button>
            </div>
            {jobs.length === 0 ? (
              <p style={{ margin: 0, fontSize: 12, color: 'var(--fg-3)', fontStyle: 'italic', fontFamily: 'var(--font-sans)' }}>No jobs yet</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {jobs.map(job => {
                  const color = JOB_STATUS_COLOR[job.status] ?? 'var(--fg-3)'
                  const iconName = JOB_STATUS_ICON[job.status] ?? 'x'
                  const isExpanded = expandedJobId === job.id
                  return (
                    <div key={job.id}>
                      <div
                        style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, borderRadius: 3, padding: '4px 6px', cursor: job.output ? 'pointer' : 'default', background: 'none' }}
                        onClick={() => job.output && setExpandedJobId(isExpanded ? null : job.id)}
                      >
                        <Icon name={iconName} size={11} color={color} />
                        <span style={{ color: 'var(--fg-2)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'var(--font-sans)' }}>
                          {job.categories ? job.categories.split(',').join(', ') : 'audit'}
                        </span>
                        <span style={{ fontSize: 10, color, fontFamily: 'var(--font-sans)' }}>{job.status}</span>
                        <span style={{ fontSize: 10, color: 'var(--fg-3)', flexShrink: 0, fontFamily: 'var(--font-mono)' }}>{fmtTime(job.created_at)}</span>
                        {job.output && <Icon name={isExpanded ? 'chev_u' : 'chev_d'} size={10} color="var(--fg-3)" />}
                      </div>
                      {isExpanded && job.output && (
                        <pre style={{ margin: '4px 0', borderRadius: 2, fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--fg-2)', background: 'var(--bg)', border: rule, padding: 8, maxHeight: 200, overflowY: 'auto', overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                          {job.output}
                        </pre>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}
      </div>

      {showDeploy && <DeployModal agent={agent} onClose={() => setShowDeploy(false)} />}
      {showAudit && (
        <RunAuditModal
          agent={agent} categories={categories}
          onClose={() => setShowAudit(false)}
          onJobCreated={() => { onJobQueued(); if (expanded) loadJobs() }}
        />
      )}
    </>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function Agents() {
  const [agents, setAgents] = useState<AgentRecord[]>([])
  const [targets, setTargets] = useState<Target[]>([])
  const [categories, setCategories] = useState<ScanCategory[]>([])
  const [loading, setLoading] = useState(true)
  const [showNewModal, setShowNewModal] = useState(false)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  function loadAgents() {
    fetch(`${getApiBase()}/agents`).then(r => r.json()).then(setAgents).catch(() => {})
  }

  useEffect(() => {
    Promise.all([
      fetch(`${getApiBase()}/agents`).then(r => r.json()),
      fetch(`${getApiBase()}/targets`).then(r => r.json()),
      fetch(`${getApiBase()}/audit/categories`).then(r => r.json()),
    ]).then(([agts, ts, cats]) => {
      setAgents(agts); setTargets(ts)
      const catList = Array.isArray(cats) ? cats : Object.values(cats as Record<string, { id: string; name: string }>).map(c => ({ id: c.id, label: c.name }))
      setCategories(catList)
    }).finally(() => setLoading(false))

    intervalRef.current = setInterval(loadAgents, 30000)
    return () => { if (intervalRef.current) clearInterval(intervalRef.current) }
  }, [])

  function handleDelete(id: string) {
    fetch(`${getApiBase()}/agents/${id}`, { method: 'DELETE' }).then(() => {
      setAgents(prev => prev.filter(a => a.id !== id))
    })
  }

  const onlineCount = agents.filter(a => a.status === 'online').length
  const offlineCount = agents.filter(a => a.status === 'offline').length

  return (
    <div style={{ padding: 24, paddingBottom: 80, display: 'flex', flexDirection: 'column', gap: 20, background: 'var(--bg)', color: 'var(--fg)' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: 'var(--fg)', display: 'flex', alignItems: 'center', gap: 10, fontFamily: 'var(--font-sans)' }}>
            <Icon name="cpu" size={18} color="var(--accent)" /> Agents
          </h1>
          <p style={{ margin: '4px 0 0', fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>
            Lightweight defensive audit agents deployed to target hosts.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 20, flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--ok)', fontFamily: 'var(--font-mono)' }}>{onlineCount}</div>
              <div style={{ fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.1em', fontFamily: 'var(--font-sans)' }}>Online</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>{offlineCount}</div>
              <div style={{ fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.1em', fontFamily: 'var(--font-sans)' }}>Offline</div>
            </div>
          </div>

          <button
            onClick={() => setShowNewModal(true)}
            style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '7px 14px', borderRadius: 4, background: 'var(--accent)', color: 'var(--bg)', border: 'none', fontSize: 12, fontWeight: 700, cursor: 'pointer', fontFamily: 'var(--font-sans)' }}
          >
            <Icon name="plus" size={13} color="currentColor" /> New Agent
          </button>
        </div>
      </div>

      {/* Content */}
      {loading ? (
        <p style={{ fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>Loading…</p>
      ) : agents.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '80px 0' }}>
          <Icon name="cpu" size={40} color="var(--rule-strong)" />
          <p style={{ margin: '12px 0 6px', fontSize: 13, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>No agents registered</p>
          <p style={{ margin: '0 0 20px', fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>
            Create an agent, then deploy the install script to a target host.
          </p>
          <button
            onClick={() => setShowNewModal(true)}
            style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '7px 16px', borderRadius: 4, background: 'none', border: ruleStrong, fontSize: 12, color: 'var(--accent)', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}
          >
            <Icon name="plus" size={13} color="currentColor" /> Create your first agent
          </button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {agents.map(agent => (
            <AgentCard key={agent.id} agent={agent} categories={categories} onDelete={handleDelete} onJobQueued={loadAgents} />
          ))}
        </div>
      )}

      {showNewModal && (
        <NewAgentModal
          targets={targets}
          onClose={() => setShowNewModal(false)}
          onCreated={agent => setAgents(prev => [agent, ...prev])}
        />
      )}
    </div>
  )
}
