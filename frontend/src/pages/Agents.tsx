import { useState, useEffect, useRef } from 'react'
import {
  Cpu, Plus, Trash2, ChevronDown, RefreshCw,
  Terminal, Play, CheckCircle, XCircle, Clock, AlertTriangle, Copy,
} from 'lucide-react'

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

const JOB_STATUS_META: Record<string, { color: string; icon: React.ReactNode }> = {
  pending:   { color: 'text-slate-400', icon: <Clock size={12} /> },
  running:   { color: 'text-amber-400', icon: <RefreshCw size={12} className="animate-spin" /> },
  completed: { color: 'text-green-400', icon: <CheckCircle size={12} /> },
  failed:    { color: 'text-red-400',   icon: <XCircle size={12} /> },
}

// ── New Agent Modal ────────────────────────────────────────────────────────────

function NewAgentModal({
  targets,
  onClose,
  onCreated,
}: {
  targets: Target[]
  onClose: () => void
  onCreated: (a: AgentRecord) => void
}) {
  const [name, setName] = useState('')
  const [targetId, setTargetId] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const inputCls = 'w-full px-3 py-2 rounded-lg border border-cyan-900/20 text-sm text-slate-200 focus:outline-none focus:border-cyan-500/50 transition-colors'
  const inputStyle = { background: '#05080d' }

  async function submit() {
    if (!name.trim()) { setError('Name is required'); return }
    setError('')
    setSaving(true)
    try {
      const res = await fetch('/api/v1/agents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), target_id: targetId || null }),
      })
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail ?? 'Failed') }
      const agent = await res.json()
      onCreated(agent)
      onClose()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(5,8,13,0.85)' }}>
      <div className="rounded-xl border border-cyan-900/30 p-6 w-full max-w-sm space-y-4" style={{ background: '#070d17' }}>
        <div className="flex items-center gap-2 mb-2">
          <Cpu size={16} className="text-cyan-400" />
          <h2 className="text-base font-bold text-white">New Agent</h2>
        </div>

        {error && (
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-red-500/30 bg-red-500/10 text-sm text-red-300">
            <AlertTriangle size={13} />{error}
          </div>
        )}

        <div>
          <label className="block text-xs text-slate-400 mb-1.5">Agent name</label>
          <input
            value={name}
            onChange={e => setName(e.target.value)}
            placeholder="e.g. prod-web-01"
            className={inputCls}
            style={inputStyle}
            onKeyDown={e => e.key === 'Enter' && submit()}
            autoFocus
          />
        </div>

        <div>
          <label className="block text-xs text-slate-400 mb-1.5">Target (optional)</label>
          <select value={targetId} onChange={e => setTargetId(e.target.value)} className={inputCls} style={inputStyle}>
            <option value="">— no target —</option>
            {targets.map(t => <option key={t.id} value={t.id}>{t.hostname_or_ip}</option>)}
          </select>
        </div>

        <div className="flex gap-2 pt-1">
          <button
            onClick={submit}
            disabled={saving}
            className="flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/10 transition-all disabled:opacity-50"
            style={{ background: 'rgba(6,182,212,0.05)' }}
          >
            <Plus size={14} />
            {saving ? 'Creating…' : 'Create Agent'}
          </button>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-sm text-slate-400 border border-cyan-900/20 hover:text-slate-200 transition-colors"
            style={{ background: '#05080d' }}
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Deploy Modal ───────────────────────────────────────────────────────────────

function CmdBlock({ cmd, label }: { cmd: string; label: string }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(cmd).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }
  return (
    <div className="space-y-1">
      <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">{label}</label>
      <div className="relative">
        <pre
          className="rounded-lg border border-cyan-900/20 px-4 py-3 text-xs font-mono text-cyan-300 overflow-x-auto pr-12"
          style={{ background: '#05080d' }}
        >
          {cmd}
        </pre>
        <button
          onClick={copy}
          title="Copy"
          className="absolute right-2 top-2 p-1.5 rounded text-slate-500 hover:text-cyan-400 transition-colors"
        >
          {copied ? <CheckCircle size={14} className="text-green-400" /> : <Copy size={14} />}
        </button>
      </div>
    </div>
  )
}

function DeployModal({ agent, onClose }: { agent: AgentRecord; onClose: () => void }) {
  const shortUrl = agent.short_code
    ? `${window.location.origin}/a/${agent.short_code}`
    : `${window.location.origin}/api/v1/agents/${agent.id}/install-script`
  const installCmd = `curl -sSL ${shortUrl} | sudo bash`
  const uninstallCmd = `curl -sSL ${window.location.origin}/api/v1/agents/uninstall-script | sudo bash`

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(5,8,13,0.85)' }}>
      <div className="rounded-xl border border-cyan-900/30 p-6 w-full max-w-lg space-y-4" style={{ background: '#070d17' }}>
        <div className="flex items-center gap-2 mb-1">
          <Terminal size={16} className="text-cyan-400" />
          <h2 className="text-base font-bold text-white">Deploy Agent: {agent.name}</h2>
        </div>
        <p className="text-xs text-slate-400">
          Run the install command on the target host as root. Sets up a systemd service that calls home every 60s.
        </p>

        <CmdBlock cmd={installCmd} label="Install" />
        <CmdBlock cmd={uninstallCmd} label="Uninstall" />

        <div className="text-[11px] text-slate-500 space-y-0.5">
          <p>• Requires: python3, systemd, sudo/root access</p>
          <p>• Runs as root so lynis/openscap work correctly</p>
          <p>• Logs: <span className="font-mono">journalctl -u seraph-agent -f</span></p>
        </div>

        <button
          onClick={onClose}
          className="mt-2 w-full py-2 rounded-lg text-sm text-slate-400 border border-cyan-900/20 hover:text-slate-200 transition-colors"
          style={{ background: '#05080d' }}
        >
          Close
        </button>
      </div>
    </div>
  )
}

// ── Run Audit Modal ────────────────────────────────────────────────────────────

function RunAuditModal({
  agent,
  categories,
  onClose,
  onJobCreated,
}: {
  agent: AgentRecord
  categories: ScanCategory[]
  onClose: () => void
  onJobCreated: () => void
}) {
  const [selCats, setSelCats] = useState<string[]>([])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  function toggleCat(id: string) {
    setSelCats(prev => prev.includes(id) ? prev.filter(c => c !== id) : [...prev, id])
  }

  async function submit() {
    if (selCats.length === 0) { setError('Select at least one category'); return }
    setError('')
    setSaving(true)
    try {
      const res = await fetch(`/api/v1/agents/${agent.id}/jobs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ categories: selCats }),
      })
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail ?? 'Failed') }
      onJobCreated()
      onClose()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Unknown error')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(5,8,13,0.85)' }}>
      <div className="rounded-xl border border-cyan-900/30 p-6 w-full max-w-md space-y-4" style={{ background: '#070d17' }}>
        <div className="flex items-center gap-2 mb-1">
          <Play size={16} className="text-cyan-400" />
          <h2 className="text-base font-bold text-white">Run Audit: {agent.name}</h2>
        </div>
        <p className="text-xs text-slate-400">
          Select audit categories. The job will be queued and picked up by the agent on its next poll.
        </p>

        {error && (
          <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-red-500/30 bg-red-500/10 text-sm text-red-300">
            <AlertTriangle size={13} />{error}
          </div>
        )}

        <div className="grid grid-cols-2 gap-1.5 max-h-60 overflow-y-auto">
          {categories.map(cat => (
            <label
              key={cat.id}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg border cursor-pointer transition-all text-xs ${
                selCats.includes(cat.id)
                  ? 'border-cyan-500/40 text-cyan-300 bg-cyan-500/10'
                  : 'border-cyan-900/20 text-slate-400 hover:border-cyan-900/40'
              }`}
              style={{ background: selCats.includes(cat.id) ? undefined : '#05080d' }}
            >
              <input
                type="checkbox"
                className="hidden"
                checked={selCats.includes(cat.id)}
                onChange={() => toggleCat(cat.id)}
              />
              <span className={`w-3 h-3 rounded border shrink-0 flex items-center justify-center text-[8px] ${
                selCats.includes(cat.id)
                  ? 'bg-cyan-500/30 border-cyan-500/60 text-cyan-300'
                  : 'border-cyan-900/30'
              }`}>
                {selCats.includes(cat.id) ? '✓' : ''}
              </span>
              {cat.label}
            </label>
          ))}
        </div>

        <div className="flex gap-2 pt-1">
          <button
            onClick={submit}
            disabled={saving || selCats.length === 0}
            className="flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/10 transition-all disabled:opacity-50"
            style={{ background: 'rgba(6,182,212,0.05)' }}
          >
            <Play size={14} />
            {saving ? 'Queueing…' : `Queue Audit (${selCats.length})`}
          </button>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-sm text-slate-400 border border-cyan-900/20 hover:text-slate-200 transition-colors"
            style={{ background: '#05080d' }}
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Agent Card ─────────────────────────────────────────────────────────────────

function AgentCard({
  agent,
  categories,
  onDelete,
  onJobQueued,
}: {
  agent: AgentRecord
  categories: ScanCategory[]
  onDelete: (id: string) => void
  onJobQueued: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [jobs, setJobs] = useState<AgentJob[]>([])
  const [loadingJobs, setLoadingJobs] = useState(false)
  const [showDeploy, setShowDeploy] = useState(false)
  const [showAudit, setShowAudit] = useState(false)
  const [expandedJobId, setExpandedJobId] = useState<string | null>(null)
  const [confirmDelete, setConfirmDelete] = useState(false)

  function loadJobs() {
    if (loadingJobs) return
    setLoadingJobs(true)
    fetch(`/api/v1/agents/${agent.id}/jobs`)
      .then(r => r.json())
      .then(data => setJobs(data.slice(0, 5)))
      .finally(() => setLoadingJobs(false))
  }

  function toggle() {
    if (!expanded) loadJobs()
    setExpanded(e => !e)
  }

  const isOnline = agent.status === 'online'

  return (
    <>
      <div className="rounded-xl border border-cyan-900/20 overflow-hidden" style={{ background: '#090d14' }}>
        {/* Header */}
        <div className="flex items-center gap-3 px-4 py-3">
          {/* Status dot */}
          <div className="relative shrink-0">
            <span className={`w-2.5 h-2.5 rounded-full inline-block ${isOnline ? 'bg-green-400' : 'bg-slate-600'}`} />
            {isOnline && (
              <span className="absolute inset-0 rounded-full animate-ping bg-green-400 opacity-60" />
            )}
          </div>

          {/* Name + meta */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-sm text-slate-200 truncate">{agent.name}</span>
              {agent.platform && (
                <span className="text-[10px] px-1.5 py-0.5 rounded border border-cyan-900/20 text-slate-500 font-mono">
                  {agent.platform}
                </span>
              )}
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5">
              {agent.hostname ? `${agent.hostname}` : <span className="italic">hostname unknown</span>}
              {agent.target_hostname && ` · target: ${agent.target_hostname}`}
            </div>
          </div>

          {/* Last seen */}
          <div className="hidden sm:block text-right shrink-0">
            <div className={`text-[11px] ${isOnline ? 'text-green-400' : 'text-slate-500'}`}>
              {isOnline ? 'online' : 'offline'}
            </div>
            <div className="text-[10px] text-slate-600">{fmtTime(agent.last_seen)}</div>
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-1 shrink-0">
            <button
              onClick={() => setShowDeploy(true)}
              title="Deploy"
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-xs text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/10 transition-colors"
            >
              <Terminal size={11} />
              Deploy
            </button>
            <button
              onClick={() => setShowAudit(true)}
              title="Run Audit"
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-xs text-green-300 border border-green-500/30 hover:bg-green-500/10 transition-colors"
            >
              <Play size={11} />
              Audit
            </button>
            {confirmDelete ? (
              <div className="flex items-center gap-1 text-[11px]">
                <button onClick={() => onDelete(agent.id)} className="text-red-400 hover:text-red-300 font-semibold">Yes</button>
                <span className="text-slate-600">/</span>
                <button onClick={() => setConfirmDelete(false)} className="text-slate-400 hover:text-slate-200">No</button>
              </div>
            ) : (
              <button
                onClick={() => setConfirmDelete(true)}
                title="Delete"
                className="p-1.5 rounded text-slate-600 hover:text-red-400 hover:bg-red-500/10 transition-colors"
              >
                <Trash2 size={13} />
              </button>
            )}
            <button
              onClick={toggle}
              className="p-1.5 rounded text-slate-500 hover:text-slate-300 transition-colors"
            >
              <ChevronDown
                size={13}
                style={{ transform: expanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }}
              />
            </button>
          </div>
        </div>

        {/* Recent Jobs */}
        {expanded && (
          <div className="border-t border-cyan-900/15 px-4 py-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Recent Jobs</span>
              <button
                onClick={loadJobs}
                className="text-slate-600 hover:text-cyan-400 transition-colors"
                title="Refresh"
              >
                <RefreshCw size={11} className={loadingJobs ? 'animate-spin' : ''} />
              </button>
            </div>
            {jobs.length === 0 ? (
              <p className="text-xs text-slate-600 italic">No jobs yet</p>
            ) : (
              <div className="space-y-1">
                {jobs.map(job => {
                  const meta = JOB_STATUS_META[job.status] ?? JOB_STATUS_META.failed
                  const isExpanded = expandedJobId === job.id
                  return (
                    <div key={job.id}>
                      <div
                        className="flex items-center gap-2 text-xs rounded px-1 py-1 cursor-pointer hover:bg-cyan-950/20 transition-colors"
                        onClick={() => setExpandedJobId(isExpanded ? null : job.id)}
                        title={job.output ? 'Click to view output' : undefined}
                      >
                        <span className={`shrink-0 ${meta.color}`}>{meta.icon}</span>
                        <span className="text-slate-400 flex-1 truncate">
                          {job.categories ? job.categories.split(',').join(', ') : 'audit'}
                        </span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded ${meta.color}`}>
                          {job.status}
                        </span>
                        <span className="text-[10px] text-slate-600 shrink-0">{fmtTime(job.created_at)}</span>
                        {job.output && (
                          <ChevronDown
                            size={10}
                            className="text-slate-600 shrink-0"
                            style={{ transform: isExpanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }}
                          />
                        )}
                      </div>
                      {isExpanded && job.output && (
                        <pre
                          className="mt-1 mb-1 rounded text-[10px] font-mono text-slate-400 overflow-x-auto overflow-y-auto leading-relaxed p-2 border border-cyan-900/15"
                          style={{ background: '#030508', maxHeight: '200px', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}
                        >
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
          agent={agent}
          categories={categories}
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
    fetch('/api/v1/agents')
      .then(r => r.json())
      .then(setAgents)
      .catch(() => {})
  }

  useEffect(() => {
    Promise.all([
      fetch('/api/v1/agents').then(r => r.json()),
      fetch('/api/v1/targets').then(r => r.json()),
      fetch('/api/v1/audit/categories').then(r => r.json()),
    ]).then(([agts, ts, cats]) => {
      setAgents(agts)
      setTargets(ts)
      const catList = Array.isArray(cats)
        ? cats
        : Object.values(cats as Record<string, { id: string; name: string }>)
            .map(c => ({ id: c.id, label: c.name }))
      setCategories(catList)
    }).finally(() => setLoading(false))

    intervalRef.current = setInterval(loadAgents, 30000)
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [])

  function handleDelete(id: string) {
    fetch(`/api/v1/agents/${id}`, { method: 'DELETE' }).then(() => {
      setAgents(prev => prev.filter(a => a.id !== id))
    })
  }

  const onlineCount = agents.filter(a => a.status === 'online').length
  const offlineCount = agents.filter(a => a.status === 'offline').length

  return (
    <div className="p-6 pb-20 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Cpu size={20} className="text-cyan-400" />
            <h1 className="text-xl font-bold text-white tracking-tight">Agents</h1>
          </div>
          <p className="text-sm text-slate-400">
            Lightweight defensive audit agents deployed to target hosts.
          </p>
        </div>

        <div className="flex items-center gap-4 shrink-0">
          {/* Status summary */}
          <div className="flex items-center gap-3">
            <div className="text-center">
              <div className="text-lg font-bold text-green-400">{onlineCount}</div>
              <div className="text-[10px] text-slate-600 uppercase tracking-widest">Online</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-slate-500">{offlineCount}</div>
              <div className="text-[10px] text-slate-600 uppercase tracking-widest">Offline</div>
            </div>
          </div>

          <button
            onClick={() => setShowNewModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/10 transition-all"
            style={{ background: 'rgba(6,182,212,0.05)' }}
          >
            <Plus size={14} />
            New Agent
          </button>
        </div>
      </div>

      {/* Content */}
      {loading ? (
        <p className="text-sm text-slate-500">Loading…</p>
      ) : agents.length === 0 ? (
        <div className="text-center py-20">
          <Cpu size={40} className="text-slate-700 mx-auto mb-4" />
          <p className="text-slate-500 text-sm mb-2">No agents registered</p>
          <p className="text-slate-600 text-xs mb-5">
            Create an agent, then deploy the install script to a target host.
          </p>
          <button
            onClick={() => setShowNewModal(true)}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/10 transition-all"
          >
            <Plus size={14} /> Create your first agent
          </button>
        </div>
      ) : (
        <div className="space-y-2">
          {agents.map(agent => (
            <AgentCard
              key={agent.id}
              agent={agent}
              categories={categories}
              onDelete={handleDelete}
              onJobQueued={loadAgents}
            />
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
