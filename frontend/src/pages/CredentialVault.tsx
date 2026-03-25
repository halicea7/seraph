import { useState, useEffect } from 'react'
import {
  KeyRound, Plus, Copy, Check, Trash2, Eye, EyeOff, ShieldAlert,
} from 'lucide-react'
import type { Credential, CredType, CredSource, Project } from '../types/index'

const CRED_TYPE_STYLES: Record<CredType, string> = {
  password:  'bg-cyan-950/60 text-cyan-400 border-cyan-500/40',
  hash:      'bg-purple-950/60 text-purple-400 border-purple-500/40',
  key:       'bg-amber-950/60 text-amber-400 border-amber-500/40',
  token:     'bg-blue-950/60 text-blue-400 border-blue-500/40',
  other:     'bg-slate-800/60 text-slate-400 border-slate-600/40',
}

const SOURCE_STYLES: Record<CredSource, string> = {
  manual:      'text-slate-400',
  c2_loot:     'text-red-400',
  osint:       'text-yellow-400',
  brute_force: 'text-orange-400',
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

export default function CredentialVault() {
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedProject, setSelectedProject] = useState('')
  const [credentials, setCredentials] = useState<Credential[]>([])
  const [showModal, setShowModal] = useState(false)
  const [form, setForm] = useState(EMPTY_FORM)
  const [saving, setSaving] = useState(false)
  const [revealedIds, setRevealedIds] = useState<Set<string>>(new Set())
  const [copied, setCopied] = useState<string | null>(null)
  const [filterType, setFilterType] = useState<string>('all')
  const [filterSource, setFilterSource] = useState<string>('all')
  const [search, setSearch] = useState('')

  useEffect(() => {
    fetch('/api/v1/projects')
      .then(r => r.json())
      .then(data => {
        setProjects(data)
        if (data.length > 0) setSelectedProject(data[0].id)
      })
  }, [])

  useEffect(() => {
    if (selectedProject) loadCredentials()
  }, [selectedProject])

  async function loadCredentials() {
    const res = await fetch(`/api/v1/credentials?project_id=${selectedProject}`)
    setCredentials(await res.json())
  }

  async function handleSave() {
    if (!selectedProject) return
    setSaving(true)
    await fetch('/api/v1/credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...form, project_id: selectedProject }),
    })
    setSaving(false)
    setShowModal(false)
    setForm(EMPTY_FORM)
    loadCredentials()
  }

  async function handleDelete(id: string) {
    await fetch(`/api/v1/credentials/${id}`, { method: 'DELETE' })
    setCredentials(prev => prev.filter(c => c.id !== id))
  }

  function toggleReveal(id: string) {
    setRevealedIds(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
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

  const inputClass = "w-full rounded px-3 py-2 text-sm text-slate-200 focus:outline-none border border-cyan-900/20 focus:border-cyan-500/50 bg-[#05080d]"

  return (
    <div className="p-6 flex flex-col gap-6 h-full min-h-0">
      {/* Header */}
      <div className="flex items-center justify-between flex-shrink-0">
        <div>
          <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <KeyRound size={20} className="text-cyan-400" />
            Credential Vault
          </h1>
          <p className="text-sm text-slate-400 mt-0.5">Harvested credentials, hashes, keys, and tokens</p>
        </div>
        <button
          onClick={() => setShowModal(true)}
          disabled={!selectedProject}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-sm text-white font-medium transition-all hover:shadow-glow-cyan"
        >
          <Plus size={15} /> Add Credential
        </button>
      </div>

      {/* Project selector + filters */}
      <div className="flex flex-wrap gap-3 items-center flex-shrink-0">
        <select
          value={selectedProject}
          onChange={e => setSelectedProject(e.target.value)}
          className="rounded px-3 py-1.5 text-sm text-slate-200 border border-cyan-900/20 focus:outline-none focus:border-cyan-500/50 bg-[#090d14]"
        >
          <option value="">Select project...</option>
          {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>

        <select
          value={filterType}
          onChange={e => setFilterType(e.target.value)}
          className="rounded px-3 py-1.5 text-sm text-slate-200 border border-cyan-900/20 focus:outline-none focus:border-cyan-500/50 bg-[#090d14]"
        >
          <option value="all">All Types</option>
          {(['password','hash','key','token','other'] as CredType[]).map(t => (
            <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>
          ))}
        </select>

        <select
          value={filterSource}
          onChange={e => setFilterSource(e.target.value)}
          className="rounded px-3 py-1.5 text-sm text-slate-200 border border-cyan-900/20 focus:outline-none focus:border-cyan-500/50 bg-[#090d14]"
        >
          <option value="all">All Sources</option>
          {(['manual','c2_loot','osint','brute_force'] as CredSource[]).map(s => (
            <option key={s} value={s}>{SOURCE_LABELS[s]}</option>
          ))}
        </select>

        <input
          type="text"
          placeholder="Search..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="rounded px-3 py-1.5 text-sm text-slate-200 border border-cyan-900/20 focus:outline-none focus:border-cyan-500/50 bg-[#090d14] w-44"
        />

        <span className="ml-auto text-xs text-slate-500 font-mono">{filtered.length} credential{filtered.length !== 1 ? 's' : ''}</span>
      </div>

      {/* Table */}
      <div className="flex-1 min-h-0 overflow-y-auto">
        {filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-slate-500">
            <ShieldAlert size={36} className="mb-3 opacity-30 text-cyan-600" />
            <p className="text-sm">{credentials.length === 0 ? 'No credentials stored yet' : 'No credentials match current filters'}</p>
          </div>
        ) : (
          <div className="glass rounded-xl overflow-hidden">
            {/* Header row */}
            <div className="grid grid-cols-[120px_160px_1fr_120px_130px_100px] gap-0 border-b border-cyan-900/20 px-4 py-2.5">
              {['Type', 'Username', 'Secret', 'Source', 'Target Host', 'Actions'].map(h => (
                <div key={h} className="text-xs font-semibold text-slate-400 uppercase tracking-wider">{h}</div>
              ))}
            </div>

            {filtered.map(cred => {
              const revealed = revealedIds.has(cred.id)
              return (
                <div key={cred.id} className="grid grid-cols-[120px_160px_1fr_120px_130px_100px] gap-0 border-b border-cyan-900/10 hover:bg-cyan-950/10 transition-colors px-4 py-3 items-center">
                  {/* Type */}
                  <div>
                    <span className={`text-xs px-2 py-0.5 rounded-full border font-semibold uppercase ${CRED_TYPE_STYLES[cred.cred_type]}`}>
                      {cred.cred_type}
                    </span>
                  </div>

                  {/* Username */}
                  <div className="flex items-center gap-1.5 min-w-0">
                    <span className="text-sm text-slate-200 font-mono truncate">{cred.username || '—'}</span>
                    {cred.username && (
                      <button onClick={() => copyText(cred.username, `u-${cred.id}`)} className="text-slate-600 hover:text-cyan-400 flex-shrink-0">
                        {copied === `u-${cred.id}` ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
                      </button>
                    )}
                  </div>

                  {/* Secret */}
                  <div className="flex items-center gap-1.5 min-w-0">
                    <span className="text-sm text-slate-300 font-mono truncate">
                      {revealed ? cred.secret : '••••••••••••'}
                    </span>
                    <button onClick={() => toggleReveal(cred.id)} className="text-slate-600 hover:text-cyan-400 flex-shrink-0">
                      {revealed ? <EyeOff size={11} /> : <Eye size={11} />}
                    </button>
                    {cred.secret && (
                      <button onClick={() => copyText(cred.secret, `s-${cred.id}`)} className="text-slate-600 hover:text-cyan-400 flex-shrink-0">
                        {copied === `s-${cred.id}` ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
                      </button>
                    )}
                  </div>

                  {/* Source */}
                  <div className={`text-xs font-medium ${SOURCE_STYLES[cred.source]}`}>
                    {SOURCE_LABELS[cred.source]}
                  </div>

                  {/* Target Host */}
                  <div className="text-xs font-mono text-slate-400 truncate">{cred.target_host || '—'}</div>

                  {/* Actions */}
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleDelete(cred.id)}
                      className="text-slate-600 hover:text-red-400 transition-colors"
                      title="Delete"
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Add Credential Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.7)' }}>
          <div className="glass rounded-2xl p-6 w-full max-w-md border border-cyan-900/30 shadow-glow-cyan" style={{ backdropFilter: 'blur(16px)' }}>
            <h2 className="text-base font-bold text-slate-100 mb-5 flex items-center gap-2">
              <KeyRound size={16} className="text-cyan-400" /> Add Credential
            </h2>

            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs text-slate-500 mb-1 block">Type</label>
                  <select value={form.cred_type} onChange={e => setForm(f => ({ ...f, cred_type: e.target.value as CredType }))} className={inputClass}>
                    {(['password','hash','key','token','other'] as CredType[]).map(t => (
                      <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="text-xs text-slate-500 mb-1 block">Source</label>
                  <select value={form.source} onChange={e => setForm(f => ({ ...f, source: e.target.value as CredSource }))} className={inputClass}>
                    {(['manual','c2_loot','osint','brute_force'] as CredSource[]).map(s => (
                      <option key={s} value={s}>{SOURCE_LABELS[s]}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="text-xs text-slate-500 mb-1 block">Username / Account</label>
                <input value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} className={inputClass} placeholder="administrator" />
              </div>

              <div>
                <label className="text-xs text-slate-500 mb-1 block">Secret (password / hash / key)</label>
                <input type="password" value={form.secret} onChange={e => setForm(f => ({ ...f, secret: e.target.value }))} className={inputClass} placeholder="••••••••" />
              </div>

              <div>
                <label className="text-xs text-slate-500 mb-1 block">Target Host</label>
                <input value={form.target_host} onChange={e => setForm(f => ({ ...f, target_host: e.target.value }))} className={inputClass} placeholder="192.168.1.10" />
              </div>

              <div>
                <label className="text-xs text-slate-500 mb-1 block">Notes</label>
                <textarea value={form.notes} onChange={e => setForm(f => ({ ...f, notes: e.target.value }))} className={inputClass} rows={2} placeholder="Found in /etc/shadow, domain admin..." />
              </div>
            </div>

            <div className="flex gap-3 mt-5">
              <button
                onClick={() => { setShowModal(false); setForm(EMPTY_FORM) }}
                className="flex-1 py-2 rounded-lg border border-cyan-900/30 text-sm text-slate-400 hover:text-slate-200 hover:border-cyan-700/50 transition-all"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving || !form.secret}
                className="flex-1 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-sm text-white font-medium transition-all hover:shadow-glow-cyan"
              >
                {saving ? 'Saving...' : 'Save Credential'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
