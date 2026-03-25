import { useState, useEffect, useRef } from 'react'
import {
  ShieldAlert,
  Plus,
  Trash2,
  Edit,
  Brain,
  ArrowDownToLine,
  Search,
  CheckCircle,
  AlertTriangle,
  X,
  ChevronDown,
  Sparkles,
  RefreshCw,
  Filter,
} from 'lucide-react'
import type { Project } from '../types/index'

// ── Types ────────────────────────────────────────────────────────────────────

type VulnStatus = 'open' | 'in_progress' | 'mitigated' | 'accepted' | 'false_positive'
type VulnSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

interface Vuln {
  id: string
  project_id: string
  title: string
  description: string
  severity: VulnSeverity
  status: VulnStatus
  cvss_score: string | null
  cve_id: string | null
  affected_asset: string
  remediation_notes: string
  tags: string[]
  ai_remediation: string | null
  created_at: string
  updated_at: string
}

interface VulnStats {
  total: number
  by_status: Record<string, number>
  by_severity: Record<string, number>
}

interface ScanFinding {
  id: string
  title: string
  severity: string
  description: string | null
  scan_id: string
}

// ── Style maps ───────────────────────────────────────────────────────────────

const SEVERITY_BORDER: Record<VulnSeverity, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#22c55e',
  info:     '#3b82f6',
}

const SEVERITY_BADGE: Record<VulnSeverity, string> = {
  critical: 'bg-red-950/60 text-red-400 border border-red-500/40',
  high:     'bg-orange-950/60 text-orange-400 border border-orange-500/40',
  medium:   'bg-amber-950/50 text-amber-400 border border-amber-500/40',
  low:      'bg-green-950/50 text-green-400 border border-green-500/40',
  info:     'bg-blue-950/50 text-blue-400 border border-blue-500/40',
}

const STATUS_BADGE: Record<VulnStatus, string> = {
  open:           'bg-red-950/40 text-red-400 border border-red-600/30',
  in_progress:    'bg-amber-950/40 text-amber-400 border border-amber-600/30',
  mitigated:      'bg-green-950/40 text-green-400 border border-green-600/30',
  accepted:       'bg-blue-950/40 text-blue-400 border border-blue-600/30',
  false_positive: 'bg-slate-800/60 text-slate-400 border border-slate-600/30',
}

const STATUS_LABELS: Record<VulnStatus, string> = {
  open:           'Open',
  in_progress:    'In Progress',
  mitigated:      'Mitigated',
  accepted:       'Accepted',
  false_positive: 'False Positive',
}

const ALL_STATUSES: VulnStatus[] = ['open', 'in_progress', 'mitigated', 'accepted', 'false_positive']
const ALL_SEVERITIES: VulnSeverity[] = ['critical', 'high', 'medium', 'low', 'info']

const inputClass =
  'w-full rounded px-3 py-2 text-sm text-slate-200 focus:outline-none border border-cyan-900/20 focus:border-cyan-500/50 bg-[#05080d] placeholder-slate-600'

const selectClass =
  'w-full rounded px-3 py-2 text-sm text-slate-200 focus:outline-none border border-cyan-900/20 focus:border-cyan-500/50 bg-[#05080d]'

// ── Helpers ───────────────────────────────────────────────────────────────────

function parseTags(raw: string): string[] {
  return raw
    .split(',')
    .map(t => t.trim())
    .filter(Boolean)
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  })
}

// ── Status quick-change dropdown ─────────────────────────────────────────────

function StatusDropdown({
  current,
  onSelect,
}: {
  current: VulnStatus
  onSelect: (s: VulnStatus) => void
}) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(o => !o)}
        className={`flex items-center gap-1 text-xs px-2 py-0.5 rounded font-medium transition-all ${STATUS_BADGE[current]}`}
      >
        {STATUS_LABELS[current]}
        <ChevronDown size={10} />
      </button>
      {open && (
        <div
          className="absolute left-0 top-full mt-1 z-20 rounded-lg border border-cyan-900/30 overflow-hidden shadow-xl"
          style={{ background: 'var(--bg-surface-2)', minWidth: '150px' }}
        >
          {ALL_STATUSES.map(s => (
            <button
              key={s}
              onClick={() => { onSelect(s); setOpen(false) }}
              className={`w-full text-left text-xs px-3 py-2 transition-all hover:bg-cyan-950/30 ${
                s === current ? 'text-cyan-400' : 'text-slate-400'
              }`}
            >
              {STATUS_LABELS[s]}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function VulnTracker() {
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedProject, setSelectedProject] = useState('')
  const [vulns, setVulns] = useState<Vuln[]>([])
  const [stats, setStats] = useState<VulnStats>({ total: 0, by_status: {}, by_severity: {} })

  const [filterStatus, setFilterStatus] = useState<'all' | VulnStatus>('all')
  const [filterSeverity, setFilterSeverity] = useState<'all' | VulnSeverity>('all')
  const [searchQuery, setSearchQuery] = useState('')

  // Modal
  const [showModal, setShowModal] = useState(false)
  const [editingVuln, setEditingVuln] = useState<Vuln | null>(null)
  const [saving, setSaving] = useState(false)
  const [modalError, setModalError] = useState('')

  // Form fields
  const [formTitle, setFormTitle] = useState('')
  const [formDesc, setFormDesc] = useState('')
  const [formSeverity, setFormSeverity] = useState<VulnSeverity>('medium')
  const [formStatus, setFormStatus] = useState<VulnStatus>('open')
  const [formCvss, setFormCvss] = useState('')
  const [formCve, setFormCve] = useState('')
  const [formAsset, setFormAsset] = useState('')
  const [formRemediation, setFormRemediation] = useState('')
  const [formTags, setFormTags] = useState('')

  // AI remediation
  const [aiLoading, setAiLoading] = useState<string | null>(null)
  const [aiExpanded, setAiExpanded] = useState<string | null>(null)

  // Import modal
  const [showImport, setShowImport] = useState(false)
  const [importing, setImporting] = useState(false)
  const [findingsList, setFindingsList] = useState<ScanFinding[]>([])
  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<string>>(new Set())

  // ── Data loading ──────────────────────────────────────────────────────────

  useEffect(() => {
    fetch('/api/v1/projects')
      .then(r => r.json())
      .then((data: Project[]) => {
        setProjects(data)
        if (data.length > 0) setSelectedProject(data[0].id)
      })
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (selectedProject) {
      loadVulns()
      loadStats()
    }
  }, [selectedProject])

  async function loadVulns() {
    try {
      const res = await fetch(`/api/v1/vulns?project_id=${selectedProject}`)
      const data = await res.json()
      setVulns(data)
    } catch {
      setVulns([])
    }
  }

  async function loadStats() {
    try {
      const res = await fetch(`/api/v1/vulns/stats?project_id=${selectedProject}`)
      const data = await res.json()
      setStats(data)
    } catch {
      setStats({ total: 0, by_status: {}, by_severity: {} })
    }
  }

  // ── Modal helpers ─────────────────────────────────────────────────────────

  function openCreateModal() {
    setEditingVuln(null)
    setFormTitle('')
    setFormDesc('')
    setFormSeverity('medium')
    setFormStatus('open')
    setFormCvss('')
    setFormCve('')
    setFormAsset('')
    setFormRemediation('')
    setFormTags('')
    setModalError('')
    setShowModal(true)
  }

  function openEditModal(v: Vuln) {
    setEditingVuln(v)
    setFormTitle(v.title)
    setFormDesc(v.description)
    setFormSeverity(v.severity)
    setFormStatus(v.status)
    setFormCvss(v.cvss_score ?? '')
    setFormCve(v.cve_id ?? '')
    setFormAsset(v.affected_asset)
    setFormRemediation(v.remediation_notes)
    setFormTags(v.tags.join(', '))
    setModalError('')
    setShowModal(true)
  }

  async function handleSave() {
    if (!formTitle.trim()) {
      setModalError('Title is required.')
      return
    }
    if (!selectedProject) {
      setModalError('Select a project first.')
      return
    }
    setSaving(true)
    setModalError('')
    try {
      const body = {
        project_id: selectedProject,
        title: formTitle.trim(),
        description: formDesc.trim(),
        severity: formSeverity,
        status: formStatus,
        cvss_score: formCvss.trim() || null,
        cve_id: formCve.trim() || null,
        affected_asset: formAsset.trim(),
        remediation_notes: formRemediation.trim(),
        tags: parseTags(formTags),
      }
      if (editingVuln) {
        await fetch(`/api/v1/vulns/${editingVuln.id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        })
      } else {
        await fetch('/api/v1/vulns', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        })
      }
      setShowModal(false)
      await loadVulns()
      await loadStats()
    } catch (err: any) {
      setModalError(err.message || 'Save failed.')
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this vulnerability?')) return
    await fetch(`/api/v1/vulns/${id}`, { method: 'DELETE' })
    setVulns(prev => prev.filter(v => v.id !== id))
    await loadStats()
  }

  async function handleStatusChange(vuln: Vuln, newStatus: VulnStatus) {
    await fetch(`/api/v1/vulns/${vuln.id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...vuln, status: newStatus }),
    })
    setVulns(prev => prev.map(v => v.id === vuln.id ? { ...v, status: newStatus } : v))
    await loadStats()
  }

  async function handleAiRemediate(vuln: Vuln) {
    setAiLoading(vuln.id)
    try {
      const res = await fetch(`/api/v1/vulns/${vuln.id}/ai-remediate`, { method: 'POST' })
      const data = await res.json()
      setVulns(prev =>
        prev.map(v => v.id === vuln.id ? { ...v, ai_remediation: data.ai_remediation } : v)
      )
      setAiExpanded(vuln.id)
    } catch {
      // ignore
    } finally {
      setAiLoading(null)
    }
  }

  // ── Import findings ───────────────────────────────────────────────────────

  async function openImportModal() {
    setSelectedFindingIds(new Set())
    setFindingsList([])
    setShowImport(true)
    try {
      const res = await fetch(`/api/v1/findings?project_id=${selectedProject}`)
      const data = await res.json()
      setFindingsList(data)
    } catch {
      setFindingsList([])
    }
  }

  function toggleFinding(id: string) {
    setSelectedFindingIds(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  async function handleImport() {
    if (selectedFindingIds.size === 0) return
    setImporting(true)
    try {
      await fetch('/api/v1/vulns/import-findings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          project_id: selectedProject,
          finding_ids: Array.from(selectedFindingIds),
        }),
      })
      setShowImport(false)
      await loadVulns()
      await loadStats()
    } catch {
      // ignore
    } finally {
      setImporting(false)
    }
  }

  // ── Filtering ─────────────────────────────────────────────────────────────

  const filtered = vulns.filter(v => {
    if (filterStatus !== 'all' && v.status !== filterStatus) return false
    if (filterSeverity !== 'all' && v.severity !== filterSeverity) return false
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      if (
        !v.title.toLowerCase().includes(q) &&
        !v.description.toLowerCase().includes(q) &&
        !v.affected_asset.toLowerCase().includes(q) &&
        !(v.cve_id ?? '').toLowerCase().includes(q)
      ) return false
    }
    return true
  })

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 h-full overflow-y-auto" style={{ background: 'var(--bg-base)' }}>

      {/* Page header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="glass rounded-xl p-2">
            <ShieldAlert size={22} className="text-red-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-100">Vulnerability Tracker</h1>
            <p className="text-xs text-slate-500 mt-0.5">Track, prioritize, and remediate security findings</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <select
            value={selectedProject}
            onChange={e => setSelectedProject(e.target.value)}
            className="rounded px-3 py-2 text-xs text-slate-300 focus:outline-none border border-cyan-900/20 focus:border-cyan-500/50"
            style={{ background: 'var(--bg-surface)' }}
          >
            <option value="">Select project...</option>
            {projects.map(p => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
          <button
            onClick={openImportModal}
            disabled={!selectedProject}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-cyan-900/30 text-xs text-slate-400 hover:text-cyan-400 hover:border-cyan-700/40 transition-all disabled:opacity-40"
          >
            <ArrowDownToLine size={14} />
            Import from Findings
          </button>
          <button
            onClick={openCreateModal}
            disabled={!selectedProject}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-white transition-all disabled:opacity-40"
            style={{ background: 'var(--accent)' }}
          >
            <Plus size={15} />
            New Vulnerability
          </button>
        </div>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-5">
        <div className="glass glass-hover rounded-xl p-4">
          <p className="text-2xl font-bold font-mono text-slate-100">{stats.total}</p>
          <p className="text-xs text-slate-500 mt-0.5">Total</p>
        </div>
        <div className="glass glass-hover rounded-xl p-4 border-t-2" style={{ borderTopColor: 'rgba(239,68,68,0.5)' }}>
          <p className="text-2xl font-bold font-mono text-red-400">{stats.by_status['open'] ?? 0}</p>
          <p className="text-xs text-slate-500 mt-0.5">Open</p>
        </div>
        <div className="glass glass-hover rounded-xl p-4 border-t-2" style={{ borderTopColor: 'rgba(245,158,11,0.5)' }}>
          <p className="text-2xl font-bold font-mono text-amber-400">{stats.by_status['in_progress'] ?? 0}</p>
          <p className="text-xs text-slate-500 mt-0.5">In Progress</p>
        </div>
        <div className="glass glass-hover rounded-xl p-4 border-t-2" style={{ borderTopColor: 'rgba(34,197,94,0.5)' }}>
          <p className="text-2xl font-bold font-mono text-green-400">{stats.by_status['mitigated'] ?? 0}</p>
          <p className="text-xs text-slate-500 mt-0.5">Mitigated</p>
        </div>
      </div>

      {/* Filter row */}
      <div className="flex flex-wrap items-center gap-3 mb-5">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px] max-w-xs">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            placeholder="Search vulnerabilities..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 rounded-lg text-xs text-slate-300 placeholder-slate-600 focus:outline-none border border-cyan-900/20 focus:border-cyan-500/40"
            style={{ background: 'var(--bg-surface)' }}
          />
        </div>

        {/* Status pills */}
        <div className="flex items-center gap-1">
          <Filter size={12} className="text-slate-600 mr-1" />
          {(['all', ...ALL_STATUSES] as const).map(s => (
            <button
              key={s}
              onClick={() => setFilterStatus(s)}
              className={`text-xs px-2.5 py-1 rounded-full transition-all ${
                filterStatus === s
                  ? 'text-white font-semibold'
                  : 'text-slate-500 hover:text-slate-300 glass'
              }`}
              style={filterStatus === s ? { background: 'var(--accent)' } : {}}
            >
              {s === 'all' ? 'All Status' : STATUS_LABELS[s]}
            </button>
          ))}
        </div>

        {/* Severity pills */}
        <div className="flex items-center gap-1">
          {(['all', ...ALL_SEVERITIES] as const).map(s => (
            <button
              key={s}
              onClick={() => setFilterSeverity(s)}
              className={`text-xs px-2.5 py-1 rounded-full transition-all capitalize ${
                filterSeverity === s
                  ? 'font-semibold'
                  : 'text-slate-500 hover:text-slate-300 glass'
              }`}
              style={
                filterSeverity === s && s !== 'all'
                  ? { background: `${SEVERITY_BORDER[s]}22`, color: SEVERITY_BORDER[s], border: `1px solid ${SEVERITY_BORDER[s]}55` }
                  : filterSeverity === s
                  ? { background: 'var(--accent)', color: '#fff' }
                  : {}
              }
            >
              {s === 'all' ? 'All Severity' : s}
            </button>
          ))}
        </div>
      </div>

      {/* Vuln list */}
      {filtered.length === 0 ? (
        <div className="glass rounded-xl p-16 text-center">
          <ShieldAlert size={40} className="mx-auto mb-3 text-slate-700" />
          <p className="text-slate-400 text-sm">
            {vulns.length === 0 ? 'No vulnerabilities tracked yet.' : 'No vulnerabilities match the current filters.'}
          </p>
          {vulns.length === 0 && selectedProject && (
            <button
              onClick={openCreateModal}
              className="mt-4 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
            >
              + Add your first vulnerability
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map(vuln => (
            <div key={vuln.id} className="glass rounded-xl overflow-hidden">
              <div className="flex">
                {/* Left severity bar */}
                <div
                  className="w-1 flex-shrink-0"
                  style={{ backgroundColor: SEVERITY_BORDER[vuln.severity] }}
                />
                <div className="flex-1 p-4">
                  {/* Top row: badges + title */}
                  <div className="flex items-start gap-2 flex-wrap mb-2">
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wide ${SEVERITY_BADGE[vuln.severity]}`}>
                      {vuln.severity}
                    </span>
                    <StatusDropdown
                      current={vuln.status}
                      onSelect={s => handleStatusChange(vuln, s)}
                    />
                    {vuln.cve_id && (
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800/60 text-slate-300 border border-slate-600/30 font-mono">
                        {vuln.cve_id}
                      </span>
                    )}
                    {vuln.cvss_score && (
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800/40 text-slate-400 border border-slate-700/30 font-mono">
                        CVSS {vuln.cvss_score}
                      </span>
                    )}
                  </div>

                  <h3 className="text-sm font-semibold text-slate-100 mb-0.5">{vuln.title}</h3>

                  {vuln.affected_asset && (
                    <p className="text-xs text-slate-500 mb-1.5 font-mono">
                      Asset: {vuln.affected_asset}
                    </p>
                  )}

                  {vuln.description && (
                    <p className="text-xs text-slate-400 leading-relaxed mb-2 line-clamp-2">
                      {vuln.description}
                    </p>
                  )}

                  {/* Tags */}
                  {vuln.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-3">
                      {vuln.tags.map(tag => (
                        <span
                          key={tag}
                          className="text-[10px] px-1.5 py-0.5 rounded border border-cyan-900/30 text-cyan-600"
                          style={{ background: 'rgba(6,182,212,0.04)' }}
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Bottom row */}
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="text-[10px] text-slate-600 font-mono">
                      {formatDate(vuln.created_at)}
                    </span>
                    <div className="flex items-center gap-1.5 ml-auto">
                      <button
                        onClick={() => handleAiRemediate(vuln)}
                        disabled={aiLoading === vuln.id}
                        className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg border border-purple-700/30 text-purple-400 hover:text-purple-300 hover:border-purple-600/50 transition-all disabled:opacity-50"
                        style={{ background: 'rgba(88,28,135,0.1)' }}
                        title="AI Remediation"
                      >
                        {aiLoading === vuln.id
                          ? <RefreshCw size={12} className="animate-spin" />
                          : <Brain size={12} />
                        }
                        AI Remediate
                      </button>
                      <button
                        onClick={() => openEditModal(vuln)}
                        className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg border border-cyan-900/30 text-slate-400 hover:text-cyan-400 hover:border-cyan-700/40 transition-all"
                      >
                        <Edit size={12} />
                        Edit
                      </button>
                      <button
                        onClick={() => handleDelete(vuln.id)}
                        className="flex items-center gap-1 text-xs px-2.5 py-1 rounded-lg border border-red-900/30 text-slate-500 hover:text-red-400 hover:border-red-700/40 transition-all"
                      >
                        <Trash2 size={12} />
                        Delete
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* AI remediation panel */}
              {vuln.ai_remediation && (
                <div
                  className="border-t border-purple-900/20 px-5 py-3"
                  style={{ background: 'rgba(88,28,135,0.06)' }}
                >
                  <button
                    onClick={() => setAiExpanded(aiExpanded === vuln.id ? null : vuln.id)}
                    className="flex items-center gap-2 text-xs text-purple-400 hover:text-purple-300 transition-colors w-full"
                  >
                    <Sparkles size={12} />
                    <span className="font-medium">AI Remediation Insight</span>
                    <ChevronDown
                      size={12}
                      className={`ml-auto transition-transform ${aiExpanded === vuln.id ? 'rotate-180' : ''}`}
                    />
                  </button>
                  {aiExpanded === vuln.id && (
                    <div className="mt-2 text-xs text-slate-300 leading-relaxed whitespace-pre-wrap border-l-2 border-purple-700/40 pl-3">
                      {vuln.ai_remediation}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Create / Edit Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/70" onClick={() => setShowModal(false)} />
          <div
            className="relative w-full max-w-2xl rounded-xl border border-cyan-900/30 shadow-2xl flex flex-col max-h-[90vh]"
            style={{ background: 'var(--bg-surface-2)' }}
          >
            {/* Modal header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-cyan-900/20 flex-shrink-0">
              <div className="flex items-center gap-2">
                <ShieldAlert size={18} className="text-red-400" />
                <h2 className="text-sm font-semibold text-slate-100">
                  {editingVuln ? 'Edit Vulnerability' : 'New Vulnerability'}
                </h2>
              </div>
              <button onClick={() => setShowModal(false)} className="text-slate-500 hover:text-slate-300 transition-colors">
                <X size={16} />
              </button>
            </div>

            {/* Modal body */}
            <div className="overflow-y-auto flex-1 px-6 py-4 space-y-4">
              {modalError && (
                <div className="text-xs text-red-400 border border-red-700/30 rounded-lg px-3 py-2" style={{ background: 'rgba(127,29,29,0.15)' }}>
                  {modalError}
                </div>
              )}

              <div>
                <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1 block">
                  Title <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  placeholder="e.g. SQL Injection in /login endpoint"
                  value={formTitle}
                  onChange={e => setFormTitle(e.target.value)}
                  className={inputClass}
                />
              </div>

              <div>
                <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1 block">Description</label>
                <textarea
                  rows={3}
                  placeholder="Describe the vulnerability and its impact..."
                  value={formDesc}
                  onChange={e => setFormDesc(e.target.value)}
                  className={inputClass + ' resize-none'}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1 block">Severity</label>
                  <select
                    value={formSeverity}
                    onChange={e => setFormSeverity(e.target.value as VulnSeverity)}
                    className={selectClass}
                  >
                    {ALL_SEVERITIES.map(s => (
                      <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                    ))}
                  </select>
                </div>
                {editingVuln && (
                  <div>
                    <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1 block">Status</label>
                    <select
                      value={formStatus}
                      onChange={e => setFormStatus(e.target.value as VulnStatus)}
                      className={selectClass}
                    >
                      {ALL_STATUSES.map(s => (
                        <option key={s} value={s}>{STATUS_LABELS[s]}</option>
                      ))}
                    </select>
                  </div>
                )}
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1 block">CVSS Score</label>
                  <input
                    type="text"
                    placeholder="e.g. 9.8"
                    value={formCvss}
                    onChange={e => setFormCvss(e.target.value)}
                    className={inputClass}
                  />
                </div>
                <div>
                  <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1 block">CVE ID</label>
                  <input
                    type="text"
                    placeholder="e.g. CVE-2024-1234"
                    value={formCve}
                    onChange={e => setFormCve(e.target.value)}
                    className={inputClass}
                  />
                </div>
              </div>

              <div>
                <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1 block">Affected Asset</label>
                <input
                  type="text"
                  placeholder="e.g. 192.168.1.10 or https://example.com/login"
                  value={formAsset}
                  onChange={e => setFormAsset(e.target.value)}
                  className={inputClass}
                />
              </div>

              <div>
                <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1 block">Remediation Notes</label>
                <textarea
                  rows={3}
                  placeholder="Steps to fix or mitigate this vulnerability..."
                  value={formRemediation}
                  onChange={e => setFormRemediation(e.target.value)}
                  className={inputClass + ' resize-none'}
                />
              </div>

              <div>
                <label className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-1 block">Tags</label>
                <input
                  type="text"
                  placeholder="e.g. web, injection, authentication (comma-separated)"
                  value={formTags}
                  onChange={e => setFormTags(e.target.value)}
                  className={inputClass}
                />
              </div>
            </div>

            {/* Modal footer */}
            <div className="flex items-center justify-end gap-2 px-6 py-4 border-t border-cyan-900/20 flex-shrink-0">
              <button
                onClick={() => setShowModal(false)}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-cyan-900/30 text-xs text-slate-400 hover:text-slate-300 transition-all"
              >
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-white transition-all disabled:opacity-50"
                style={{ background: 'var(--accent)' }}
              >
                {saving ? <RefreshCw size={14} className="animate-spin" /> : <CheckCircle size={14} />}
                {saving ? 'Saving…' : editingVuln ? 'Update' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Import Findings Modal */}
      {showImport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/70" onClick={() => setShowImport(false)} />
          <div
            className="relative w-full max-w-xl rounded-xl border border-cyan-900/30 shadow-2xl flex flex-col max-h-[80vh]"
            style={{ background: 'var(--bg-surface-2)' }}
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-cyan-900/20 flex-shrink-0">
              <div className="flex items-center gap-2">
                <ArrowDownToLine size={16} className="text-cyan-400" />
                <h2 className="text-sm font-semibold text-slate-100">Import from Scan Findings</h2>
              </div>
              <button onClick={() => setShowImport(false)} className="text-slate-500 hover:text-slate-300 transition-colors">
                <X size={16} />
              </button>
            </div>

            <div className="overflow-y-auto flex-1 px-6 py-4">
              {findingsList.length === 0 ? (
                <div className="text-center py-10">
                  <AlertTriangle size={32} className="mx-auto mb-2 text-slate-700" />
                  <p className="text-slate-500 text-sm">No scan findings found for this project.</p>
                  <p className="text-slate-600 text-xs mt-1">Run a scan first to populate findings.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  <p className="text-xs text-slate-500 mb-3">
                    Select findings to import as vulnerabilities ({selectedFindingIds.size} selected)
                  </p>
                  {findingsList.map(f => (
                    <label
                      key={f.id}
                      className="flex items-start gap-3 p-3 rounded-lg border border-cyan-900/20 cursor-pointer hover:border-cyan-700/30 transition-all"
                      style={{ background: selectedFindingIds.has(f.id) ? 'rgba(6,182,212,0.05)' : 'var(--bg-surface)' }}
                    >
                      <input
                        type="checkbox"
                        checked={selectedFindingIds.has(f.id)}
                        onChange={() => toggleFinding(f.id)}
                        className="mt-0.5 accent-cyan-500"
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-0.5">
                          <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold uppercase ${SEVERITY_BADGE[(f.severity as VulnSeverity) ?? 'info']}`}>
                            {f.severity}
                          </span>
                          <span className="text-xs text-slate-200 truncate">{f.title}</span>
                        </div>
                        {f.description && (
                          <p className="text-[10px] text-slate-500 truncate">{f.description}</p>
                        )}
                      </div>
                    </label>
                  ))}
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-2 px-6 py-4 border-t border-cyan-900/20 flex-shrink-0">
              <button
                onClick={() => setShowImport(false)}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-cyan-900/30 text-xs text-slate-400 hover:text-slate-300 transition-all"
              >
                Cancel
              </button>
              <button
                onClick={handleImport}
                disabled={importing || selectedFindingIds.size === 0}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-white transition-all disabled:opacity-40"
                style={{ background: 'var(--accent)' }}
              >
                {importing ? <RefreshCw size={14} className="animate-spin" /> : <ArrowDownToLine size={14} />}
                {importing ? 'Importing…' : `Import ${selectedFindingIds.size > 0 ? selectedFindingIds.size : ''} Selected`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
