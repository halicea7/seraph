import { useEffect, useRef, useState } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { Search, Download, ChevronDown, ChevronLeft, Tag, X, EyeOff, RotateCcw, ShieldOff, Plus, Trash2 } from 'lucide-react'
import { Brain, Sparkles, AlertTriangle } from 'lucide-react'
import { getApiBase } from '@/lib/config'
import { useAiModel, completeFeature, runCompletion } from '@/lib/ai'
import AiModelSelect from '@/components/AiModelSelect'
import Icon from '@/components/Icon'
import { useAppStore } from '@/stores/appStore'
import { useToast } from '@/contexts/ToastContext'
import { useConfirm } from '@/contexts/ConfirmContext'
import EmptyState from '@/components/EmptyState'
import { SkeletonRows } from '@/components/Skeleton'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

const rule = '1px solid var(--rule)'

// ── Scan Findings types ────────────────────────────────────────────────────────

interface FindingRow {
  id: string
  severity: string
  title: string
  description: string
  remediation: string | null
  cve_id: string | null
  cvss_score: string | null
  status: string
  fp_reason: string | null
  tags: string
  target: string
  project: string
  project_id: string | null
  created_at: string | null
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--crit)', high: '#f97316', medium: 'var(--accent)', low: 'var(--ok)', info: 'var(--fg-3)',
}

const STATUS_OPTIONS = ['open', 'in-review', 'remediated', 'accepted', 'false_positive'] as const
type FindingStatus = typeof STATUS_OPTIONS[number]

const STATUS_STYLES: Record<string, { color: string; bg: string; border: string }> = {
  'open':           { color: 'var(--crit)',   bg: 'rgba(232,64,64,0.08)',   border: 'rgba(232,64,64,0.25)' },
  'in-review':      { color: 'var(--accent)', bg: 'rgba(240,168,58,0.08)', border: 'rgba(240,168,58,0.25)' },
  'remediated':     { color: 'var(--ok)',     bg: 'rgba(84,175,97,0.08)',   border: 'rgba(84,175,97,0.25)' },
  'accepted':       { color: 'var(--fg-3)',   bg: 'rgba(100,116,139,0.08)', border: 'rgba(100,116,139,0.2)' },
  'false_positive': { color: '#a78bfa',       bg: 'rgba(167,139,250,0.08)', border: 'rgba(167,139,250,0.25)' },
}

// ── VulnRecords types ──────────────────────────────────────────────────────────

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

// ── VulnRecords style maps ─────────────────────────────────────────────────────

const VSEV_COLOR: Record<VulnSeverity, string> = {
  critical: 'var(--crit)',
  high:     '#f97316',
  medium:   'var(--accent)',
  low:      'var(--ok)',
  info:     'var(--med)',
}

const VSEV_STYLE: Record<VulnSeverity, { color: string; background: string; border: string }> = {
  critical: { color: 'var(--crit)',   background: 'rgba(232,64,64,0.08)',  border: '1px solid rgba(232,64,64,0.3)' },
  high:     { color: '#f97316',       background: 'rgba(249,115,22,0.08)', border: '1px solid rgba(249,115,22,0.3)' },
  medium:   { color: 'var(--accent)', background: 'rgba(240,168,58,0.08)', border: '1px solid rgba(240,168,58,0.3)' },
  low:      { color: 'var(--ok)',     background: 'rgba(84,175,97,0.08)',  border: '1px solid rgba(84,175,97,0.3)' },
  info:     { color: 'var(--med)',    background: 'rgba(240,168,58,0.06)', border: '1px solid rgba(240,168,58,0.15)' },
}

const VSTATUS_STYLE: Record<VulnStatus, { color: string; background: string; border: string }> = {
  open:           { color: 'var(--crit)',   background: 'rgba(232,64,64,0.08)',  border: '1px solid rgba(232,64,64,0.3)' },
  in_progress:    { color: 'var(--accent)', background: 'rgba(240,168,58,0.08)', border: '1px solid rgba(240,168,58,0.3)' },
  mitigated:      { color: 'var(--ok)',     background: 'rgba(84,175,97,0.08)',  border: '1px solid rgba(84,175,97,0.3)' },
  accepted:       { color: 'var(--fg-3)',   background: 'rgba(100,116,139,0.06)', border: '1px solid rgba(100,116,139,0.2)' },
  false_positive: { color: 'var(--fg-3)',   background: 'rgba(100,116,139,0.08)', border: '1px solid rgba(100,116,139,0.2)' },
}

const VSTATUS_LABELS: Record<VulnStatus, string> = {
  open:           'Open',
  in_progress:    'In Progress',
  mitigated:      'Mitigated',
  accepted:       'Accepted',
  false_positive: 'False Positive',
}

const ALL_STATUSES: VulnStatus[] = ['open', 'in_progress', 'mitigated', 'accepted', 'false_positive']
const ALL_SEVERITIES: VulnSeverity[] = ['critical', 'high', 'medium', 'low', 'info']

const ruleStrong = '1px solid var(--rule-strong)'

const inputStyle: React.CSSProperties = {
  width: '100%',
  boxSizing: 'border-box',
  background: 'var(--bg)',
  border: ruleStrong,
  borderRadius: 3,
  padding: '6px 10px',
  fontSize: 12,
  color: 'var(--fg)',
  fontFamily: 'var(--font-sans)',
  outline: 'none',
}

const labelStyle: React.CSSProperties = {
  display: 'block',
  fontSize: 10,
  fontWeight: 700,
  color: 'var(--fg-3)',
  textTransform: 'uppercase',
  letterSpacing: '0.08em',
  marginBottom: 5,
  fontFamily: 'var(--font-sans)',
}

// ── VulnRecords helpers ────────────────────────────────────────────────────────

function parseTags(raw: string): string[] {
  return raw.split(',').map(t => t.trim()).filter(Boolean)
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
}

function StatusDropdown({ current, onSelect }: { current: VulnStatus; onSelect: (s: VulnStatus) => void }) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const ss = VSTATUS_STYLE[current]

  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  return (
    <div style={{ position: 'relative' }} ref={ref}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 4,
          fontSize: 10, padding: '2px 7px', borderRadius: 10,
          fontWeight: 600, fontFamily: 'var(--font-sans)', cursor: 'pointer',
          color: ss.color, background: ss.background, border: ss.border,
        }}
      >
        {VSTATUS_LABELS[current]}
        <Icon name="chev_d" size={9} color="currentColor" />
      </button>
      {open && (
        <div style={{
          position: 'absolute', left: 0, top: '100%', marginTop: 4,
          zIndex: 20, borderRadius: 4, border: ruleStrong,
          background: 'var(--bg-2)', minWidth: 150, overflow: 'hidden',
          boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
        }}>
          {ALL_STATUSES.map(s => (
            <button
              key={s}
              onClick={() => { onSelect(s); setOpen(false) }}
              style={{
                width: '100%', textAlign: 'left', fontSize: 11,
                padding: '7px 12px', background: 'none', border: 'none',
                color: s === current ? 'var(--accent)' : 'var(--fg-2)',
                cursor: 'pointer', fontFamily: 'var(--font-sans)',
                borderBottom: rule,
              }}
            >
              {VSTATUS_LABELS[s]}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

// ── VulnRecords component ──────────────────────────────────────────────────────

function VulnRecords({ projectId }: { projectId: string }) {
  const [vulns, setVulns] = useState<Vuln[]>([])
  const [stats, setStats] = useState<VulnStats>({ total: 0, by_status: {}, by_severity: {} })

  const [filterStatus, setFilterStatus] = useState<'all' | VulnStatus>('all')
  const [filterSeverity, setFilterSeverity] = useState<'all' | VulnSeverity>('all')
  const [searchQuery, setSearchQuery] = useState('')

  const [showModal, setShowModal] = useState(false)
  const [editingVuln, setEditingVuln] = useState<Vuln | null>(null)
  const [saving, setSaving] = useState(false)
  const [modalError, setModalError] = useState('')

  const [formTitle, setFormTitle] = useState('')
  const [formDesc, setFormDesc] = useState('')
  const [formSeverity, setFormSeverity] = useState<VulnSeverity>('medium')
  const [formStatus, setFormStatus] = useState<VulnStatus>('open')
  const [formCvss, setFormCvss] = useState('')
  const [formCve, setFormCve] = useState('')
  const [formAsset, setFormAsset] = useState('')
  const [formRemediation, setFormRemediation] = useState('')
  const [formTags, setFormTags] = useState('')

  const [aiLoading, setAiLoading] = useState<string | null>(null)
  const [aiExpanded, setAiExpanded] = useState<string | null>(null)
  const { options: aiModels, modelKey: aiModel, setModelKey: setAiModel } = useAiModel()

  const [showImport, setShowImport] = useState(false)
  const [importing, setImporting] = useState(false)
  const [findingsList, setFindingsList] = useState<ScanFinding[]>([])
  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<string>>(new Set())

  useEffect(() => {
    if (projectId) {
      loadVulns()
      loadStats()
    }
  }, [projectId])


  async function loadVulns() {
    try {
      const res = await fetch(`${getApiBase()}/vulns?project_id=${projectId}`)
      setVulns(await res.json())
    } catch { setVulns([]) }
  }

  async function loadStats() {
    try {
      const res = await fetch(`${getApiBase()}/vulns/stats?project_id=${projectId}`)
      setStats(await res.json())
    } catch { setStats({ total: 0, by_status: {}, by_severity: {} }) }
  }

  function openCreateModal() {
    setEditingVuln(null)
    setFormTitle(''); setFormDesc(''); setFormSeverity('medium'); setFormStatus('open')
    setFormCvss(''); setFormCve(''); setFormAsset(''); setFormRemediation(''); setFormTags('')
    setModalError('')
    setShowModal(true)
  }

  function openEditModal(v: Vuln) {
    setEditingVuln(v)
    setFormTitle(v.title); setFormDesc(v.description); setFormSeverity(v.severity); setFormStatus(v.status)
    setFormCvss(v.cvss_score ?? ''); setFormCve(v.cve_id ?? ''); setFormAsset(v.affected_asset)
    setFormRemediation(v.remediation_notes); setFormTags(v.tags.join(', '))
    setModalError('')
    setShowModal(true)
  }

  async function handleSave() {
    if (!formTitle.trim()) { setModalError('Title is required.'); return }
    if (!projectId) { setModalError('Select a project first.'); return }
    setSaving(true); setModalError('')
    try {
      const body = {
        project_id: projectId,
        title: formTitle.trim(), description: formDesc.trim(),
        severity: formSeverity, status: formStatus,
        cvss_score: formCvss.trim() || null, cve_id: formCve.trim() || null,
        affected_asset: formAsset.trim(), remediation_notes: formRemediation.trim(),
        tags: parseTags(formTags),
      }
      if (editingVuln) {
        await fetch(`${getApiBase()}/vulns/${editingVuln.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      } else {
        await fetch(`${getApiBase()}/vulns`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      }
      setShowModal(false)
      await loadVulns(); await loadStats()
    } catch (err: unknown) {
      setModalError(err instanceof Error ? err.message : 'Save failed.')
    } finally { setSaving(false) }
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this vulnerability?')) return
    await fetch(`${getApiBase()}/vulns/${id}`, { method: 'DELETE' })
    setVulns(prev => prev.filter(v => v.id !== id))
    await loadStats()
  }

  async function handleStatusChange(vuln: Vuln, newStatus: VulnStatus) {
    await fetch(`${getApiBase()}/vulns/${vuln.id}`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...vuln, status: newStatus }),
    })
    setVulns(prev => prev.map(v => v.id === vuln.id ? { ...v, status: newStatus } : v))
    await loadStats()
  }

  async function handleAiRemediate(vuln: Vuln) {
    setAiLoading(vuln.id)
    try {
      const text = await completeFeature(aiModel, `/vulns/${vuln.id}/ai-remediate`, {})
      // Persist so local- and server-run results behave the same.
      await fetch(`${getApiBase()}/vulns/${vuln.id}/ai-remediate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ result: text }),
      }).catch(() => {})
      setVulns(prev => prev.map(v => v.id === vuln.id ? { ...v, ai_remediation: text } : v))
      setAiExpanded(vuln.id)
    } catch { /* ignore */ } finally { setAiLoading(null) }
  }

  async function openImportModal() {
    setSelectedFindingIds(new Set()); setFindingsList([])
    setShowImport(true)
    try {
      const res = await fetch(`${getApiBase()}/findings?project_id=${projectId}`)
      setFindingsList(await res.json())
    } catch { setFindingsList([]) }
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
      await fetch(`${getApiBase()}/vulns/import-findings`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_id: projectId, finding_ids: Array.from(selectedFindingIds) }),
      })
      setShowImport(false); await loadVulns(); await loadStats()
    } catch { /* ignore */ } finally { setImporting(false) }
  }

  const filtered = vulns.filter(v => {
    if (filterStatus !== 'all' && v.status !== filterStatus) return false
    if (filterSeverity !== 'all' && v.severity !== filterSeverity) return false
    if (searchQuery) {
      const q = searchQuery.toLowerCase()
      if (!v.title.toLowerCase().includes(q) && !v.description.toLowerCase().includes(q) &&
          !v.affected_asset.toLowerCase().includes(q) && !(v.cve_id ?? '').toLowerCase().includes(q)) return false
    }
    return true
  })

  return (
    <div style={{ padding: 24, overflowY: 'auto', background: 'var(--bg)', color: 'var(--fg)', flex: 1, minHeight: 0 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <Icon name="shield" size={20} color="var(--crit)" />
          <div>
            <h1 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: 'var(--fg)', fontFamily: 'var(--font-sans)' }}>Vulnerability Tracker</h1>
            <p style={{ margin: '2px 0 0', fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>Track, prioritize, and remediate security findings</p>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <AiModelSelect value={aiModel} onChange={setAiModel} options={aiModels} />
          <button
            onClick={openImportModal}
            disabled={!projectId}
            style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 12px', borderRadius: 4, background: 'none', border: ruleStrong, fontSize: 12, color: 'var(--fg-3)', cursor: projectId ? 'pointer' : 'not-allowed', fontFamily: 'var(--font-sans)', opacity: projectId ? 1 : 0.5 }}
          >
            <Icon name="download" size={13} color="currentColor" /> Import from Findings
          </button>
          <button
            onClick={openCreateModal}
            disabled={!projectId}
            style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px', borderRadius: 4, background: projectId ? 'var(--accent)' : 'var(--bg-2)', color: projectId ? 'var(--bg)' : 'var(--fg-3)', border: 'none', fontSize: 12, fontWeight: 700, cursor: projectId ? 'pointer' : 'not-allowed', fontFamily: 'var(--font-sans)', opacity: projectId ? 1 : 0.5 }}
          >
            <Icon name="plus" size={13} color="currentColor" /> New Vulnerability
          </button>
        </div>
      </div>

      {/* Stats bar */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 18 }}>
        {[
          { label: 'Total', value: stats.total, color: 'var(--fg)' },
          { label: 'Open', value: stats.by_status['open'] ?? 0, color: 'var(--crit)', accent: 'rgba(232,64,64,0.5)' },
          { label: 'In Progress', value: stats.by_status['in_progress'] ?? 0, color: 'var(--accent)', accent: 'rgba(240,168,58,0.5)' },
          { label: 'Mitigated', value: stats.by_status['mitigated'] ?? 0, color: 'var(--ok)', accent: 'rgba(84,175,97,0.5)' },
        ].map(s => (
          <div key={s.label} style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, padding: '12px 16px', borderTop: s.accent ? `2px solid ${s.accent}` : ruleStrong }}>
            <p style={{ margin: 0, fontSize: 22, fontWeight: 700, fontFamily: 'var(--font-mono)', color: s.color }}>{s.value}</p>
            <p style={{ margin: '2px 0 0', fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>{s.label}</p>
          </div>
        ))}
      </div>

      {/* Filter row */}
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8, marginBottom: 18 }}>
        <div style={{ position: 'relative', flex: '1 1 200px', maxWidth: 280 }}>
          <span style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)', color: 'var(--fg-3)' }}>
            <Icon name="search" size={12} color="currentColor" />
          </span>
          <input
            type="text"
            placeholder="Search vulnerabilities..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            style={{ ...inputStyle, paddingLeft: 28 }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <Icon name="filter" size={11} color="var(--fg-3)" />
          {(['all', ...ALL_STATUSES] as const).map(s => {
            const isActive = filterStatus === s
            return (
              <button
                key={s}
                onClick={() => setFilterStatus(s)}
                style={{
                  fontSize: 10, padding: '3px 9px', borderRadius: 10, cursor: 'pointer',
                  fontWeight: isActive ? 700 : 400,
                  background: isActive ? 'var(--accent)' : 'none',
                  color: isActive ? 'var(--bg)' : 'var(--fg-3)',
                  border: isActive ? 'none' : ruleStrong,
                  fontFamily: 'var(--font-sans)',
                }}
              >
                {s === 'all' ? 'All Status' : VSTATUS_LABELS[s]}
              </button>
            )
          })}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          {(['all', ...ALL_SEVERITIES] as const).map(s => {
            const isActive = filterSeverity === s
            const sc = s !== 'all' ? VSEV_COLOR[s] : 'var(--accent)'
            return (
              <button
                key={s}
                onClick={() => setFilterSeverity(s)}
                style={{
                  fontSize: 10, padding: '3px 9px', borderRadius: 10, cursor: 'pointer',
                  fontWeight: isActive ? 700 : 400, textTransform: 'capitalize',
                  background: isActive ? (s === 'all' ? 'var(--accent)' : `${sc}22`) : 'none',
                  color: isActive ? (s === 'all' ? 'var(--bg)' : sc) : 'var(--fg-3)',
                  border: isActive && s !== 'all' ? `1px solid ${sc}55` : (isActive ? 'none' : ruleStrong),
                  fontFamily: 'var(--font-sans)',
                }}
              >
                {s === 'all' ? 'All Severity' : s}
              </button>
            )
          })}
        </div>
      </div>

      {/* Vuln list */}
      {filtered.length === 0 ? (
        <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4 }}>
          <EmptyState
            icon="flag"
            title={vulns.length === 0 ? 'No vulnerabilities tracked yet' : 'No vulnerabilities match the current filters'}
            action={vulns.length === 0 && projectId ? { label: 'Add your first vulnerability', onClick: openCreateModal } : undefined}
            pad={56}
          />
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {filtered.map(vuln => {
            const sevColor = VSEV_COLOR[vuln.severity]
            const ss = VSEV_STYLE[vuln.severity]
            return (
              <div key={vuln.id} style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, overflow: 'hidden' }}>
                <div style={{ display: 'flex' }}>
                  <div style={{ width: 3, flexShrink: 0, background: sevColor }} />
                  <div style={{ flex: 1, padding: '14px 16px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
                      <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 10, fontWeight: 700, textTransform: 'uppercase', fontFamily: 'var(--font-sans)', color: ss.color, background: ss.background, border: ss.border }}>
                        {vuln.severity}
                      </span>
                      <StatusDropdown current={vuln.status} onSelect={s => handleStatusChange(vuln, s)} />
                      {vuln.cve_id && (
                        <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 3, background: 'var(--bg)', border: ruleStrong, color: 'var(--fg-2)', fontFamily: 'var(--font-mono)' }}>
                          {vuln.cve_id}
                        </span>
                      )}
                      {vuln.cvss_score && (
                        <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 3, background: 'var(--bg)', border: ruleStrong, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>
                          CVSS {vuln.cvss_score}
                        </span>
                      )}
                    </div>

                    <h3 style={{ margin: '0 0 3px', fontSize: 13, fontWeight: 600, color: 'var(--fg)', fontFamily: 'var(--font-sans)' }}>{vuln.title}</h3>

                    {vuln.affected_asset && (
                      <p style={{ margin: '0 0 6px', fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>
                        Asset: {vuln.affected_asset}
                      </p>
                    )}

                    {vuln.description && (
                      <p style={{ margin: '0 0 8px', fontSize: 12, color: 'var(--fg-2)', lineHeight: 1.5, display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                        {vuln.description}
                      </p>
                    )}

                    {vuln.tags.length > 0 && (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 10 }}>
                        {vuln.tags.map(tag => (
                          <span key={tag} style={{ fontSize: 10, padding: '1px 7px', borderRadius: 10, background: 'rgba(240,168,58,0.06)', border: '1px solid rgba(240,168,58,0.2)', color: 'var(--accent)', fontFamily: 'var(--font-sans)' }}>
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}

                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>
                        {formatDate(vuln.created_at)}
                      </span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginLeft: 'auto' }}>
                        <button
                          onClick={() => handleAiRemediate(vuln)}
                          disabled={aiLoading === vuln.id}
                          title="AI Remediation"
                          style={{
                            display: 'flex', alignItems: 'center', gap: 5,
                            fontSize: 11, padding: '4px 10px', borderRadius: 4,
                            background: 'rgba(168,85,247,0.08)', border: '1px solid rgba(168,85,247,0.25)',
                            color: '#a855f7', cursor: aiLoading === vuln.id ? 'not-allowed' : 'pointer',
                            fontFamily: 'var(--font-sans)', opacity: aiLoading === vuln.id ? 0.6 : 1,
                          }}
                        >
                          <Brain size={11} /> AI Remediate
                        </button>
                        <button
                          onClick={() => openEditModal(vuln)}
                          style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, padding: '4px 10px', borderRadius: 4, background: 'none', border: ruleStrong, color: 'var(--fg-3)', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}
                        >
                          <Icon name="edit" size={11} color="currentColor" /> Edit
                        </button>
                        <button
                          onClick={() => handleDelete(vuln.id)}
                          style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, padding: '4px 10px', borderRadius: 4, background: 'none', border: '1px solid rgba(232,64,64,0.2)', color: 'var(--fg-3)', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}
                          onMouseEnter={e => { e.currentTarget.style.color = 'var(--crit)'; e.currentTarget.style.borderColor = 'rgba(232,64,64,0.5)' }}
                          onMouseLeave={e => { e.currentTarget.style.color = 'var(--fg-3)'; e.currentTarget.style.borderColor = 'rgba(232,64,64,0.2)' }}
                        >
                          <Icon name="trash" size={11} color="currentColor" /> Delete
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                {vuln.ai_remediation && (
                  <div style={{ borderTop: '1px solid rgba(168,85,247,0.15)', padding: '10px 16px', background: 'rgba(168,85,247,0.05)' }}>
                    <button
                      onClick={() => setAiExpanded(aiExpanded === vuln.id ? null : vuln.id)}
                      style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#a855f7', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-sans)', width: '100%' }}
                    >
                      <Sparkles size={11} />
                      <span style={{ fontWeight: 600 }}>AI Remediation Insight</span>
                      <Icon name={aiExpanded === vuln.id ? 'chev_u' : 'chev_d'} size={10} color="currentColor" style={{ marginLeft: 'auto' }} />
                    </button>
                    {aiExpanded === vuln.id && (
                      <div style={{ marginTop: 8, fontSize: 12, color: 'var(--fg-2)', lineHeight: 1.6, whiteSpace: 'pre-wrap', borderLeft: '2px solid rgba(168,85,247,0.4)', paddingLeft: 12, fontFamily: 'var(--font-sans)' }}>
                        {vuln.ai_remediation}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* Create / Edit Modal */}
      {showModal && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
          <div style={{ position: 'absolute', inset: 0, background: 'rgba(0,0,0,0.75)' }} onClick={() => setShowModal(false)} />
          <div style={{ position: 'relative', width: '100%', maxWidth: 600, background: 'var(--bg-2)', border: ruleStrong, borderRadius: 6, boxShadow: '0 16px 48px rgba(0,0,0,0.5)', display: 'flex', flexDirection: 'column', maxHeight: '90vh' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 20px', borderBottom: rule, flexShrink: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Icon name="shield" size={15} color="var(--crit)" />
                <h2 style={{ margin: 0, fontSize: 13, fontWeight: 700, color: 'var(--fg)', fontFamily: 'var(--font-sans)' }}>
                  {editingVuln ? 'Edit Vulnerability' : 'New Vulnerability'}
                </h2>
              </div>
              <button onClick={() => setShowModal(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0 }}>
                <Icon name="x" size={14} color="currentColor" />
              </button>
            </div>

            <div style={{ overflowY: 'auto', flex: 1, padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
              {modalError && (
                <div style={{ fontSize: 12, color: 'var(--crit)', background: 'rgba(232,64,64,0.08)', border: '1px solid rgba(232,64,64,0.3)', borderRadius: 3, padding: '7px 12px', fontFamily: 'var(--font-sans)' }}>
                  {modalError}
                </div>
              )}

              <div>
                <label style={labelStyle}>Title <span style={{ color: 'var(--crit)' }}>*</span></label>
                <input type="text" placeholder="e.g. SQL Injection in /login endpoint" value={formTitle} onChange={e => setFormTitle(e.target.value)} style={inputStyle} />
              </div>

              <div>
                <label style={labelStyle}>Description</label>
                <textarea rows={3} placeholder="Describe the vulnerability and its impact..." value={formDesc} onChange={e => setFormDesc(e.target.value)} style={{ ...inputStyle, resize: 'none' }} />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <label style={labelStyle}>Severity</label>
                  <select value={formSeverity} onChange={e => setFormSeverity(e.target.value as VulnSeverity)} style={{ ...inputStyle }}>
                    {ALL_SEVERITIES.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
                  </select>
                </div>
                {editingVuln && (
                  <div>
                    <label style={labelStyle}>Status</label>
                    <select value={formStatus} onChange={e => setFormStatus(e.target.value as VulnStatus)} style={{ ...inputStyle }}>
                      {ALL_STATUSES.map(s => <option key={s} value={s}>{VSTATUS_LABELS[s]}</option>)}
                    </select>
                  </div>
                )}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <label style={labelStyle}>CVSS Score</label>
                  <input type="text" placeholder="e.g. 9.8" value={formCvss} onChange={e => setFormCvss(e.target.value)} style={inputStyle} />
                </div>
                <div>
                  <label style={labelStyle}>CVE ID</label>
                  <input type="text" placeholder="e.g. CVE-2024-1234" value={formCve} onChange={e => setFormCve(e.target.value)} style={inputStyle} />
                </div>
              </div>

              <div>
                <label style={labelStyle}>Affected Asset</label>
                <input type="text" placeholder="e.g. 192.168.1.10 or https://example.com/login" value={formAsset} onChange={e => setFormAsset(e.target.value)} style={inputStyle} />
              </div>

              <div>
                <label style={labelStyle}>Remediation Notes</label>
                <textarea rows={3} placeholder="Steps to fix or mitigate this vulnerability..." value={formRemediation} onChange={e => setFormRemediation(e.target.value)} style={{ ...inputStyle, resize: 'none' }} />
              </div>

              <div>
                <label style={labelStyle}>Tags</label>
                <input type="text" placeholder="e.g. web, injection, authentication (comma-separated)" value={formTags} onChange={e => setFormTags(e.target.value)} style={inputStyle} />
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 8, padding: '12px 20px', borderTop: rule, flexShrink: 0 }}>
              <button onClick={() => setShowModal(false)} style={{ padding: '6px 14px', borderRadius: 4, background: 'none', border: ruleStrong, fontSize: 12, color: 'var(--fg-3)', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}>
                Cancel
              </button>
              <button
                onClick={handleSave}
                disabled={saving}
                style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 16px', borderRadius: 4, background: saving ? 'var(--bg)' : 'var(--accent)', color: saving ? 'var(--fg-3)' : 'var(--bg)', border: 'none', fontSize: 12, fontWeight: 700, cursor: saving ? 'not-allowed' : 'pointer', fontFamily: 'var(--font-sans)', opacity: saving ? 0.6 : 1 }}
              >
                {saving ? <Icon name="refresh" size={13} color="currentColor" /> : <Icon name="check" size={13} color="currentColor" />}
                {saving ? 'Saving…' : editingVuln ? 'Update' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Import Findings Modal */}
      {showImport && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
          <div style={{ position: 'absolute', inset: 0, background: 'rgba(0,0,0,0.75)' }} onClick={() => setShowImport(false)} />
          <div style={{ position: 'relative', width: '100%', maxWidth: 520, background: 'var(--bg-2)', border: ruleStrong, borderRadius: 6, boxShadow: '0 16px 48px rgba(0,0,0,0.5)', display: 'flex', flexDirection: 'column', maxHeight: '80vh' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 20px', borderBottom: rule, flexShrink: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Icon name="download" size={14} color="var(--accent)" />
                <h2 style={{ margin: 0, fontSize: 13, fontWeight: 700, color: 'var(--fg)', fontFamily: 'var(--font-sans)' }}>Import from Scan Findings</h2>
              </div>
              <button onClick={() => setShowImport(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0 }}>
                <Icon name="x" size={14} color="currentColor" />
              </button>
            </div>

            <div style={{ overflowY: 'auto', flex: 1, padding: '14px 20px' }}>
              {findingsList.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '40px 0' }}>
                  <AlertTriangle size={32} style={{ margin: '0 auto 8px', color: 'var(--fg-3)', display: 'block' }} />
                  <p style={{ margin: 0, fontSize: 13, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>No scan findings found for this project.</p>
                  <p style={{ margin: '4px 0 0', fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>Run a scan first to populate findings.</p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <p style={{ margin: '0 0 8px', fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>
                    Select findings to import as vulnerabilities ({selectedFindingIds.size} selected)
                  </p>
                  {findingsList.map(f => {
                    const fs = VSEV_STYLE[(f.severity as VulnSeverity) ?? 'info']
                    return (
                      <label
                        key={f.id}
                        style={{
                          display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 12px',
                          borderRadius: 3, border: ruleStrong, cursor: 'pointer',
                          background: selectedFindingIds.has(f.id) ? 'rgba(240,168,58,0.05)' : 'var(--bg)',
                        }}
                      >
                        <input type="checkbox" checked={selectedFindingIds.has(f.id)} onChange={() => toggleFinding(f.id)} style={{ marginTop: 2, accentColor: 'var(--accent)' }} />
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                            <span style={{ fontSize: 10, padding: '1px 6px', borderRadius: 8, fontWeight: 700, textTransform: 'uppercase', fontFamily: 'var(--font-sans)', color: fs.color, background: fs.background, border: fs.border }}>
                              {f.severity}
                            </span>
                            <span style={{ fontSize: 12, color: 'var(--fg)', fontFamily: 'var(--font-sans)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</span>
                          </div>
                          {f.description && (
                            <p style={{ margin: 0, fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.description}</p>
                          )}
                        </div>
                      </label>
                    )
                  })}
                </div>
              )}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 8, padding: '12px 20px', borderTop: rule, flexShrink: 0 }}>
              <button onClick={() => setShowImport(false)} style={{ padding: '6px 14px', borderRadius: 4, background: 'none', border: ruleStrong, fontSize: 12, color: 'var(--fg-3)', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}>
                Cancel
              </button>
              <button
                onClick={handleImport}
                disabled={importing || selectedFindingIds.size === 0}
                style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 16px', borderRadius: 4, background: importing || selectedFindingIds.size === 0 ? 'var(--bg)' : 'var(--accent)', color: importing || selectedFindingIds.size === 0 ? 'var(--fg-3)' : 'var(--bg)', border: 'none', fontSize: 12, fontWeight: 700, cursor: importing || selectedFindingIds.size === 0 ? 'not-allowed' : 'pointer', fontFamily: 'var(--font-sans)', opacity: importing || selectedFindingIds.size === 0 ? 0.5 : 1 }}
              >
                {importing ? <Icon name="refresh" size={13} color="currentColor" /> : <Icon name="download" size={13} color="currentColor" />}
                {importing ? 'Importing…' : `Import ${selectedFindingIds.size > 0 ? selectedFindingIds.size : ''} Selected`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Scan Findings sub-components ───────────────────────────────────────────────

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

function Counter({ label, v, color }: { label: string; v: number; color: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'baseline', gap: 5 }}>
      <span className="mono tnum" style={{ fontSize: 17, color, fontWeight: 500 }}>{v}</span>
      <span className="mono" style={{ fontSize: 9, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.14em' }}>{label}</span>
    </div>
  )
}

function SevSquare({ sev }: { sev: string }) {
  return <div style={{ width: 10, height: 10, background: SEV_COLOR[sev] ?? 'var(--fg-4)', flexShrink: 0 }} />
}

function StatusPill({ status }: { status: string }) {
  const ss = STATUS_STYLES[status] ?? STATUS_STYLES.open
  return (
    <span style={{
      fontSize: 9, fontWeight: 600, padding: '2px 7px', letterSpacing: '0.06em',
      fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
      color: ss.color, background: ss.bg, border: `1px solid ${ss.border}`,
    }}>
      {status}
    </span>
  )
}

interface DetailProps {
  finding: FindingRow
  tagInput: string
  setTagInput: (v: string) => void
  onAddTag: () => void
  onRemoveTag: (tag: string) => void
  onChangeStatus: (id: string, s: FindingStatus) => void
  onShowFpModal: () => void
  onRestore: (id: string) => void
  onVerify: (id: string) => void
  onReport: (finding: FindingRow) => void
  onDelete: (id: string) => void
  onClose: () => void
}

function FindingDetail({ finding, tagInput, setTagInput, onAddTag, onRemoveTag, onChangeStatus, onShowFpModal, onRestore, onVerify, onReport, onDelete, onClose }: DetailProps) {
  const { options: aiModels, modelKey: aiModel, setModelKey: setAiModel } = useAiModel()
  const [aiResult, setAiResult] = useState<string | null>(null)
  const [aiGenerating, setAiGenerating] = useState(false)
  const [statusOpen, setStatusOpen] = useState(false)
  const tagInputRef = useRef<HTMLInputElement>(null)

  async function generateRemediation() {
    if (!aiModel) return
    setAiGenerating(true)
    setAiResult(null)
    try {
      const prompt = `You are a senior penetration tester and security engineer. Give direct, technical remediation guidance for the following vulnerability. No emojis. No decorative symbols. No disclaimers. No preamble. Use plain markdown with headers and lists only where they add clarity.\n\nTitle: ${finding.title}\nSeverity: ${finding.severity}\nCVE: ${finding.cve_id ?? 'N/A'}\nTarget: ${finding.target ?? 'N/A'}\nDescription: ${finding.description ?? 'No description'}\n\n## Immediate Mitigation\nState the fastest way to reduce exposure right now.\n\n## Remediation\nExplain the proper long-term fix with specific configuration changes, commands, or code where applicable.\n\n## Verification\nProvide a command or test to confirm the issue is resolved.`
      const text = await runCompletion(aiModel, [{ role: 'user', content: prompt }])
      setAiResult(text || 'No response from model.')
    } catch {
      setAiResult('AI request failed. Check the selected model / Settings → AI.')
    } finally {
      setAiGenerating(false)
    }
  }
  const fTags = (finding.tags ?? '').split(',').map(t => t.trim()).filter(Boolean)
  const fStatus = (finding.status || 'open') as FindingStatus
  const ss = STATUS_STYLES[fStatus] ?? STATUS_STYLES.open

  return (
    <div style={{ overflowY: 'auto', background: 'var(--bg-2)', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <div style={{ padding: '18px var(--pad)', borderBottom: rule, flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
          <div className="smcap">{finding.id.slice(0, 8)} · {finding.cve_id ?? 'manual finding'}</div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', padding: 0, flexShrink: 0 }}>
            <X size={14} />
          </button>
        </div>
        <h2 style={{ margin: '8px 0 0', fontFamily: 'var(--font-serif)', fontWeight: 500, fontSize: 20, lineHeight: 1.25, letterSpacing: '-0.01em', color: 'var(--fg)' }}>
          {finding.title}
        </h2>
        <div style={{ display: 'flex', gap: 8, marginTop: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{
            fontSize: 10, fontWeight: 700, padding: '2px 8px', fontFamily: 'var(--font-mono)',
            textTransform: 'uppercase', letterSpacing: '0.1em',
            color: SEV_COLOR[finding.severity] ?? 'var(--fg-3)',
            background: `${SEV_COLOR[finding.severity] ?? '#888'}18`,
            border: `1px solid ${SEV_COLOR[finding.severity] ?? 'var(--rule-strong)'}44`,
          }}>{finding.severity}</span>
          {finding.cvss_score && (
            <span className="badge badge-accent">cvss {finding.cvss_score}</span>
          )}
          <StatusPill status={fStatus} />
        </div>
      </div>

      <div style={{ padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 14, flex: 1 }}>
        {/* KV metadata */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '4px 16px' }}>
          {[
            { k: 'target',  v: finding.target || '—' },
            { k: 'project', v: finding.project || '—' },
            { k: 'cve',     v: finding.cve_id || '—' },
            { k: 'created', v: finding.created_at ? new Date(finding.created_at).toLocaleDateString() : '—' },
          ].map(({ k, v }) => (
            <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px dashed var(--rule)' }}>
              <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{k}</span>
              <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v}</span>
            </div>
          ))}
        </div>

        {/* Description */}
        {finding.description && (
          <div style={{ border: rule, padding: 14 }}>
            <div className="smcap" style={{ marginBottom: 6 }}>Description</div>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.6, margin: 0, fontFamily: 'var(--font-serif)', whiteSpace: 'pre-wrap' }}>
              {finding.description}
            </p>
          </div>
        )}

        {/* Remediation / solution (e.g. Nessus-provided) */}
        {finding.remediation && (
          <div style={{ border: rule, padding: 14 }}>
            <div className="smcap" style={{ marginBottom: 6 }}>Solution</div>
            <p style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.6, margin: 0, fontFamily: 'var(--font-serif)', whiteSpace: 'pre-wrap' }}>
              {finding.remediation}
            </p>
          </div>
        )}

        {/* Tags */}
        <div style={{ border: rule, padding: 12 }}>
          <div className="smcap" style={{ marginBottom: 8 }}>Tags</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
            {fTags.map(tag => (
              <span key={tag} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10, background: 'rgba(240,168,58,0.08)', color: 'var(--accent)', border: '1px solid rgba(240,168,58,0.25)', padding: '2px 8px' }}>
                {tag}
                <button onClick={() => onRemoveTag(tag)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--accent)', padding: 0, display: 'flex' }}>
                  <X size={9} />
                </button>
              </span>
            ))}
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              <Tag size={10} style={{ color: 'var(--fg-4)' }} />
              <input
                ref={tagInputRef}
                type="text"
                placeholder="add tag…"
                value={tagInput}
                onChange={e => setTagInput(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); onAddTag() } }}
                style={{ background: 'transparent', fontSize: 10, color: 'var(--fg-3)', outline: 'none', width: 70, border: 'none', borderBottom: rule }}
              />
            </div>
          </div>
          {finding.fp_reason && (
            <div style={{ marginTop: 8, fontSize: 10, color: '#a78bfa', background: 'rgba(167,139,250,0.08)', border: '1px solid rgba(167,139,250,0.2)', padding: '4px 8px' }}>
              FP: {finding.fp_reason}
            </div>
          )}
        </div>

        {/* Status change */}
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => setStatusOpen(o => !o)}
            style={{
              width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '8px 12px', background: ss.bg, border: `1px solid ${ss.border}`,
              cursor: 'pointer', color: ss.color, fontFamily: 'var(--font-mono)', fontSize: 11,
            }}
          >
            <span style={{ textTransform: 'uppercase', letterSpacing: '0.1em' }}>Status: {fStatus}</span>
            <ChevronDown size={12} style={{ transform: statusOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }} />
          </button>
          {statusOpen && (
            <div style={{ position: 'absolute', left: 0, right: 0, top: '100%', background: 'var(--bg-2)', border: rule, zIndex: 20 }}>
              {STATUS_OPTIONS.filter(o => o !== 'false_positive').map(opt => {
                const os = STATUS_STYLES[opt]
                return (
                  <button
                    key={opt}
                    onClick={() => { onChangeStatus(finding.id, opt); setStatusOpen(false) }}
                    style={{
                      display: 'block', width: '100%', padding: '8px 12px', textAlign: 'left',
                      fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.1em',
                      background: opt === fStatus ? os.bg : 'none',
                      color: opt === fStatus ? os.color : 'var(--fg-3)',
                      border: 'none', borderBottom: rule, cursor: 'pointer',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    {opt}
                  </button>
                )
              })}
            </div>
          )}
        </div>

        {/* AI Remediation */}
        <div style={{ border: `1px solid ${aiResult ? 'rgba(168,85,247,0.5)' : 'var(--rule)'}`, background: aiResult ? 'rgba(168,85,247,0.03)' : 'transparent' }}>
          <div className="sec-h" style={{ gap: 6 }}>
            <span className="title" style={{ marginRight: 'auto' }}>AI REMEDIATION</span>
            <AiModelSelect value={aiModel} onChange={setAiModel} options={aiModels} style={{ maxWidth: 150 }} />
            <button
              onClick={generateRemediation}
              disabled={!aiModel || aiGenerating}
              style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, padding: '3px 10px', background: aiModel && !aiGenerating ? 'rgba(168,85,247,0.12)' : 'transparent', border: '1px solid rgba(168,85,247,0.35)', color: aiModel && !aiGenerating ? '#a855f7' : 'var(--fg-4)', cursor: aiModel && !aiGenerating ? 'pointer' : 'not-allowed', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap', letterSpacing: '0.06em' }}
            >
              <Brain size={9} /> {aiGenerating ? 'Generating…' : 'Generate'}
            </button>
          </div>
          {aiResult && (
            <div style={{ padding: '10px 14px', fontSize: 11.5, color: 'var(--fg-2)', lineHeight: 1.7, borderTop: '1px solid rgba(168,85,247,0.2)', fontFamily: 'var(--font-sans)' }}>
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                  h2: ({ children }) => <p style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.12em', color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', margin: '12px 0 4px' }}>{children}</p>,
                  h3: ({ children }) => <p style={{ fontSize: 10, fontWeight: 600, color: 'var(--fg-2)', fontFamily: 'var(--font-mono)', margin: '10px 0 3px' }}>{children}</p>,
                  p: ({ children }) => <p style={{ margin: '0 0 6px', fontSize: 11.5, color: 'var(--fg-2)' }}>{children}</p>,
                  ul: ({ children }) => <ul style={{ margin: '0 0 6px', paddingLeft: 16 }}>{children}</ul>,
                  ol: ({ children }) => <ol style={{ margin: '0 0 6px', paddingLeft: 16 }}>{children}</ol>,
                  li: ({ children }) => <li style={{ fontSize: 11.5, color: 'var(--fg-2)', marginBottom: 2 }}>{children}</li>,
                  code: ({ children, className }) => className
                    ? <pre style={{ background: 'var(--bg-3)', border: '1px solid var(--rule)', padding: '8px 10px', fontSize: 10.5, fontFamily: 'var(--font-mono)', color: 'var(--fg)', overflowX: 'auto', margin: '6px 0' }}><code>{children}</code></pre>
                    : <code style={{ fontFamily: 'var(--font-mono)', fontSize: 10.5, color: 'var(--accent)', background: 'var(--bg-3)', padding: '1px 4px' }}>{children}</code>,
                  strong: ({ children }) => <strong style={{ fontWeight: 600, color: 'var(--fg)' }}>{children}</strong>,
                }}
              >
                {aiResult}
              </ReactMarkdown>
            </div>
          )}
          {!aiResult && !aiGenerating && (
            <div style={{ padding: '6px 12px' }}>
              <p style={{ fontSize: 11, color: 'var(--fg-4)', margin: 0 }}>Local Ollama · no external API calls</p>
            </div>
          )}
        </div>

        {/* Action buttons */}
        <div style={{ display: 'flex', gap: 6 }}>
          <button
            className="btn btn-sm"
            style={{ flex: 1, justifyContent: 'center' }}
            onClick={() => onVerify(finding.id)}
            disabled={fStatus === 'in-review'}
            title="Mark this finding as verified / in review"
          >
            <Icon name="check" size={9} /> Verify
          </button>
          <button
            className="btn btn-sm"
            style={{ flex: 1, justifyContent: 'center' }}
            onClick={() => tagInputRef.current?.focus()}
            title="Add a tag to this finding"
          >
            <Icon name="flag" size={9} /> Tag
          </button>
          <button
            className="btn btn-sm btn-primary"
            style={{ flex: 1, justifyContent: 'center' }}
            onClick={() => onReport(finding)}
            title="Open the report for this finding's project"
          >
            <Icon name="file" size={9} color="#1a1408" /> Report
          </button>
        </div>

        {/* FP / Delete row */}
        <div style={{ display: 'flex', gap: 6, paddingTop: 4, borderTop: '1px dashed var(--rule)' }}>
          {fStatus === 'false_positive' ? (
            <button
              onClick={() => onRestore(finding.id)}
              className="btn btn-sm btn-ghost"
              style={{ color: '#a78bfa', borderColor: 'rgba(167,139,250,0.3)' }}
            >
              <RotateCcw size={9} /> Restore
            </button>
          ) : (
            <button
              onClick={onShowFpModal}
              className="btn btn-sm btn-ghost"
            >
              <EyeOff size={9} /> False positive
            </button>
          )}
          <button
            onClick={() => onDelete(finding.id)}
            className="btn btn-sm btn-ghost"
            style={{ marginLeft: 'auto', color: 'var(--crit)', borderColor: 'rgba(232,64,64,0.25)' }}
          >
            <Trash2 size={9} /> Delete
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main AllFindings page ──────────────────────────────────────────────────────

export default function AllFindings() {
  const { selectedProject: sp, projects, addProject, setSelectedProject: setStoreProject } = useAppStore()
  const projectId = sp?.id ?? ''
  const toast = useToast()
  const navigate = useNavigate()
  const confirm = useConfirm()
  const [activeTab, setActiveTab] = useState<'findings' | 'vulns'>('findings')
  const [searchParams, setSearchParams] = useSearchParams()
  const [findings, setFindings] = useState<FindingRow[]>([])
  const [loading, setLoading] = useState(true)
  const [sevFilter, setSevFilter] = useState(searchParams.get('severity') ?? 'all')
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') ?? 'all')
  const [search, setSearch] = useState(searchParams.get('q') ?? '')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [exportOpen, setExportOpen] = useState(false)
  const [fpModal, setFpModal] = useState<{ id: string; title: string } | null>(null)
  const [fpReason, setFpReason] = useState('')
  const [fpSaving, setFpSaving] = useState(false)
  const [showFp, setShowFp] = useState(false)
  const [tagInputs, setTagInputs] = useState<Record<string, string>>({})
  const exportRef = useRef<HTMLDivElement>(null)

  interface FPRule { id: string; tool: string | null; title_contains: string; created_at: string }
  interface ProjectOpt { id: string; name: string }
  const [rulesOpen, setRulesOpen] = useState(false)
  const [ruleProjects, setRuleProjects] = useState<ProjectOpt[]>([])
  const [ruleProjectId, setRuleProjectId] = useState('')
  const [fpRules, setFpRules] = useState<FPRule[]>([])
  const [ruleTool, setRuleTool] = useState('')
  const [ruleTitleContains, setRuleTitleContains] = useState('')
  const [ruleSaving, setRuleSaving] = useState(false)

  interface NessusScan { id: number; name: string; status: string; last_modification_date: number; host_count: number }
  interface NessusHost { host_id: number; hostname: string; critical: number; high: number; medium: number; low: number; info: number }
  const [showNessusModal, setShowNessusModal] = useState(false)
  const [nessusScans, setNessusScans] = useState<NessusScan[]>([])
  const [nessusLoadingScans, setNessusLoadingScans] = useState(false)
  const [nessusImportError, setNessusImportError] = useState('')
  const [nessusImportResult, setNessusImportResult] = useState<{ scan_ids: string[]; findings_created: number; hosts_processed: number; targets_created: number; project_id: string } | null>(null)
  // Wizard state
  const [nessusStep, setNessusStep] = useState<'scans' | 'hosts'>('scans')
  const [nessusSelectedScan, setNessusSelectedScan] = useState<{ id: number; name: string } | null>(null)
  const [nessusScanHosts, setNessusScanHosts] = useState<NessusHost[]>([])
  const [nessusLoadingHosts, setNessusLoadingHosts] = useState(false)
  const [nessusSelectedHostIds, setNessusSelectedHostIds] = useState<Set<number>>(new Set())
  const [nessusProjectMode, setNessusProjectMode] = useState<'existing' | 'new'>('existing')
  const [nessusImportProjectId, setNessusImportProjectId] = useState(projectId)
  const [nessusNewProjectName, setNessusNewProjectName] = useState('')
  const [nessusImporting, setNessusImporting] = useState(false)

  useEffect(() => {
    function handler(e: MouseEvent) {
      if (exportRef.current && !exportRef.current.contains(e.target as Node)) setExportOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  useEffect(() => {
    setLoading(true)
    const url = projectId
      ? `${getApiBase()}/findings?project_id=${projectId}`
      : `${getApiBase()}/findings`
    fetch(url)
      .then(r => r.json())
      .then(setFindings)
      .finally(() => setLoading(false))
  }, [projectId])

  useEffect(() => {
    if (!rulesOpen) return
    fetch(`${getApiBase()}/projects`).then(r => r.json()).then((data: ProjectOpt[]) => {
      setRuleProjects(data)
      if (data.length > 0 && !ruleProjectId) setRuleProjectId(data[0].id)
    }).catch(() => {})
  }, [rulesOpen])

  useEffect(() => {
    if (!ruleProjectId) return
    fetch(`${getApiBase()}/projects/${ruleProjectId}/fp-rules`).then(r => r.json()).then(setFpRules).catch(() => setFpRules([]))
  }, [ruleProjectId])

  function updateFilter(sev: string, q: string, stat: string) {
    const params: Record<string, string> = {}
    if (sev !== 'all') params.severity = sev
    if (q) params.q = q
    if (stat !== 'all') params.status = stat
    setSearchParams(params, { replace: true })
  }

  function exportCSV() {
    const header = 'severity,status,title,target,project,cve_id,cvss_score,created_at,description'
    const rows = filtered.map(f =>
      [f.severity, f.status, f.title, f.target, f.project, f.cve_id ?? '', f.cvss_score ?? '', f.created_at ?? '', f.description ?? '']
        .map(v => `"${String(v).replace(/"/g, '""')}"`)
        .join(',')
    )
    const blob = new Blob([header + '\n' + rows.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'findings.csv'; a.click()
    URL.revokeObjectURL(url)
    setExportOpen(false)
  }

  function exportJSON() {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url; a.download = 'findings.json'; a.click()
    URL.revokeObjectURL(url)
    setExportOpen(false)
  }

  function changeStatus(id: string, newStatus: FindingStatus) {
    fetch(`${getApiBase()}/findings/${id}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus }),
    }).then(() => setFindings(prev => prev.map(f => f.id === id ? { ...f, status: newStatus } : f)))
  }

  function verifyFinding(id: string) {
    changeStatus(id, 'in-review')
    toast.success('Finding marked for verification')
  }

  function reportFinding(finding: FindingRow) {
    const proj = projects.find(p => p.id === finding.project_id)
    if (proj) setStoreProject(proj)
    else if (!finding.project_id) {
      toast.error('This finding is not linked to a project')
      return
    }
    navigate('/reports')
  }

  function addTag(id: string) {
    const raw = (tagInputs[id] ?? '').trim()
    if (!raw) return
    const finding = findings.find(f => f.id === id)
    if (!finding) return
    const existing = (finding.tags ?? '').split(',').map(t => t.trim()).filter(Boolean)
    if (existing.includes(raw)) { setTagInputs(p => ({ ...p, [id]: '' })); return }
    const newTags = [...existing, raw]
    fetch(`${getApiBase()}/findings/${id}/tags`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tags: newTags }),
    }).then(() => {
      setFindings(prev => prev.map(f => f.id === id ? { ...f, tags: newTags.join(',') } : f))
      setTagInputs(p => ({ ...p, [id]: '' }))
    })
  }

  function removeTag(id: string, tag: string) {
    const finding = findings.find(f => f.id === id)
    if (!finding) return
    const newTags = (finding.tags ?? '').split(',').map(t => t.trim()).filter(t => t && t !== tag)
    fetch(`${getApiBase()}/findings/${id}/tags`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tags: newTags }),
    }).then(() => setFindings(prev => prev.map(f => f.id === id ? { ...f, tags: newTags.join(',') } : f)))
  }

  async function suppressFinding(id: string, reason: string) {
    setFpSaving(true)
    try {
      await fetch(`${getApiBase()}/findings/${id}/suppress`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason }),
      })
      setFindings(prev => prev.map(f => f.id === id ? { ...f, status: 'false_positive', fp_reason: reason } : f))
      setFpModal(null)
      setFpReason('')
    } finally {
      setFpSaving(false)
    }
  }

  async function restoreFinding(id: string) {
    await fetch(`${getApiBase()}/findings/${id}/restore`, { method: 'POST' })
    setFindings(prev => prev.map(f => f.id === id ? { ...f, status: 'open', fp_reason: null } : f))
  }

  async function deleteFinding(id: string) {
    const ok = await confirm({
      title: 'Delete finding?',
      message: 'This permanently removes the finding from the engagement. This cannot be undone.',
      confirmLabel: 'Delete',
      danger: true,
    })
    if (!ok) return
    try {
      const res = await fetch(`${getApiBase()}/findings/${id}`, { method: 'DELETE' })
      if (res.ok) {
        setFindings(prev => prev.filter(f => f.id !== id))
        if (selectedId === id) setSelectedId(null)
        toast.success('Finding deleted')
      } else {
        toast.error('Could not delete finding')
      }
    } catch {
      toast.error('Could not delete finding — backend unreachable')
    }
  }

  async function addFpRule() {
    if (!ruleProjectId || !ruleTitleContains.trim()) return
    setRuleSaving(true)
    try {
      const res = await fetch(`${getApiBase()}/projects/${ruleProjectId}/fp-rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool: ruleTool.trim() || null, title_contains: ruleTitleContains.trim() }),
      })
      if (res.ok) {
        const newRule = await res.json()
        setFpRules(prev => [...prev, newRule])
        setRuleTitleContains('')
        setRuleTool('')
      }
    } finally {
      setRuleSaving(false)
    }
  }

  async function deleteFpRule(ruleId: string) {
    const ok = await confirm({
      title: 'Delete suppression rule?',
      message: 'Findings matching this rule will no longer be auto-suppressed.',
      confirmLabel: 'Delete',
      danger: true,
    })
    if (!ok) return
    await fetch(`${getApiBase()}/projects/${ruleProjectId}/fp-rules/${ruleId}`, { method: 'DELETE' })
    setFpRules(prev => prev.filter(r => r.id !== ruleId))
  }

  async function openNessusModal() {
    setShowNessusModal(true)
    setNessusStep('scans')
    setNessusSelectedScan(null)
    setNessusScanHosts([])
    setNessusSelectedHostIds(new Set())
    setNessusImportResult(null)
    setNessusImportError('')
    setNessusImportProjectId(projectId)
    setNessusNewProjectName('')
    setNessusProjectMode('existing')
    setNessusLoadingScans(true)
    if (ruleProjects.length === 0) {
      fetch(`${getApiBase()}/projects`).then(r => r.json()).then((data: ProjectOpt[]) => {
        setRuleProjects(data)
        if (!projectId && data.length > 0) setNessusImportProjectId(data[0].id)
      }).catch(() => {})
    }
    try {
      const res = await fetch(`${getApiBase()}/nessus/scans`)
      if (!res.ok) { const d = await res.json(); setNessusImportError(d.detail ?? 'Failed to fetch scans'); setNessusScans([]); return }
      setNessusScans(await res.json())
    } catch { setNessusImportError('Could not connect to Nessus. Check Settings → Nessus.') }
    finally { setNessusLoadingScans(false) }
  }

  async function selectNessusScan(scan: NessusScan) {
    setNessusSelectedScan({ id: scan.id, name: scan.name })
    setNessusSelectedHostIds(new Set())
    setNessusImportResult(null)
    setNessusImportError('')
    setNessusLoadingHosts(true)
    setNessusStep('hosts')
    try {
      const res = await fetch(`${getApiBase()}/nessus/scans/${scan.id}`)
      if (!res.ok) { setNessusImportError('Failed to load hosts.'); return }
      const data = await res.json()
      const hosts: NessusHost[] = data.hosts || []
      setNessusScanHosts(hosts)
      setNessusSelectedHostIds(new Set(hosts.map((h: NessusHost) => h.host_id)))
    } catch { setNessusImportError('Failed to load hosts.') }
    finally { setNessusLoadingHosts(false) }
  }

  async function handleNessusImport() {
    if (nessusSelectedHostIds.size === 0) { setNessusImportError('Select at least one host.'); return }
    if (nessusProjectMode === 'existing' && !nessusImportProjectId) { setNessusImportError('Select a project.'); return }
    if (nessusProjectMode === 'new' && !nessusNewProjectName.trim()) { setNessusImportError('Enter a project name.'); return }
    setNessusImporting(true)
    setNessusImportResult(null)
    setNessusImportError('')
    try {
      const body: Record<string, unknown> = { host_ids: [...nessusSelectedHostIds] }
      if (nessusProjectMode === 'existing') {
        body.project_id = nessusImportProjectId
      } else {
        body.project_name = nessusNewProjectName.trim()
      }
      const res = await fetch(`${getApiBase()}/nessus/scans/${nessusSelectedScan!.id}/import`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!res.ok) { const d = await res.json(); setNessusImportError(d.detail ?? 'Import failed'); return }
      const data = await res.json()
      setNessusImportResult(data)
      if (nessusProjectMode === 'new' && data.project_id) {
        fetch(`${getApiBase()}/projects/${data.project_id}`)
          .then(r => r.ok ? r.json() : null)
          .then(proj => { if (proj) { addProject(proj); setStoreProject(proj) } })
          .catch(() => {})
      }
      const url = projectId ? `${getApiBase()}/findings?project_id=${projectId}` : `${getApiBase()}/findings`
      fetch(url).then(r => r.json()).then(setFindings).catch(() => {})
    } catch { setNessusImportError('Import request failed.') }
    finally { setNessusImporting(false) }
  }

  const filtered = findings.filter(f => {
    if (!showFp && f.status === 'false_positive') return false
    if (sevFilter !== 'all' && f.severity !== sevFilter) return false
    if (statusFilter !== 'all' && f.status !== statusFilter) return false
    if (search) {
      const q = search.toLowerCase()
      return (
        f.title.toLowerCase().includes(q) ||
        f.target.toLowerCase().includes(q) ||
        f.project.toLowerCase().includes(q) ||
        (f.cve_id?.toLowerCase().includes(q) ?? false)
      )
    }
    return true
  })

  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    if (f.status !== 'false_positive') acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})

  const selectedFinding = filtered.find(f => f.id === selectedId) ?? null

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Page header */}
      <div style={{ borderBottom: rule, padding: '18px var(--pad)', display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: 16, flexShrink: 0 }}>
        <div>
          <div className="smcap" style={{ marginBottom: 4 }}>Findings & Vulnerabilities</div>
          <h1 className="mono" style={{ margin: 0, fontWeight: 500, fontSize: 22, letterSpacing: '-0.01em' }}>All Findings</h1>
          <div style={{ color: 'var(--fg-3)', fontSize: 12, marginTop: 6 }}>
            {activeTab === 'findings'
              ? `${filtered.length} of ${findings.length} findings${counts.critical ? ` · ${counts.critical} critical` : ''}${counts.high ? ` · ${counts.high} high` : ''}`
              : 'Tracked vulnerabilities for this project'}
          </div>
        </div>
        {activeTab === 'findings' && (
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>
            <button
              onClick={() => setShowFp(p => !p)}
              className={`btn ${showFp ? '' : 'btn-ghost'}`}
              style={showFp ? { color: '#a78bfa', borderColor: 'rgba(167,139,250,0.4)' } : {}}
            >
              <EyeOff size={11} /> {showFp ? 'Hide FPs' : 'Show FPs'}
            </button>
            <button onClick={openNessusModal} className="btn btn-ghost">
              <Icon name="scan" size={11} color="currentColor" /> Nessus
            </button>
            <div style={{ position: 'relative' }} ref={exportRef}>
              <button onClick={() => setExportOpen(o => !o)} className="btn">
                <Download size={11} /> Export <ChevronDown size={10} />
              </button>
              {exportOpen && (
                <div style={{ position: 'absolute', right: 0, marginTop: 4, width: 144, background: 'var(--bg-2)', border: rule, zIndex: 10, overflow: 'hidden' }}>
                  <button onClick={exportCSV} style={{ display: 'block', width: '100%', padding: '10px 16px', textAlign: 'left', fontSize: 11, color: 'var(--fg-2)', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}>
                    Download CSV
                  </button>
                  <button onClick={exportJSON} style={{ display: 'block', width: '100%', padding: '10px 16px', textAlign: 'left', fontSize: 11, color: 'var(--fg-2)', background: 'none', border: 'none', cursor: 'pointer', borderTop: rule, fontFamily: 'var(--font-mono)' }}>
                    Download JSON
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--rule)', background: 'var(--bg-2)', flexShrink: 0 }}>
        {(['findings', 'vulns'] as const).map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)} style={{
            padding: '10px 20px', fontSize: 11, fontFamily: 'var(--font-mono)',
            textTransform: 'uppercase', letterSpacing: '0.1em', border: 'none',
            borderBottom: activeTab === tab ? '2px solid var(--accent)' : '2px solid transparent',
            background: 'transparent', color: activeTab === tab ? 'var(--accent)' : 'var(--fg-3)',
            cursor: 'pointer',
          }}>
            {tab === 'findings' ? 'Scan Findings' : 'Vuln Records'}
          </button>
        ))}
      </div>

      {activeTab === 'vulns' ? (
        <VulnRecords projectId={projectId} />
      ) : (
        <>
          {/* Filter strip */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px var(--pad)', borderBottom: rule, background: 'var(--bg-2)', flexShrink: 0, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <Search size={12} color="var(--fg-3)" />
              <input
                placeholder="search · cve · title"
                value={search}
                onChange={e => { setSearch(e.target.value); updateFilter(sevFilter, e.target.value, statusFilter) }}
                style={{ width: 220 }}
              />
            </div>
            <div style={{ width: 1, height: 18, background: 'var(--rule)' }} />
            <SegBtns
              options={['all', ...SEV_ORDER.filter(s => counts[s])]}
              value={sevFilter}
              onChange={v => { setSevFilter(v); updateFilter(v, search, statusFilter) }}
            />
            <div style={{ width: 1, height: 18, background: 'var(--rule)' }} />
            <SegBtns
              options={['all', 'open', 'in-review', 'remediated', 'accepted']}
              value={statusFilter}
              onChange={v => { setStatusFilter(v); updateFilter(sevFilter, search, v) }}
            />
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 14 }}>
              <Counter label="critical" v={counts.critical ?? 0} color="var(--crit)" />
              <Counter label="high"     v={counts.high     ?? 0} color="var(--high)" />
              <Counter label="medium"   v={counts.medium   ?? 0} color="var(--med)" />
              <Counter label="low"      v={counts.low      ?? 0} color="var(--ok)" />
            </div>
          </div>

          {/* Main split */}
          <div style={{ display: 'grid', gridTemplateColumns: selectedFinding ? '1fr 480px' : '1fr', flex: 1, minHeight: 0 }}>
            {/* List */}
            <div style={{ overflowY: 'auto', borderRight: selectedFinding ? rule : 'none' }}>
              {loading ? (
                <div style={{ paddingTop: 4 }}><SkeletonRows rows={8} cols={4} /></div>
              ) : filtered.length === 0 ? (
                <EmptyState icon="flag" title="No findings match the current filter" hint="Clear the filters above, or import a Nessus scan to bring findings in." pad={52} />
              ) : (
                <table className="data">
                  <thead>
                    <tr>
                      <th style={{ width: 26 }}></th>
                      <th style={{ width: 58 }}>CVSS</th>
                      <th>Finding</th>
                      <th style={{ width: 190 }}>Target</th>
                      <th style={{ width: 100 }}>Status</th>
                      <th style={{ width: 120 }}>Project</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map(f => (
                      <tr
                        key={f.id}
                        className={selectedId === f.id ? 'selected' : ''}
                        onClick={() => setSelectedId(selectedId === f.id ? null : f.id)}
                        style={{ cursor: 'pointer' }}
                      >
                        <td><SevSquare sev={f.severity} /></td>
                        <td className="mono tnum" style={{
                          color: f.cvss_score
                            ? parseFloat(f.cvss_score) >= 9 ? 'var(--crit)' : parseFloat(f.cvss_score) >= 7 ? 'var(--high)' : 'var(--fg-2)'
                            : 'var(--fg-4)',
                        }}>
                          {f.cvss_score ?? '—'}
                        </td>
                        <td>
                          <div style={{ fontWeight: 500, fontSize: 12.5 }}>{f.title}</div>
                          <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', marginTop: 2 }}>
                            {f.cve_id ?? 'no cve'}
                          </div>
                        </td>
                        <td className="mono" style={{ fontSize: 11, color: 'var(--fg-2)', maxWidth: 190, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {f.target}
                        </td>
                        <td><StatusPill status={f.status || 'open'} /></td>
                        <td className="mono" style={{ fontSize: 10.5, color: 'var(--fg-3)', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {f.project}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            {/* Detail panel */}
            {selectedFinding && (
              <FindingDetail
                finding={selectedFinding}
                tagInput={tagInputs[selectedFinding.id] ?? ''}
                setTagInput={v => setTagInputs(p => ({ ...p, [selectedFinding.id]: v }))}
                onAddTag={() => addTag(selectedFinding.id)}
                onRemoveTag={tag => removeTag(selectedFinding.id, tag)}
                onChangeStatus={changeStatus}
                onShowFpModal={() => { setFpModal({ id: selectedFinding.id, title: selectedFinding.title }); setFpReason('') }}
                onRestore={restoreFinding}
                onVerify={verifyFinding}
                onReport={reportFinding}
                onDelete={deleteFinding}
                onClose={() => setSelectedId(null)}
              />
            )}
          </div>

          {/* FP Suppression Rules — collapsible footer */}
          <div style={{ borderTop: rule, flexShrink: 0 }}>
            <button
              onClick={() => setRulesOpen(o => !o)}
              style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 8, padding: '10px var(--pad)', background: 'none', border: 'none', cursor: 'pointer' }}
            >
              <ShieldOff size={13} style={{ color: '#a78bfa' }} />
              <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>Auto-suppression Rules</span>
              <span style={{ fontSize: 11, color: 'var(--fg-4)', marginLeft: 4 }}>— auto-mark FPs at parse time</span>
              <ChevronDown size={11} style={{ color: 'var(--fg-4)', marginLeft: 'auto', transform: rulesOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }} />
            </button>
            {rulesOpen && (
              <div style={{ padding: '0 var(--pad) 16px', display: 'flex', flexDirection: 'column', gap: 12, borderTop: rule }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 12 }}>
                  <label style={{ fontSize: 11, color: 'var(--fg-2)', fontFamily: 'var(--font-mono)' }}>Project:</label>
                  <select
                    value={ruleProjectId}
                    onChange={e => setRuleProjectId(e.target.value)}
                    style={{ background: 'var(--bg)', border: rule, padding: '4px 8px', fontSize: 11, color: 'var(--fg)', outline: 'none' }}
                  >
                    {ruleProjects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                  </select>
                </div>
                {fpRules.length === 0 ? (
                  <p style={{ fontSize: 11, color: 'var(--fg-3)', margin: 0 }}>No rules yet. Rules here will auto-suppress matching findings when scans are parsed.</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {fpRules.map(fpRule => (
                      <div key={fpRule.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 12px', background: 'rgba(167,139,250,0.06)', border: '1px solid rgba(167,139,250,0.15)' }}>
                        {fpRule.tool && (
                          <span className="mono" style={{ fontSize: 10, background: 'rgba(100,116,139,0.2)', color: 'var(--fg-2)', padding: '1px 6px' }}>{fpRule.tool}</span>
                        )}
                        <span style={{ fontSize: 11, color: 'var(--fg-2)', flex: 1 }}>title contains <span style={{ color: '#a78bfa', fontWeight: 500 }}>"{fpRule.title_contains}"</span></span>
                        <button onClick={() => deleteFpRule(fpRule.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', padding: 0 }}>
                          <X size={12} />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <input
                    type="text"
                    placeholder="Tool (e.g. nikto)"
                    value={ruleTool}
                    onChange={e => setRuleTool(e.target.value)}
                    style={{ padding: '5px 8px', fontSize: 11, color: 'var(--fg)', outline: 'none', width: 130 }}
                  />
                  <input
                    type="text"
                    placeholder="Title contains (required)"
                    value={ruleTitleContains}
                    onChange={e => setRuleTitleContains(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter') addFpRule() }}
                    style={{ padding: '5px 8px', fontSize: 11, color: 'var(--fg)', outline: 'none', width: 210 }}
                  />
                  <button
                    onClick={addFpRule}
                    disabled={!ruleTitleContains.trim() || !ruleProjectId || ruleSaving}
                    className="btn btn-sm"
                    style={{ color: '#a78bfa', borderColor: 'rgba(167,139,250,0.4)' }}
                  >
                    <Plus size={10} /> Add Rule
                  </button>
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {/* Nessus Import Wizard */}
      {showNessusModal && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.6)' }}>
          <div style={{ width: '100%', maxWidth: 680, background: 'var(--bg-2)', border: rule, padding: 24, display: 'flex', flexDirection: 'column', gap: 16, maxHeight: '85vh' }}>

            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              {nessusStep === 'hosts' && (
                <button onClick={() => { setNessusStep('scans'); setNessusImportResult(null); setNessusImportError('') }}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0, display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                  <ChevronLeft size={13} /> Back
                </button>
              )}
              <h2 style={{ fontSize: 15, fontWeight: 600, color: 'var(--fg)', margin: 0, fontFamily: 'var(--font-mono)', flex: 1 }}>
                {nessusStep === 'scans' ? 'Import from Nessus' : nessusSelectedScan?.name}
              </h2>
              <button onClick={() => setShowNessusModal(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)' }}><X size={14} /></button>
            </div>

            {/* Error / Result */}
            {nessusImportError && (
              <div style={{ fontSize: 11, color: 'var(--crit)', fontFamily: 'var(--font-mono)', background: 'rgba(232,64,64,0.08)', border: '1px solid rgba(232,64,64,0.2)', padding: '8px 12px' }}>
                {nessusImportError}
              </div>
            )}
            {nessusImportResult && (
              <div style={{ fontSize: 11, color: 'var(--ok)', fontFamily: 'var(--font-mono)', background: 'rgba(84,175,97,0.08)', border: '1px solid rgba(84,175,97,0.2)', padding: '8px 12px', display: 'flex', alignItems: 'center', gap: 12 }}>
                <span>
                  {nessusImportResult.targets_created > 0 && `${nessusImportResult.targets_created} target(s) created · `}
                  {nessusImportResult.findings_created} finding(s) imported from {nessusImportResult.hosts_processed} host(s).
                </span>
              </div>
            )}

            {/* Step 1 — Scan list */}
            {nessusStep === 'scans' && (
              <div style={{ overflowY: 'auto', flex: 1, minHeight: 0 }}>
                {nessusLoadingScans ? (
                  <div style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>Loading scans…</div>
                ) : nessusScans.length === 0 && !nessusImportError ? (
                  <div style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>No scans found. Check Settings → Nessus.</div>
                ) : (
                  <table className="data">
                    <thead>
                      <tr>
                        <th>Scan Name</th>
                        <th style={{ width: 70 }}>Hosts</th>
                        <th style={{ width: 90 }}>Status</th>
                        <th style={{ width: 80 }}></th>
                      </tr>
                    </thead>
                    <tbody>
                      {nessusScans.map(s => (
                        <tr key={s.id} style={{ cursor: 'pointer' }} onClick={() => selectNessusScan(s)}>
                          <td style={{ fontSize: 12 }}>{s.name}</td>
                          <td className="mono tnum" style={{ fontSize: 11, color: 'var(--fg-3)' }}>{s.host_count}</td>
                          <td>
                            <span style={{
                              fontSize: 9, fontWeight: 600, padding: '2px 7px', letterSpacing: '0.06em',
                              fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
                              color: s.status === 'completed' ? 'var(--ok)' : 'var(--fg-3)',
                              background: s.status === 'completed' ? 'rgba(84,175,97,0.08)' : 'rgba(100,116,139,0.08)',
                              border: `1px solid ${s.status === 'completed' ? 'rgba(84,175,97,0.25)' : 'rgba(100,116,139,0.2)'}`,
                            }}>{s.status}</span>
                          </td>
                          <td>
                            <button className="btn btn-sm" style={{ fontSize: 10 }} onClick={e => { e.stopPropagation(); selectNessusScan(s) }}>
                              Select →
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* Step 2 — Host selection + project */}
            {nessusStep === 'hosts' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14, flex: 1, minHeight: 0, overflowY: 'auto' }}>
                {nessusLoadingHosts ? (
                  <div style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>Loading hosts…</div>
                ) : (
                  <>
                    {/* Host table */}
                    <div style={{ overflowY: 'auto', minHeight: 0 }}>
                      <table className="data">
                        <thead>
                          <tr>
                            <th style={{ width: 32 }}>
                              <input type="checkbox"
                                checked={nessusSelectedHostIds.size === nessusScanHosts.length && nessusScanHosts.length > 0}
                                onChange={e => setNessusSelectedHostIds(e.target.checked ? new Set(nessusScanHosts.map(h => h.host_id)) : new Set())}
                              />
                            </th>
                            <th>Host</th>
                            <th style={{ width: 40, textAlign: 'center' }}>Crit</th>
                            <th style={{ width: 40, textAlign: 'center' }}>High</th>
                            <th style={{ width: 40, textAlign: 'center' }}>Med</th>
                            <th style={{ width: 40, textAlign: 'center' }}>Low</th>
                            <th style={{ width: 40, textAlign: 'center' }}>Info</th>
                          </tr>
                        </thead>
                        <tbody>
                          {nessusScanHosts.map(h => (
                            <tr key={h.host_id} style={{ cursor: 'pointer' }}
                              onClick={() => setNessusSelectedHostIds(prev => {
                                const next = new Set(prev)
                                next.has(h.host_id) ? next.delete(h.host_id) : next.add(h.host_id)
                                return next
                              })}
                            >
                              <td onClick={e => e.stopPropagation()}>
                                <input type="checkbox" checked={nessusSelectedHostIds.has(h.host_id)}
                                  onChange={() => setNessusSelectedHostIds(prev => {
                                    const next = new Set(prev)
                                    next.has(h.host_id) ? next.delete(h.host_id) : next.add(h.host_id)
                                    return next
                                  })}
                                />
                              </td>
                              <td className="mono" style={{ fontSize: 12 }}>{h.hostname}</td>
                              <td className="tnum" style={{ textAlign: 'center', fontSize: 11, color: h.critical > 0 ? 'var(--crit)' : 'var(--fg-4)' }}>{h.critical || '—'}</td>
                              <td className="tnum" style={{ textAlign: 'center', fontSize: 11, color: h.high > 0 ? '#f97316' : 'var(--fg-4)' }}>{h.high || '—'}</td>
                              <td className="tnum" style={{ textAlign: 'center', fontSize: 11, color: h.medium > 0 ? 'var(--accent)' : 'var(--fg-4)' }}>{h.medium || '—'}</td>
                              <td className="tnum" style={{ textAlign: 'center', fontSize: 11, color: h.low > 0 ? 'var(--ok)' : 'var(--fg-4)' }}>{h.low || '—'}</td>
                              <td className="tnum" style={{ textAlign: 'center', fontSize: 11, color: 'var(--fg-3)' }}>{h.info || '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    {/* Project destination */}
                    <div style={{ borderTop: rule, paddingTop: 12, display: 'flex', flexDirection: 'column', gap: 10 }}>
                      <div style={{ fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: 'var(--font-mono)' }}>
                        Project Destination
                      </div>
                      <div style={{ display: 'flex', gap: 6 }}>
                        {(['existing', 'new'] as const).map(m => (
                          <button key={m} onClick={() => setNessusProjectMode(m)}
                            style={{ padding: '4px 14px', fontSize: 11, fontFamily: 'var(--font-sans)', textTransform: 'capitalize', cursor: 'pointer',
                              background: nessusProjectMode === m ? 'var(--accent-2)' : 'var(--bg)',
                              border: nessusProjectMode === m ? '1px solid var(--accent)' : rule,
                              color: nessusProjectMode === m ? 'var(--accent)' : 'var(--fg-2)' }}
                          >{m === 'existing' ? 'Existing project' : 'New project'}</button>
                        ))}
                      </div>
                      {nessusProjectMode === 'existing' ? (
                        <select value={nessusImportProjectId} onChange={e => setNessusImportProjectId(e.target.value)}
                          style={{ background: 'var(--bg)', border: rule, padding: '5px 8px', fontSize: 12, color: 'var(--fg)', outline: 'none', width: '100%' }}>
                          {ruleProjects.length > 0
                            ? ruleProjects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)
                            : projectId
                              ? <option value={projectId}>{sp?.name ?? 'Current project'}</option>
                              : <option value="">— no projects —</option>
                          }
                        </select>
                      ) : (
                        <input type="text" value={nessusNewProjectName} onChange={e => setNessusNewProjectName(e.target.value)}
                          placeholder="New project name…"
                          style={{ background: 'var(--bg)', border: rule, padding: '5px 8px', fontSize: 12, color: 'var(--fg)', outline: 'none', width: '100%', boxSizing: 'border-box', fontFamily: 'var(--font-sans)' }}
                        />
                      )}
                    </div>

                    {/* Import action */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <button
                        onClick={handleNessusImport}
                        disabled={nessusImporting || nessusSelectedHostIds.size === 0}
                        className="btn btn-primary"
                        style={{ opacity: (nessusImporting || nessusSelectedHostIds.size === 0) ? 0.5 : 1 }}
                      >
                        {nessusImporting ? 'Importing…' : `Import ${nessusSelectedHostIds.size} host(s)`}
                      </button>
                      <span style={{ fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>
                        {nessusSelectedHostIds.size}/{nessusScanHosts.length} selected
                      </span>
                    </div>
                  </>
                )}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', borderTop: rule, paddingTop: 12 }}>
              <button onClick={() => setShowNessusModal(false)} className="btn btn-ghost">Close</button>
            </div>
          </div>
        </div>
      )}

      {fpModal && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.6)' }}>
          <div style={{ width: '100%', maxWidth: 480, background: 'var(--bg-2)', border: rule, padding: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
            <h2 style={{ fontSize: 15, fontWeight: 600, color: 'var(--fg)', margin: 0, fontFamily: 'var(--font-mono)' }}>Mark as False Positive</h2>
            <p style={{ fontSize: 12, color: 'var(--fg-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', margin: 0 }}>{fpModal.title}</p>
            <div>
              <label style={{ display: 'block', fontSize: 11, color: 'var(--fg-2)', marginBottom: 4, fontFamily: 'var(--font-mono)' }}>Reason *</label>
              <textarea
                value={fpReason}
                onChange={e => setFpReason(e.target.value)}
                placeholder="Explain why this is a false positive…"
                rows={3}
                style={{ width: '100%', padding: '8px 12px', fontSize: 13, color: 'var(--fg)', outline: 'none', resize: 'none', fontFamily: 'var(--font-sans)', boxSizing: 'border-box' }}
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button onClick={() => setFpModal(null)} className="btn btn-ghost">Cancel</button>
              <button
                onClick={() => suppressFinding(fpModal.id, fpReason)}
                disabled={!fpReason.trim() || fpSaving}
                className="btn btn-primary"
                style={{ color: '#a78bfa', background: 'rgba(167,139,250,0.15)', borderColor: 'rgba(167,139,250,0.4)' }}
              >
                {fpSaving ? 'Saving…' : 'Suppress'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
