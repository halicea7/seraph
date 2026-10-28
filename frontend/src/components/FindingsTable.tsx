import { useState, useMemo, useEffect } from 'react'
import type React from 'react'
import { ChevronDown, ChevronUp, ChevronRight, Filter, Plus, Trash2, Zap, Loader, RefreshCw } from 'lucide-react'
import type { Finding, FindingNote } from '../types/index'
import { getApiBase, authedUrl } from '@/lib/config'
import { useAiModel, completeFeature } from '@/lib/ai'
import AiModelSelect from './AiModelSelect'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

const SEVERITY_INLINE: Record<string, React.CSSProperties> = {
  critical: { color: 'var(--crit)', background: 'rgba(232,92,78,0.1)',  border: '1px solid rgba(232,92,78,0.5)' },
  high:     { color: 'var(--high)', background: 'rgba(240,168,58,0.1)',  border: '1px solid rgba(240,168,58,0.5)' },
  medium:   { color: 'var(--med)',  background: 'rgba(212,196,90,0.08)', border: '1px solid rgba(212,196,90,0.4)' },
  low:      { color: 'var(--low)',  background: 'rgba(107,138,114,0.08)', border: '1px solid rgba(107,138,114,0.4)' },
  info:     { color: 'var(--fg-3)', background: 'var(--bg-2)',           border: '1px solid var(--rule-strong)' },
}

const SEVERITY_ACCENT: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '',
  low: '',
  info: '',
}

interface FindingsTableProps {
  findings: Finding[]
  loading?: boolean
  onDelete?: (id: string) => void
  /** When provided, shows a "Retest" action that re-runs the finding's originating check. */
  onRetest?: (finding: Finding) => void
}

export default function FindingsTable({ findings, loading, onDelete, onRetest }: FindingsTableProps) {
  const [sortField, setSortField] = useState<'severity' | 'title' | 'framework'>('severity')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')
  const [filterSeverity, setFilterSeverity] = useState<string>('all')
  const [filterFramework, setFilterFramework] = useState<string>('all')
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [notes, setNotes] = useState<Record<string, FindingNote[]>>({})
  const [noteInput, setNoteInput] = useState<Record<string, string>>({})
  const [savingNote, setSavingNote] = useState<string | null>(null)
  const [enriching, setEnriching] = useState<string | null>(null)
  const [enrichedData, setEnrichedData] = useState<Record<string, { cvss_score: string | null; cve_id: string | null }>>({})
  const [shots, setShots] = useState<Record<string, { id: string; url: string }[]>>({})
  const [lightboxShot, setLightboxShot] = useState<string | null>(null)
  const [aiRemediation, setAiRemediation] = useState<Record<string, string>>({})
  const [aiLoading, setAiLoading] = useState<string | null>(null)
  const { options: aiModels, modelKey: aiModelKey, setModelKey: setAiModelKey } = useAiModel()

  const frameworks = useMemo(() => {
    const set = new Set(findings.map(f => f.framework).filter(Boolean) as string[])
    return Array.from(set)
  }, [findings])

  const sorted = useMemo(() => {
    let result = [...findings]

    if (search) {
      const q = search.toLowerCase()
      result = result.filter(f =>
        f.title.toLowerCase().includes(q) ||
        f.description?.toLowerCase().includes(q) ||
        f.control_id?.toLowerCase().includes(q)
      )
    }

    if (filterSeverity !== 'all') result = result.filter(f => f.severity === filterSeverity)
    if (filterFramework !== 'all') result = result.filter(f => f.framework === filterFramework)

    result.sort((a, b) => {
      let cmp = 0
      if (sortField === 'severity') {
        cmp = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
      } else if (sortField === 'title') {
        cmp = a.title.localeCompare(b.title)
      } else if (sortField === 'framework') {
        cmp = (a.framework || '').localeCompare(b.framework || '')
      }
      return sortDir === 'asc' ? cmp : -cmp
    })

    return result
  }, [findings, sortField, sortDir, filterSeverity, filterFramework, search])

  useEffect(() => {
    if (!expandedId) return
    if (!notes[expandedId]) {
      fetch(`${getApiBase()}/findings/${expandedId}/notes`)
        .then(r => r.json())
        .then(data => setNotes(prev => ({ ...prev, [expandedId]: data })))
    }
    if (!shots[expandedId]) {
      fetch(`${getApiBase()}/screenshots?finding_id=${expandedId}`)
        .then(r => r.ok ? r.json() : [])
        .then(data => setShots(prev => ({ ...prev, [expandedId]: data })))
        .catch(() => {})
    }
  }, [expandedId])

  async function handleAddNote(findingId: string) {
    const content = (noteInput[findingId] || '').trim()
    if (!content) return
    setSavingNote(findingId)
    const res = await fetch(`${getApiBase()}/findings/${findingId}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    })
    const newNote = await res.json()
    setNotes(prev => ({ ...prev, [findingId]: [...(prev[findingId] || []), newNote] }))
    setNoteInput(prev => ({ ...prev, [findingId]: '' }))
    setSavingNote(null)
  }

  async function handleRemediate(findingId: string) {
    setAiLoading(findingId)
    try {
      const text = await completeFeature(aiModelKey, `/findings/${findingId}/ai-remediate`, {})
      setAiRemediation(prev => ({ ...prev, [findingId]: text }))
    } catch (e) {
      setAiRemediation(prev => ({ ...prev, [findingId]: `⚠ ${e instanceof Error ? e.message : 'AI request failed'}` }))
    } finally { setAiLoading(null) }
  }

  async function handleEnrich(findingId: string) {
    setEnriching(findingId)
    const res = await fetch(`${getApiBase()}/findings/${findingId}/enrich`, { method: 'POST' })
    const data = await res.json()
    if (data.status === 'enriched') {
      setEnrichedData(prev => ({ ...prev, [findingId]: { cvss_score: data.cvss_score, cve_id: data.cve_id } }))
    }
    setEnriching(null)
  }

  async function handleDeleteNote(findingId: string, noteId: string) {
    await fetch(`${getApiBase()}/findings/notes/${noteId}`, { method: 'DELETE' })
    setNotes(prev => ({ ...prev, [findingId]: prev[findingId].filter(n => n.id !== noteId) }))
  }

  function toggleSort(field: typeof sortField) {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('asc') }
  }

  function SortIcon({ field }: { field: typeof sortField }) {
    if (sortField !== field) return <ChevronDown size={14} style={{ color: 'var(--fg-4)' }} />
    return sortDir === 'asc'
      ? <ChevronUp size={14} style={{ color: 'var(--accent)' }} />
      : <ChevronDown size={14} style={{ color: 'var(--accent)' }} />
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-32 text-slate-400">
        Loading findings...
      </div>
    )
  }

  const filterInputStyle: React.CSSProperties = { background: 'var(--bg-2)', border: '1px solid var(--rule)', padding: '5px 10px', fontSize: 12, color: 'var(--fg)', outline: 'none', fontFamily: 'var(--font-mono)', borderRadius: 0 }

  return (
    <div className="space-y-3">
      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="flex items-center gap-2 text-slate-400">
          <Filter size={14} />
          <span className="text-xs">Filter:</span>
        </div>
        <input
          type="text"
          placeholder="Search findings..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ ...filterInputStyle, width: 200 }}
        />
        <select value={filterSeverity} onChange={e => setFilterSeverity(e.target.value)} style={filterInputStyle}>
          <option value="all">All Severities</option>
          {SEVERITY_ORDER.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
        </select>
        {frameworks.length > 0 && (
          <select value={filterFramework} onChange={e => setFilterFramework(e.target.value)} style={filterInputStyle}>
            <option value="all">All Frameworks</option>
            {frameworks.map(f => <option key={f} value={f}>{f.replace(/_/g, ' ')}</option>)}
          </select>
        )}
        <div className="ml-auto" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <AiModelSelect value={aiModelKey} onChange={setAiModelKey} options={aiModels} />
          <span className="text-xs text-slate-400">{sorted.length} findings</span>
        </div>
      </div>

      {/* Table */}
      <div style={{ border: '1px solid var(--rule-strong)', overflow: 'hidden' }}>
        <div className="grid grid-cols-[120px_1fr_140px_100px] gap-0" style={{ borderBottom: '1px solid var(--rule-strong)' }}>
          {[
            { label: 'Severity', field: 'severity' as const },
            { label: 'Finding', field: 'title' as const },
            { label: 'Framework / Control', field: 'framework' as const },
            { label: 'Source', field: null as null },
          ].map(col => (
            <div
              key={col.label}
              className={`px-4 py-2.5 text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1 ${col.field ? 'cursor-pointer hover:text-slate-200' : ''}`}
              onClick={() => col.field && toggleSort(col.field)}
            >
              {col.label}
              {col.field && <SortIcon field={col.field} />}
            </div>
          ))}
        </div>

        {sorted.length === 0 ? (
          <div className="text-center text-slate-400 py-10 text-sm">No findings match the current filters.</div>
        ) : (
          sorted.map(finding => (
            <div key={finding.id}>
              <div
                className="grid grid-cols-[120px_1fr_140px_100px] gap-0 cursor-pointer relative"
                style={{ borderBottom: '1px solid var(--rule-2)' }}
                onMouseEnter={e => (e.currentTarget.style.background = 'var(--bg-2)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                onClick={() => setExpandedId(expandedId === finding.id ? null : finding.id)}
              >
                {/* Left accent bar for critical/high */}
                {SEVERITY_ACCENT[finding.severity] && (
                  <div
                    className="absolute left-0 top-0 bottom-0 w-0.5"
                    style={{ backgroundColor: SEVERITY_ACCENT[finding.severity] }}
                  />
                )}
                <div className="px-4 py-3 flex items-center">
                  <span style={{ fontSize: 9, padding: '2px 6px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', fontFamily: 'var(--font-mono)', ...SEVERITY_INLINE[finding.severity] || SEVERITY_INLINE.info }}>
                    {finding.severity}
                  </span>
                </div>
                <div className="px-4 py-3">
                  <div className="text-sm text-slate-200 leading-snug flex items-center gap-2 flex-wrap">
                    <span>{finding.title}</span>
                    {finding.overdue && (
                      <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: '0.08em', padding: '1px 6px', color: 'var(--crit)', border: '1px solid var(--crit)', background: 'rgba(232,92,78,0.12)', fontFamily: 'var(--font-mono)' }}>SLA OVERDUE</span>
                    )}
                    {(finding.occurrences ?? 0) > 1 && (
                      <span title={`Seen in ${finding.occurrences} scans`} style={{ fontSize: 9, padding: '1px 6px', color: 'var(--fg-3)', border: '1px solid var(--rule-strong)', fontFamily: 'var(--font-mono)' }}>×{finding.occurrences}</span>
                    )}
                  </div>
                  {finding.description && (
                    <div className="text-xs text-slate-400 truncate mt-0.5">{finding.description}</div>
                  )}
                </div>
                <div className="px-4 py-3 space-y-1">
                  {finding.framework && (
                    <div className="text-xs text-slate-300">{finding.framework.replace(/_/g, ' ')}</div>
                  )}
                  {finding.control_id && (
                    <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{finding.control_id}</div>
                  )}
                  {/* Extra framework tags (OWASP / MITRE / PCI) */}
                  {finding.tags && (() => {
                    const frameworkTags = finding.tags.split(',').filter(t => t.startsWith('OWASP:') || t.startsWith('MITRE:') || t.startsWith('PCI:'))
                    if (!frameworkTags.length) return null
                    return (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {frameworkTags.map(tag => {
                          const [ns] = tag.split(':')
                          const colors: Record<string, string> = {
                            OWASP: 'text-orange-400 border-orange-700/40 bg-orange-950/30',
                            MITRE: 'text-red-400 border-red-700/40 bg-red-950/20',
                            PCI:   'text-violet-400 border-violet-700/40 bg-violet-950/20',
                          }
                          return (
                            <span key={tag} className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${colors[ns] || 'text-slate-400 border-slate-700/30'}`}>
                              {tag}
                            </span>
                          )
                        })}
                      </div>
                    )
                  })()}
                </div>
                <div className="px-4 py-3 flex items-center justify-end">
                  {expandedId === finding.id
                    ? <ChevronUp size={14} className="text-slate-400" />
                    : <ChevronRight size={14} className="text-slate-500" />
                  }
                </div>
              </div>

              {/* Expanded row */}
              {expandedId === finding.id && (
                <div style={{ borderBottom: '1px solid var(--rule)', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 12, background: 'var(--bg)' }}>
                  {/* CVE / CVSS row */}
                  {(() => {
                    const cvssScore = enrichedData[finding.id]?.cvss_score ?? finding.cvss_score
                    const cveId = enrichedData[finding.id]?.cve_id ?? finding.cve_id
                    const hasCveInText = /CVE-\d{4}-\d{4,7}/i.test(`${finding.title} ${finding.description || ''}`)
                    return (
                      <div className="flex items-center gap-3 flex-wrap">
                        {cveId && (
                          <a href={`https://nvd.nist.gov/vuln/detail/${cveId}`} target="_blank" rel="noopener noreferrer"
                             style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent)', textDecoration: 'underline dotted' }}>
                            {cveId}
                          </a>
                        )}
                        {cvssScore && (
                          <span className={`text-xs px-2 py-0.5 rounded-full border font-bold ${parseFloat(cvssScore) >= 9 ? 'bg-red-950/60 text-red-400 border-red-500/50' : parseFloat(cvssScore) >= 7 ? 'bg-orange-950/60 text-orange-400 border-orange-500/40' : parseFloat(cvssScore) >= 4 ? 'bg-amber-950/40 text-amber-400 border-amber-500/30' : 'bg-green-950/40 text-green-400 border-green-500/30'}`}>
                            CVSS {cvssScore}
                          </span>
                        )}
                        {hasCveInText && !cvssScore && (
                          <button
                            onClick={() => handleEnrich(finding.id)}
                            disabled={enriching === finding.id}
                            style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, padding: '2px 7px', color: 'var(--accent)', border: '1px solid var(--accent-border)', background: 'var(--accent-2)', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}
                          >
                            {enriching === finding.id ? <Loader size={10} className="animate-spin" /> : <Zap size={10} />}
                            {enriching === finding.id ? 'Fetching...' : 'Enrich CVE'}
                          </button>
                        )}
                      </div>
                    )
                  })()}
                  {(finding.occurrences || finding.first_seen || finding.sla_due) && (
                    <div className="flex items-center gap-4 flex-wrap" style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--fg-3)' }}>
                      {(finding.occurrences ?? 0) > 1 && <span>seen ×{finding.occurrences}</span>}
                      {finding.first_seen && <span>first {finding.first_seen.slice(0, 10)}</span>}
                      {finding.last_seen && <span>last {finding.last_seen.slice(0, 10)}</span>}
                      {finding.sla_due && <span style={{ color: finding.overdue ? 'var(--crit)' : 'var(--fg-3)' }}>SLA due {finding.sla_due.slice(0, 10)}{finding.overdue ? ' · overdue' : ''}</span>}
                    </div>
                  )}
                  {finding.description && (
                    <div>
                      <div className="text-xs font-semibold text-slate-400 uppercase mb-1">Description</div>
                      <p className="text-sm text-slate-300">{finding.description}</p>
                    </div>
                  )}
                  {finding.remediation && (
                    <div>
                      <div className="text-xs font-semibold text-slate-400 uppercase mb-1">Remediation</div>
                      <p className="text-sm text-green-300">{finding.remediation}</p>
                    </div>
                  )}
                  {finding.evidence && (
                    <div>
                      <div className="text-xs font-semibold text-slate-400 uppercase mb-1">Evidence</div>
                      <pre className="on-term" style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--fg-2)', padding: '10px 12px', overflowX: 'auto', whiteSpace: 'pre-wrap', border: '1px solid var(--rule)', background: 'var(--bg-term)', margin: 0 }}>{finding.evidence}</pre>
                    </div>
                  )}

                  {/* Linked screenshot evidence */}
                  {(shots[finding.id]?.length ?? 0) > 0 && (
                    <div>
                      <div className="text-xs font-semibold text-slate-400 uppercase mb-1">Evidence ({shots[finding.id].length})</div>
                      <div className="flex flex-wrap gap-2">
                        {shots[finding.id].map(sh => (
                          <img
                            key={sh.id}
                            src={authedUrl(`/screenshots/${sh.id}/image`)}
                            alt={sh.url}
                            title={sh.url}
                            onClick={() => setLightboxShot(sh.id)}
                            style={{ width: 160, height: 100, objectFit: 'cover', objectPosition: 'top', border: '1px solid var(--rule)', cursor: 'zoom-in', borderRadius: 3 }}
                          />
                        ))}
                      </div>
                    </div>
                  )}

                  {/* AI remediation */}
                  <div>
                    {aiRemediation[finding.id] && (
                      <div className="text-sm text-slate-300" style={{ whiteSpace: 'pre-wrap', background: 'var(--bg)', border: '1px solid var(--rule)', borderRadius: 3, padding: '10px 12px', marginBottom: 8, lineHeight: 1.55 }}>
                        {aiRemediation[finding.id]}
                      </div>
                    )}
                    <button
                      onClick={() => handleRemediate(finding.id)}
                      disabled={aiLoading === finding.id}
                      style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, padding: '5px 10px', color: 'var(--accent)', border: '1px solid var(--accent-border)', background: 'var(--accent-2)', cursor: aiLoading === finding.id ? 'default' : 'pointer', fontFamily: 'var(--font-mono)', opacity: aiLoading === finding.id ? 0.6 : 1 }}
                    >
                      {aiLoading === finding.id ? <Loader size={11} className="animate-spin" /> : <Zap size={11} />}
                      {aiLoading === finding.id ? 'Thinking…' : aiRemediation[finding.id] ? 'Regenerate (AI)' : 'Suggest remediation (AI)'}
                    </button>
                  </div>

                  {/* Actions */}
                  {(onDelete || onRetest) && (
                    <div className="flex justify-end gap-2 pt-1">
                      {onRetest && (
                        <button
                          onClick={() => onRetest(finding)}
                          title="Re-run the originating check to verify a fix"
                          className="flex items-center gap-1.5 px-3 py-1 rounded text-xs"
                          style={{ color: 'var(--accent)', border: '1px solid var(--accent-border)', background: 'var(--accent-2)' }}
                        >
                          <RefreshCw size={11} /> Retest
                        </button>
                      )}
                      {onDelete && (
                        <button
                          onClick={() => onDelete(finding.id)}
                          className="flex items-center gap-1.5 px-3 py-1 rounded text-xs text-red-400 border border-red-900/40 hover:bg-red-900/20 transition-colors"
                        >
                          <Trash2 size={11} /> Delete Finding
                        </button>
                      )}
                    </div>
                  )}

                  {/* Analyst Notes */}
                  <div>
                    <div className="text-xs font-semibold text-slate-400 uppercase mb-2">Analyst Notes</div>
                    <div className="space-y-2 mb-2">
                      {(notes[finding.id] || []).map(note => (
                        <div key={note.id} className="flex items-start gap-2 group" style={{ padding: '8px 10px', border: '1px solid var(--rule)', background: 'var(--bg)' }}>
                          <p className="text-xs text-slate-300 flex-1 whitespace-pre-wrap">{note.content}</p>
                          <button
                            onClick={() => handleDeleteNote(finding.id, note.id)}
                            className="text-slate-700 hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100 flex-shrink-0 mt-0.5"
                          >
                            <Trash2 size={11} />
                          </button>
                        </div>
                      ))}
                      {(notes[finding.id] || []).length === 0 && (
                        <p className="text-xs text-slate-600 italic">No notes yet</p>
                      )}
                    </div>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={noteInput[finding.id] || ''}
                        onChange={e => setNoteInput(prev => ({ ...prev, [finding.id]: e.target.value }))}
                        onKeyDown={e => e.key === 'Enter' && handleAddNote(finding.id)}
                        placeholder="Add a note..."
                        style={{ flex: 1, fontSize: 11, padding: '5px 10px', background: 'var(--bg)', border: '1px solid var(--rule)', color: 'var(--fg)', outline: 'none', fontFamily: 'var(--font-mono)' }}
                      />
                      <button
                        onClick={() => handleAddNote(finding.id)}
                        disabled={savingNote === finding.id || !noteInput[finding.id]?.trim()}
                        style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '5px 10px', fontSize: 11, color: 'var(--accent)', border: '1px solid var(--accent-border)', background: 'var(--accent-2)', cursor: 'pointer', opacity: (savingNote === finding.id || !noteInput[finding.id]?.trim()) ? 0.4 : 1, fontFamily: 'var(--font-mono)' }}
                      >
                        <Plus size={11} /> Add
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Evidence lightbox */}
      {lightboxShot && (
        <div
          onClick={() => setLightboxShot(null)}
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.85)', zIndex: 100, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 32 }}
        >
          <img
            src={authedUrl(`/screenshots/${lightboxShot}/image`)}
            alt="evidence"
            onClick={e => e.stopPropagation()}
            style={{ maxWidth: '90vw', maxHeight: '88vh', objectFit: 'contain', border: '1px solid var(--rule-strong)' }}
          />
        </div>
      )}
    </div>
  )
}
