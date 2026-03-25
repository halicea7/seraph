import { useState, useMemo, useEffect } from 'react'
import { ChevronDown, ChevronUp, ChevronRight, Filter, Plus, Trash2, Zap, Loader } from 'lucide-react'
import type { Finding, FindingNote } from '../types/index'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-red-950/60 text-red-400 border-red-500/50 severity-critical',
  high:     'bg-orange-950/60 text-orange-400 border-orange-500/40 severity-high',
  medium:   'bg-amber-950/40 text-amber-400 border-amber-500/30',
  low:      'bg-green-950/40 text-green-400 border-green-500/30',
  info:     'bg-blue-950/40 text-blue-400 border-blue-500/30',
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
}

export default function FindingsTable({ findings, loading }: FindingsTableProps) {
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
    if (!expandedId || notes[expandedId]) return
    fetch(`/api/v1/findings/${expandedId}/notes`)
      .then(r => r.json())
      .then(data => setNotes(prev => ({ ...prev, [expandedId]: data })))
  }, [expandedId])

  async function handleAddNote(findingId: string) {
    const content = (noteInput[findingId] || '').trim()
    if (!content) return
    setSavingNote(findingId)
    const res = await fetch(`/api/v1/findings/${findingId}/notes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    })
    const newNote = await res.json()
    setNotes(prev => ({ ...prev, [findingId]: [...(prev[findingId] || []), newNote] }))
    setNoteInput(prev => ({ ...prev, [findingId]: '' }))
    setSavingNote(null)
  }

  async function handleEnrich(findingId: string) {
    setEnriching(findingId)
    const res = await fetch(`/api/v1/findings/${findingId}/enrich`, { method: 'POST' })
    const data = await res.json()
    if (data.status === 'enriched') {
      setEnrichedData(prev => ({ ...prev, [findingId]: { cvss_score: data.cvss_score, cve_id: data.cve_id } }))
    }
    setEnriching(null)
  }

  async function handleDeleteNote(findingId: string, noteId: string) {
    await fetch(`/api/v1/findings/notes/${noteId}`, { method: 'DELETE' })
    setNotes(prev => ({ ...prev, [findingId]: prev[findingId].filter(n => n.id !== noteId) }))
  }

  function toggleSort(field: typeof sortField) {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('asc') }
  }

  function SortIcon({ field }: { field: typeof sortField }) {
    if (sortField !== field) return <ChevronDown size={14} className="text-slate-600" />
    return sortDir === 'asc'
      ? <ChevronUp size={14} className="text-cyan-400" />
      : <ChevronDown size={14} className="text-cyan-400" />
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-32 text-slate-400">
        Loading findings...
      </div>
    )
  }

  const inputClass = "bg-[#090d14] border border-cyan-900/30 rounded px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500/50"

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
          className={`${inputClass} w-52`}
        />
        <select
          value={filterSeverity}
          onChange={e => setFilterSeverity(e.target.value)}
          className={inputClass}
        >
          <option value="all">All Severities</option>
          {SEVERITY_ORDER.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
        </select>
        {frameworks.length > 0 && (
          <select
            value={filterFramework}
            onChange={e => setFilterFramework(e.target.value)}
            className={inputClass}
          >
            <option value="all">All Frameworks</option>
            {frameworks.map(f => <option key={f} value={f}>{f.replace(/_/g, ' ')}</option>)}
          </select>
        )}
        <span className="text-xs text-slate-400 ml-auto">{sorted.length} findings</span>
      </div>

      {/* Table */}
      <div className="glass rounded-xl overflow-hidden">
        <div className="grid grid-cols-[120px_1fr_140px_100px] gap-0 border-b border-cyan-900/20">
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
                className="grid grid-cols-[120px_1fr_140px_100px] gap-0 border-b border-cyan-900/10 hover:bg-cyan-950/10 cursor-pointer transition-colors relative"
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
                  <span className={`text-xs px-2 py-0.5 rounded-full border font-semibold uppercase ${SEVERITY_STYLES[finding.severity] || SEVERITY_STYLES.info}`}>
                    {finding.severity}
                  </span>
                </div>
                <div className="px-4 py-3">
                  <div className="text-sm text-slate-200 leading-snug">{finding.title}</div>
                  {finding.description && (
                    <div className="text-xs text-slate-400 truncate mt-0.5">{finding.description}</div>
                  )}
                </div>
                <div className="px-4 py-3 space-y-1">
                  {finding.framework && (
                    <div className="text-xs text-slate-300">{finding.framework.replace(/_/g, ' ')}</div>
                  )}
                  {finding.control_id && (
                    <div className="text-xs font-mono text-cyan-400">{finding.control_id}</div>
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
                <div className="border-b border-cyan-900/20 px-6 py-4 space-y-3" style={{ background: 'rgba(5,8,13,0.6)' }}>
                  {/* CVE / CVSS row */}
                  {(() => {
                    const cvssScore = enrichedData[finding.id]?.cvss_score ?? finding.cvss_score
                    const cveId = enrichedData[finding.id]?.cve_id ?? finding.cve_id
                    const hasCveInText = /CVE-\d{4}-\d{4,7}/i.test(`${finding.title} ${finding.description || ''}`)
                    return (
                      <div className="flex items-center gap-3 flex-wrap">
                        {cveId && (
                          <a href={`https://nvd.nist.gov/vuln/detail/${cveId}`} target="_blank" rel="noopener noreferrer"
                             className="text-xs font-mono text-cyan-400 hover:text-cyan-300 underline decoration-dotted">
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
                            className="flex items-center gap-1 text-xs px-2 py-0.5 rounded border border-cyan-900/30 text-cyan-500 hover:text-cyan-300 hover:border-cyan-700/50 disabled:opacity-50 transition-all"
                          >
                            {enriching === finding.id ? <Loader size={10} className="animate-spin" /> : <Zap size={10} />}
                            {enriching === finding.id ? 'Fetching...' : 'Enrich CVE'}
                          </button>
                        )}
                      </div>
                    )
                  })()}
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
                      <pre className="text-xs font-mono text-slate-300 rounded p-3 overflow-x-auto whitespace-pre-wrap border border-cyan-900/20" style={{ background: '#05080d' }}>{finding.evidence}</pre>
                    </div>
                  )}

                  {/* Analyst Notes */}
                  <div>
                    <div className="text-xs font-semibold text-slate-400 uppercase mb-2">Analyst Notes</div>
                    <div className="space-y-2 mb-2">
                      {(notes[finding.id] || []).map(note => (
                        <div key={note.id} className="flex items-start gap-2 group rounded-lg px-3 py-2 border border-cyan-900/20" style={{ background: '#05080d' }}>
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
                        className="flex-1 rounded px-3 py-1.5 text-xs text-slate-200 border border-cyan-900/20 focus:outline-none focus:border-cyan-500/50 bg-[#05080d]"
                      />
                      <button
                        onClick={() => handleAddNote(finding.id)}
                        disabled={savingNote === finding.id || !noteInput[finding.id]?.trim()}
                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-cyan-900/40 hover:bg-cyan-800/50 disabled:opacity-40 text-xs text-cyan-400 border border-cyan-900/30 transition-all"
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
    </div>
  )
}
