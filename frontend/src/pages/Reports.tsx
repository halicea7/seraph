import { useState, useEffect } from 'react'
import { FileText, Download, RefreshCw, Brain, Loader, FileDown, BookmarkCheck } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import FindingsTable from '../components/FindingsTable'
import type { Project, Finding } from '../types'
import { getProjects, getFindings, generateReport, getStats, type PlatformStats } from '../api/client'
import { useAuth } from '../contexts/AuthContext'
import { useAINarrative } from '../contexts/AINarrativeContext'

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22c55e',
  info: '#3b82f6',
}

const SEVERITY_BORDER_TOP: Record<string, string> = {
  critical: 'rgba(239,68,68,0.6)',
  high: 'rgba(249,115,22,0.6)',
  medium: 'rgba(245,158,11,0.6)',
  low: 'rgba(34,197,94,0.6)',
  info: 'rgba(59,130,246,0.6)',
}

const BASE_URL = '/api/v1'

export default function Reports() {
  const { user } = useAuth()
  const { generating: generatingNarrative, progress: narrativeProgress, generate } = useAINarrative()
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedProject, setSelectedProject] = useState<string>('')
  const [findings, setFindings] = useState<Finding[]>([])
  const [stats, setStats] = useState<PlatformStats | null>(null)
  const [generating, setGenerating] = useState(false)
  const [loading, setLoading] = useState(false)
  const [activeTab, setActiveTab] = useState<'findings' | 'report' | 'narrative'>('findings')
  const [reportPreview, setReportPreview] = useState<string>('')
  const [narrative, setNarrative] = useState<string>('')
  const [narrativeSavedAt, setNarrativeSavedAt] = useState<string>('')
  const [narrativeStyle, setNarrativeStyle] = useState<'executive' | 'technical'>('executive')
  const [template, setTemplate] = useState<'executive_summary' | 'technical_detail' | 'compliance_mapped'>('technical_detail')
  const [narrativeError, setNarrativeError] = useState<string>('')
  const [auditor, setAuditor] = useState<string>(user?.full_name || user?.username || '')

  useEffect(() => {
    loadProjects()
    loadStats()
  }, [])

  useEffect(() => {
    if (user && !auditor) setAuditor(user.full_name || user.username)
  }, [user])

  useEffect(() => {
    if (selectedProject) {
      loadFindings(selectedProject)
      loadSavedNarrative(selectedProject, narrativeStyle)
    }
  }, [selectedProject])

  useEffect(() => {
    if (selectedProject) loadSavedNarrative(selectedProject, narrativeStyle)
  }, [narrativeStyle])

  async function loadProjects() {
    try {
      const data = await getProjects()
      setProjects(data)
      if (data.length > 0) setSelectedProject(data[0].id)
    } catch {
      // backend may not be running
    }
  }

  async function loadStats() {
    try {
      const data = await getStats()
      setStats(data)
    } catch {
      // ignore
    }
  }

  async function loadSavedNarrative(projectId: string, style: string) {
    try {
      const res = await fetch(`/api/v1/ai/narrate/${projectId}`)
      if (!res.ok) return
      const data = await res.json()
      const saved = data[style]
      if (saved) {
        setNarrative(saved.content)
        setNarrativeSavedAt(saved.generated_at)
      } else {
        setNarrative('')
        setNarrativeSavedAt('')
      }
    } catch { /* ignore */ }
  }

  async function loadFindings(_projectId: string) {
    setLoading(true)
    try {
      const data = await getFindings()
      setFindings(data)
    } catch {
      setFindings([])
    } finally {
      setLoading(false)
    }
  }

  async function handleGenerateNarrative() {
    if (!selectedProject) return
    setNarrativeError('')
    try {
      const result = await generate(selectedProject, narrativeStyle)
      if (result) {
        setNarrative(result.narrative)
        setNarrativeSavedAt(result.savedAt)
        setActiveTab('narrative')
      }
    } catch (err: any) {
      setNarrativeError(err.message || 'Unknown error')
    }
  }

  async function handleExportPDF() {
    if (!selectedProject) return
    setGenerating(true)
    try {
      const res = await fetch(`/api/v1/audit/reports/pdf/${selectedProject}`)
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data.detail || `HTTP ${res.status}`)
      }
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `seraph_report_${selectedProject.slice(0, 8)}.pdf`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err: any) {
      alert(`PDF export failed: ${err.message}`)
    } finally {
      setGenerating(false)
    }
  }

  async function handleGenerateReport(format: 'html' | 'markdown') {
    if (!selectedProject) return
    setGenerating(true)
    try {
      // HTML-native templates go through generate+download; markdown-based go through direct download
      const isHtmlNative = template === 'executive_summary' || template === 'technical_detail' || template === 'compliance_mapped'
      let blob: Blob
      if (isHtmlNative && format === 'html') {
        const res = await fetch(`${BASE_URL}/audit/reports/generate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ project_id: selectedProject, report_type: template, auditor: auditor || 'Seraph (Automated)' }),
        })
        const data = await res.json()
        blob = new Blob([data.html || ''], { type: 'text/html' })
      } else {
        const params = new URLSearchParams({ format, auditor: auditor || 'Seraph (Automated)' })
        const res = await fetch(`${BASE_URL}/audit/reports/download/${selectedProject}?${params}`)
        blob = await res.blob()
      }
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `seraph_${template}_${selectedProject.slice(0, 8)}.${format === 'markdown' ? 'md' : 'html'}`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      // ignore download errors
    } finally {
      setGenerating(false)
    }
  }

  async function handlePreviewReport() {
    if (!selectedProject) return
    setGenerating(true)
    try {
      const data = await generateReport(selectedProject, template, auditor || 'Seraph (Automated)')
      setReportPreview(data.html || data.markdown || '')
      setActiveTab('report')
    } catch {
      // ignore
    } finally {
      setGenerating(false)
    }
  }

  const severityCounts = stats?.severity_counts || {}

  const displayFindings = template === 'executive_summary'
    ? findings.filter(f => f.severity === 'critical' || f.severity === 'high')
    : findings

  // Red dot: project has findings newer than the last saved narrative
  const selectedProj = projects.find(p => p.id === selectedProject)
  const hasNewFindings = !!(
    selectedProj?.latest_finding_at &&
    (!narrativeSavedAt || new Date(selectedProj.latest_finding_at) > new Date(narrativeSavedAt))
  )

  return (
    <div className="p-8 space-y-6">

      {/* AI Narrative progress bar — fixed top-right */}
      {narrativeProgress !== null && (
        <div className="fixed top-4 right-4 z-50 w-72 rounded-xl overflow-hidden shadow-2xl border border-purple-500/30"
          style={{ background: 'rgba(10,5,20,0.92)', backdropFilter: 'blur(8px)', boxShadow: '0 0 24px rgba(168,85,247,0.25)' }}>
          <div className="flex items-center gap-2 px-3 py-2">
            <Brain size={13} className="text-purple-400 shrink-0" />
            <span className="text-xs text-purple-300 font-medium flex-1">Generating narrative…</span>
            {narrativeProgress >= 0 && (
              <span className="text-[10px] text-purple-400 font-mono">{Math.round(narrativeProgress)}%</span>
            )}
          </div>
          <div className="h-1.5 w-full" style={{ background: 'rgba(168,85,247,0.15)' }}>
            {narrativeProgress === -1 ? (
              /* indeterminate shimmer */
              <div className="h-full w-full relative overflow-hidden">
                <div
                  className="absolute h-full rounded-full"
                  style={{
                    width: '40%',
                    background: 'linear-gradient(90deg, transparent, rgba(168,85,247,0.9), transparent)',
                    boxShadow: '0 0 10px rgba(168,85,247,0.6)',
                    animation: 'seraph-shimmer 1.4s ease-in-out infinite',
                  }}
                />
              </div>
            ) : (
              <div
                className="h-full rounded-full transition-all duration-200"
                style={{
                  width: `${narrativeProgress}%`,
                  background: 'linear-gradient(90deg, #7c3aed, #a855f7)',
                  boxShadow: narrativeProgress > 0 ? '0 0 8px rgba(168,85,247,0.7)' : 'none',
                }}
              />
            )}
          </div>
        </div>
      )}

      {/* Page header */}
      <div className="mb-2">
        <div className="flex items-center gap-3">
          <FileText size={24} className="text-blue-400" />
          <h1 className="text-2xl font-semibold text-white">Reports</h1>
        </div>
        <p className="text-sm text-slate-400 mt-1">
          Generate and export audit and pentest findings reports
        </p>
      </div>

      {/* Stats Row */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => (
            <div
              key={sev}
              className="glass glass-hover rounded-xl p-4 border-t-2 transition-all"
              style={{ borderTopColor: SEVERITY_BORDER_TOP[sev] }}
            >
              <div className="text-2xl font-bold font-mono" style={{ color: SEVERITY_COLORS[sev] }}>
                {severityCounts[sev] || 0}
              </div>
              <div className="text-xs text-slate-400 mt-1 capitalize">{sev}</div>
            </div>
          ))}
        </div>
      )}

      {/* Project selector + actions */}
      <div className="flex items-center gap-4 flex-wrap">
        <select
          value={selectedProject}
          onChange={e => setSelectedProject(e.target.value)}
          className="rounded px-3 py-2 text-sm text-slate-200 focus:outline-none border border-cyan-900/20 focus:border-cyan-500/50"
          style={{ background: '#090d14' }}
        >
          <option value="">Select project...</option>
          {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>

        <input
          type="text"
          value={auditor}
          onChange={e => setAuditor(e.target.value)}
          placeholder="Auditor name"
          className="rounded px-3 py-2 text-sm text-slate-200 focus:outline-none border border-cyan-900/20 focus:border-cyan-500/50 w-44"
          style={{ background: '#090d14' }}
        />

        {/* Template picker */}
        <div className="flex gap-1 glass rounded-lg p-1">
          <button
            onClick={() => setTemplate('executive_summary')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${template === 'executive_summary' ? 'bg-blue-600/30 text-blue-300 border border-blue-500/30' : 'text-slate-400 hover:text-slate-200'}`}
            title="Risk overview, key findings, no technical detail"
          >
            Executive Summary
          </button>
          <button
            onClick={() => setTemplate('technical_detail')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${template === 'technical_detail' ? 'bg-cyan-600/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'}`}
            title="All findings with evidence and remediation"
          >
            Technical Detail
          </button>
          <button
            onClick={() => setTemplate('compliance_mapped')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${template === 'compliance_mapped' ? 'bg-purple-600/20 text-purple-300 border border-purple-500/30' : 'text-slate-400 hover:text-slate-200'}`}
            title="Findings organized by NIST/CIS/PCI control"
          >
            Compliance Mapped
          </button>
        </div>

        <div className="flex gap-2 ml-auto flex-wrap">
          {/* AI Narrative */}
          <div className="flex items-center gap-1 glass rounded-lg px-1">
            <select
              value={narrativeStyle}
              onChange={e => setNarrativeStyle(e.target.value as 'executive' | 'technical')}
              className="bg-transparent text-xs text-slate-400 focus:outline-none py-1 px-1 cursor-pointer"
            >
              <option value="executive">Executive</option>
              <option value="technical">Technical</option>
            </select>
            <button
              onClick={handleGenerateNarrative}
              disabled={generatingNarrative || !selectedProject}
              className="relative flex items-center gap-1.5 px-3 py-1.5 rounded text-sm text-purple-300 hover:text-purple-200 disabled:opacity-50 transition-colors"
              title={hasNewFindings ? 'New findings since last narrative — regenerate' : 'Generate AI narrative using local LLM'}
            >
              {generatingNarrative ? <Loader size={13} className="animate-spin" /> : <Brain size={13} />}
              AI Narrative
              {hasNewFindings && !generatingNarrative && (
                <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-500 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-red-500 shadow-[0_0_6px_rgba(239,68,68,0.8)]" />
                </span>
              )}
            </button>
          </div>

          <button
            onClick={handlePreviewReport}
            disabled={generating || !selectedProject}
            className="flex items-center gap-2 px-4 py-2 rounded-lg glass glass-hover text-sm text-slate-300 disabled:opacity-50 transition-all"
          >
            {generating ? <RefreshCw size={14} className="animate-spin" /> : <FileText size={14} />}
            Preview
          </button>
          <button
            onClick={() => handleGenerateReport('html')}
            disabled={generating || !selectedProject}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-sm text-white transition-all hover:shadow-glow-blue"
          >
            <Download size={14} /> HTML
          </button>
          <button
            onClick={() => handleGenerateReport('markdown')}
            disabled={generating || !selectedProject}
            className="flex items-center gap-2 px-4 py-2 rounded-lg glass glass-hover text-sm text-slate-300 disabled:opacity-50 transition-all"
          >
            <Download size={14} /> Markdown
          </button>
          <button
            onClick={handleExportPDF}
            disabled={generating || !selectedProject}
            className="flex items-center gap-2 px-4 py-2 rounded-lg glass glass-hover text-sm text-red-300 hover:text-red-200 disabled:opacity-50 transition-all"
            title="Export PDF (requires WeasyPrint)"
          >
            <FileDown size={14} /> PDF
          </button>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 glass rounded-lg p-1 w-fit">
        <button
          onClick={() => setActiveTab('findings')}
          className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${activeTab === 'findings' ? 'bg-blue-600 text-white shadow-glow-blue' : 'text-slate-400 hover:text-slate-200'}`}
        >
          Findings ({displayFindings.length}{template === 'executive_summary' ? `/${findings.length}` : ''})
        </button>
        <button
          onClick={() => setActiveTab('report')}
          className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${activeTab === 'report' ? 'bg-blue-600 text-white shadow-glow-blue' : 'text-slate-400 hover:text-slate-200'}`}
        >
          Report Preview
        </button>
        <button
          onClick={() => setActiveTab('narrative')}
          className={`flex items-center gap-1.5 px-4 py-1.5 rounded text-sm font-medium transition-colors ${activeTab === 'narrative' ? 'bg-purple-700 text-white' : 'text-slate-400 hover:text-slate-200'}`}
        >
          <Brain size={13} /> AI Narrative
        </button>
      </div>

      {/* Content */}
      {activeTab === 'findings' && (
        <>
          {template === 'executive_summary' && findings.length > 0 && (
            <div className="rounded-lg px-4 py-2.5 text-xs text-blue-300 border border-blue-700/30 flex items-center gap-2" style={{ background: 'rgba(37,99,235,0.08)' }}>
              Executive template active — showing {displayFindings.length} of {findings.length} findings (critical & high only)
            </div>
          )}
          <FindingsTable findings={displayFindings} loading={loading} />
        </>
      )}

      {activeTab === 'report' && (
        <div className="glass rounded-xl p-6">
          {reportPreview ? (
            <>
              {template === 'executive_summary' && (
                <div className="mb-4 p-4 rounded-lg border border-blue-700/20" style={{ background: 'rgba(37,99,235,0.06)' }}>
                  <p className="text-xs font-bold text-blue-400 uppercase tracking-wider mb-1">Executive Summary</p>
                  <p className="text-xs text-slate-400">
                    This report highlights <strong className="text-white">{displayFindings.length}</strong> critical and high severity findings
                    out of <strong className="text-white">{findings.length}</strong> total. Immediate remediation is recommended for all items below.
                  </p>
                </div>
              )}
              <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed">{reportPreview}</pre>
            </>
          ) : (
            <div className="text-center text-slate-400 py-12">
              <FileText size={40} className="mx-auto mb-3 opacity-30 text-cyan-600" />
              <p>Click "Preview" to generate a report preview</p>
            </div>
          )}
        </div>
      )}

      {activeTab === 'narrative' && (
        <div className="glass rounded-xl p-6 space-y-4">
          {narrativeError && (
            <div className="rounded-lg px-4 py-3 text-sm text-red-300 border border-red-700/30" style={{ background: 'rgba(127,29,29,0.2)' }}>
              {narrativeError}
              {narrativeError.includes('model configured') && (
                <span className="ml-2 text-red-400 underline cursor-pointer" onClick={() => window.location.hash = '#settings'}>
                  → Go to Settings → AI
                </span>
              )}
            </div>
          )}
          {narrative ? (
            <>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-purple-400">
                  <Brain size={16} />
                  <span className="text-sm font-medium capitalize">{narrativeStyle} Narrative</span>
                  {narrativeSavedAt && (
                    <span className="flex items-center gap-1 text-[11px] text-green-400 font-normal">
                      <BookmarkCheck size={11} />
                      Saved {new Date(narrativeSavedAt).toLocaleDateString()}
                    </span>
                  )}
                </div>
                <button
                  onClick={() => navigator.clipboard.writeText(narrative)}
                  className="text-xs text-slate-500 hover:text-slate-300 transition-colors px-2 py-1 glass rounded"
                >
                  Copy
                </button>
              </div>
              <div className="border-l-2 border-purple-700/40 pl-4 prose prose-invert prose-sm max-w-none
                prose-headings:text-purple-200 prose-headings:font-semibold
                prose-p:text-slate-300 prose-p:leading-relaxed
                prose-strong:text-slate-100 prose-strong:font-semibold
                prose-em:text-slate-300
                prose-ul:text-slate-300 prose-ol:text-slate-300
                prose-li:marker:text-purple-500
                prose-code:text-purple-300 prose-code:bg-purple-950/40 prose-code:px-1 prose-code:rounded prose-code:text-xs
                prose-blockquote:border-purple-600/50 prose-blockquote:text-slate-400
                prose-hr:border-purple-900/40">
                <ReactMarkdown>{narrative}</ReactMarkdown>
              </div>
            </>
          ) : (
            <div className="text-center text-slate-400 py-12">
              <Brain size={40} className="mx-auto mb-3 opacity-30 text-purple-500" />
              <p className="text-sm">Select a project and click "AI Narrative" to generate a narrative using your local LLM.</p>
              <p className="text-xs mt-2 text-slate-500">Configure your LLM endpoint in Settings → AI</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
