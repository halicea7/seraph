import { useState, useRef } from 'react'
import {
  Search,
  Play,
  Upload,
  Brain,
  Copy,
  Check,
  AlertTriangle,
  Shield,
  Globe,
  Hash,
  Mail,
  Link,
  RefreshCw,
  X,
  FileText,
} from 'lucide-react'

// ── Types ─────────────────────────────────────────────────────────────────────

interface PatternMatch {
  id: string
  name: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  matches: Array<{ line: number; text: string }>
}

interface IOCs {
  public_ips: string[]
  private_ips: string[]
  domains: string[]
  md5: string[]
  sha1: string[]
  sha256: string[]
  emails: string[]
  urls: string[]
}

interface AnalysisResults {
  line_count: number
  pattern_count: number
  ioc_count: number
  patterns: PatternMatch[]
  iocs: IOCs
}

// ── Style maps ────────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<string, { card: string; badge: string; dot: string }> = {
  critical: {
    card:  'bg-red-950/40 border border-red-500/30',
    badge: 'bg-red-950/60 text-red-400 border border-red-500/40',
    dot:   '#ef4444',
  },
  high: {
    card:  'bg-orange-950/40 border border-orange-500/30',
    badge: 'bg-orange-950/60 text-orange-400 border border-orange-500/40',
    dot:   '#f97316',
  },
  medium: {
    card:  'bg-amber-950/30 border border-amber-500/30',
    badge: 'bg-amber-950/50 text-amber-400 border border-amber-500/40',
    dot:   '#f59e0b',
  },
  low: {
    card:  'bg-green-950/30 border border-green-500/30',
    badge: 'bg-green-950/50 text-green-400 border border-green-500/40',
    dot:   '#22c55e',
  },
}

// ── IOC section helper ────────────────────────────────────────────────────────

function IOCSection({
  label,
  icon,
  items,
  accent,
}: {
  label: string
  icon: React.ReactNode
  items: string[]
  accent: string
}) {
  const [copied, setCopied] = useState(false)

  if (items.length === 0) return null

  function copyAll() {
    navigator.clipboard.writeText(items.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className="mb-5">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-1.5" style={{ color: accent }}>
          {icon}
          <span className="text-xs font-bold uppercase tracking-wider">{label}</span>
          <span className="text-[10px] text-slate-600 font-mono ml-1">({items.length})</span>
        </div>
        <button
          onClick={copyAll}
          className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded glass text-slate-500 hover:text-slate-300 transition-colors"
        >
          {copied ? <Check size={10} className="text-green-400" /> : <Copy size={10} />}
          {copied ? 'Copied' : 'Copy all'}
        </button>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {items.map((item, i) => (
          <IOCPill key={i} value={item} accent={accent} />
        ))}
      </div>
    </div>
  )
}

function IOCPill({ value, accent }: { value: string; accent: string }) {
  const [copied, setCopied] = useState(false)

  function copy() {
    navigator.clipboard.writeText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 1200)
  }

  return (
    <button
      onClick={copy}
      className="flex items-center gap-1 font-mono text-[11px] px-2 py-0.5 rounded border transition-all hover:opacity-80"
      style={{
        background: `${accent}0d`,
        borderColor: `${accent}30`,
        color: accent,
      }}
      title={copied ? 'Copied!' : `Copy ${value}`}
    >
      {value}
      {copied ? <Check size={9} /> : <Copy size={9} className="opacity-50" />}
    </button>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function LogAnalysis() {
  const [logText, setLogText] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [results, setResults] = useState<AnalysisResults | null>(null)
  const [aiTriaging, setAiTriaging] = useState(false)
  const [aiResult, setAiResult] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'patterns' | 'iocs' | 'ai'>('patterns')
  const [aiError, setAiError] = useState('')
  const [copiedAi, setCopiedAi] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // ── Actions ─────────────────────────────────────────────────────────────────

  async function handleAnalyze() {
    if (!logText.trim()) return
    setAnalyzing(true)
    setResults(null)
    setAiResult(null)
    setAiError('')
    try {
      const res = await fetch('/api/v1/logs/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: logText }),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data.detail || `HTTP ${res.status}`)
      }
      const data: AnalysisResults = await res.json()
      setResults(data)
      setActiveTab('patterns')
    } catch (err: any) {
      setAiError(err.message || 'Analysis failed.')
    } finally {
      setAnalyzing(false)
    }
  }

  async function handleAiTriage() {
    if (!results) return
    setAiTriaging(true)
    setAiError('')
    try {
      const res = await fetch('/api/v1/logs/ai-triage', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: logText, patterns: results.patterns }),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data.detail || `HTTP ${res.status}`)
      }
      const data = await res.json()
      setAiResult(data.triage || data.result || '')
      setActiveTab('ai')
    } catch (err: any) {
      setAiError(err.message || 'AI triage failed.')
    } finally {
      setAiTriaging(false)
    }
  }

  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = ev => {
      setLogText(ev.target?.result as string)
    }
    reader.readAsText(file)
    e.target.value = ''
  }

  function handleClear() {
    setLogText('')
    setResults(null)
    setAiResult(null)
    setAiError('')
  }

  // ── Render ──────────────────────────────────────────────────────────────────

  const iocs = results?.iocs

  const lineCount = logText ? logText.split('\n').filter(l => l.trim()).length : 0

  return (
    <div className="p-6 h-full overflow-y-auto" style={{ background: 'var(--bg-base)' }}>

      {/* Page header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="glass rounded-xl p-2">
          <Search size={22} className="text-cyan-400" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-slate-100">Log Analysis</h1>
          <p className="text-xs text-slate-500 mt-0.5">Detect attack patterns and extract IOCs from logs</p>
        </div>
      </div>

      {/* Two-column layout */}
      <div className="flex gap-4 min-h-0" style={{ alignItems: 'flex-start' }}>

        {/* LEFT — Input panel (40%) */}
        <div className="w-[40%] flex-shrink-0 space-y-3">
          <div className="glass rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-cyan-900/20 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileText size={14} className="text-slate-400" />
                <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Log Input</span>
              </div>
              {logText && (
                <button
                  onClick={handleClear}
                  className="text-slate-600 hover:text-slate-400 transition-colors"
                  title="Clear"
                >
                  <X size={13} />
                </button>
              )}
            </div>
            <div className="p-3">
              <textarea
                value={logText}
                onChange={e => setLogText(e.target.value)}
                placeholder={`Paste log output here...\n\nSupports: auth.log, syslog, Apache/Nginx access logs, Windows Event Log, command history`}
                className="w-full font-mono text-xs text-slate-300 placeholder-slate-700 focus:outline-none resize-none leading-relaxed"
                style={{
                  background: 'transparent',
                  minHeight: '320px',
                }}
              />
            </div>
          </div>

          {/* Action row */}
          <div className="flex items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              accept=".log,.txt,.out,.csv"
              onChange={handleFileUpload}
              className="hidden"
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-900/30 text-xs text-slate-400 hover:text-cyan-400 hover:border-cyan-700/40 transition-all"
            >
              <Upload size={13} />
              Upload File
            </button>
            <button
              onClick={handleAnalyze}
              disabled={analyzing || !logText.trim()}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold text-white transition-all disabled:opacity-40 flex-1 justify-center"
              style={{ background: 'var(--accent)' }}
            >
              {analyzing
                ? <RefreshCw size={14} className="animate-spin" />
                : <Play size={14} />
              }
              {analyzing ? 'Analyzing…' : 'Analyze'}
            </button>
          </div>

          {logText && (
            <p className="text-[10px] text-slate-600 font-mono px-1">
              {lineCount.toLocaleString()} lines in buffer
            </p>
          )}

          {/* Quick stats after analysis */}
          {results && (
            <div className="glass rounded-xl p-4 space-y-2">
              <p className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3">Analysis Summary</p>
              <div className="grid grid-cols-3 gap-2">
                <div className="text-center">
                  <p className="text-lg font-bold font-mono text-slate-100">{results.line_count.toLocaleString()}</p>
                  <p className="text-[10px] text-slate-500">Lines Analyzed</p>
                </div>
                <div className="text-center">
                  <p className="text-lg font-bold font-mono text-amber-400">{results.pattern_count}</p>
                  <p className="text-[10px] text-slate-500">Patterns Found</p>
                </div>
                <div className="text-center">
                  <p className="text-lg font-bold font-mono text-cyan-400">{results.ioc_count}</p>
                  <p className="text-[10px] text-slate-500">IOCs Extracted</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* RIGHT — Results panel (60%) */}
        <div className="flex-1 min-w-0">
          {!results ? (
            /* Empty state */
            <div className="glass rounded-xl p-16 text-center">
              <FileText size={44} className="mx-auto mb-4 text-slate-700" />
              <p className="text-slate-400 text-sm font-medium">No analysis yet</p>
              <p className="text-slate-600 text-xs mt-2">
                Paste log data on the left and click Analyze to detect attack patterns and extract IOCs.
              </p>
            </div>
          ) : (
            <div className="glass rounded-xl overflow-hidden">
              {/* Tab bar */}
              <div className="flex items-center gap-0 border-b border-cyan-900/20 px-1 pt-1">
                <button
                  onClick={() => setActiveTab('patterns')}
                  className={`px-4 py-2 text-xs font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                    activeTab === 'patterns'
                      ? 'text-amber-400 border-b-2 border-amber-500 bg-amber-950/10'
                      : 'text-slate-500 hover:text-slate-300'
                  }`}
                >
                  <AlertTriangle size={12} />
                  Patterns ({results.pattern_count})
                </button>
                <button
                  onClick={() => setActiveTab('iocs')}
                  className={`px-4 py-2 text-xs font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                    activeTab === 'iocs'
                      ? 'text-cyan-400 border-b-2 border-cyan-500 bg-cyan-950/10'
                      : 'text-slate-500 hover:text-slate-300'
                  }`}
                >
                  <Hash size={12} />
                  IOCs ({results.ioc_count})
                </button>
                <button
                  onClick={() => setActiveTab('ai')}
                  className={`px-4 py-2 text-xs font-medium rounded-t-lg transition-colors flex items-center gap-1.5 ${
                    activeTab === 'ai'
                      ? 'text-purple-400 border-b-2 border-purple-500 bg-purple-950/10'
                      : 'text-slate-500 hover:text-slate-300'
                  }`}
                >
                  <Brain size={12} />
                  AI Triage
                </button>
              </div>

              <div className="p-4 overflow-y-auto" style={{ maxHeight: '70vh' }}>

                {/* ── Patterns tab ── */}
                {activeTab === 'patterns' && (
                  <>
                    {results.patterns.length === 0 ? (
                      <div className="text-center py-12">
                        <Shield size={32} className="mx-auto mb-3 text-green-600 opacity-60" />
                        <p className="text-green-400 text-sm font-medium">No attack patterns detected</p>
                        <p className="text-slate-500 text-xs mt-1">The log appears clean against known attack signatures.</p>
                      </div>
                    ) : (
                      <div className="space-y-3">
                        {results.patterns.map((pattern, idx) => {
                          const styles = SEVERITY_STYLES[pattern.severity] ?? SEVERITY_STYLES.low
                          return (
                            <div key={idx} className={`rounded-xl p-4 ${styles.card}`}>
                              <div className="flex items-start gap-2 mb-2">
                                <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wide flex-shrink-0 ${styles.badge}`}>
                                  {pattern.severity}
                                </span>
                                <p className="text-sm font-semibold text-slate-100">{pattern.name}</p>
                              </div>
                              {pattern.description && (
                                <p className="text-xs text-slate-400 mb-3 leading-relaxed">{pattern.description}</p>
                              )}
                              {pattern.matches.length > 0 && (
                                <div className="space-y-1">
                                  <p className="text-[10px] font-bold text-slate-600 uppercase tracking-wider mb-1">
                                    Match examples ({pattern.matches.length})
                                  </p>
                                  {pattern.matches.slice(0, 3).map((m, mi) => (
                                    <div
                                      key={mi}
                                      className="flex items-baseline gap-2 rounded px-2 py-1"
                                      style={{ background: 'rgba(0,0,0,0.25)' }}
                                    >
                                      <span className="text-[9px] font-mono text-slate-600 flex-shrink-0 w-10 text-right">
                                        L{m.line}
                                      </span>
                                      <span className="font-mono text-[10px] text-slate-300 truncate">
                                        {m.text}
                                      </span>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </>
                )}

                {/* ── IOCs tab ── */}
                {activeTab === 'iocs' && iocs && (
                  <>
                    {results.ioc_count === 0 ? (
                      <div className="text-center py-12">
                        <Shield size={32} className="mx-auto mb-3 text-slate-700 opacity-60" />
                        <p className="text-slate-400 text-sm font-medium">No IOCs extracted</p>
                        <p className="text-slate-600 text-xs mt-1">No IPs, domains, hashes, emails or URLs were found.</p>
                      </div>
                    ) : (
                      <div>
                        <IOCSection
                          label="Public IPs"
                          icon={<Globe size={13} />}
                          items={iocs.public_ips}
                          accent="#f97316"
                        />
                        <IOCSection
                          label="Private IPs"
                          icon={<Shield size={13} />}
                          items={iocs.private_ips}
                          accent="#64748b"
                        />
                        <IOCSection
                          label="Domains"
                          icon={<Globe size={13} />}
                          items={iocs.domains}
                          accent="#06b6d4"
                        />
                        <IOCSection
                          label="MD5 Hashes"
                          icon={<Hash size={13} />}
                          items={iocs.md5}
                          accent="#a78bfa"
                        />
                        <IOCSection
                          label="SHA1 Hashes"
                          icon={<Hash size={13} />}
                          items={iocs.sha1}
                          accent="#a78bfa"
                        />
                        <IOCSection
                          label="SHA256 Hashes"
                          icon={<Hash size={13} />}
                          items={iocs.sha256}
                          accent="#7c3aed"
                        />
                        <IOCSection
                          label="Email Addresses"
                          icon={<Mail size={13} />}
                          items={iocs.emails}
                          accent="#f59e0b"
                        />
                        <IOCSection
                          label="URLs"
                          icon={<Link size={13} />}
                          items={iocs.urls}
                          accent="#22c55e"
                        />
                      </div>
                    )}
                  </>
                )}

                {/* ── AI Triage tab ── */}
                {activeTab === 'ai' && (
                  <div>
                    {aiError && (
                      <div
                        className="rounded-lg px-4 py-3 text-xs text-red-300 border border-red-700/30 mb-4"
                        style={{ background: 'rgba(127,29,29,0.15)' }}
                      >
                        {aiError}
                      </div>
                    )}

                    {!aiResult && !aiTriaging && (
                      <div className="text-center py-12">
                        <Brain size={40} className="mx-auto mb-4 text-purple-700 opacity-60" />
                        <p className="text-slate-300 text-sm font-medium mb-2">AI Log Triage</p>
                        <p className="text-slate-500 text-xs mb-6 max-w-xs mx-auto">
                          Run AI analysis to get a prioritized assessment of the detected patterns and recommended actions.
                        </p>
                        <button
                          onClick={handleAiTriage}
                          disabled={aiTriaging || !results}
                          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-semibold text-white transition-all disabled:opacity-40"
                          style={{ background: 'rgba(88,28,135,0.7)', border: '1px solid rgba(139,92,246,0.4)' }}
                        >
                          <Brain size={15} />
                          Run AI Triage
                        </button>
                        <p className="text-xs text-slate-600 mt-4">
                          Requires AI to be configured in Settings → AI
                        </p>
                      </div>
                    )}

                    {aiTriaging && (
                      <div className="text-center py-12">
                        <RefreshCw size={28} className="mx-auto mb-3 text-purple-400 animate-spin" />
                        <p className="text-slate-400 text-sm">Triaging with AI…</p>
                      </div>
                    )}

                    {aiResult && !aiTriaging && (
                      <div>
                        <div className="flex items-center justify-between mb-4">
                          <div className="flex items-center gap-2 text-purple-400">
                            <Brain size={16} />
                            <span className="text-sm font-semibold">AI Triage Report</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => {
                                navigator.clipboard.writeText(aiResult)
                                setCopiedAi(true)
                                setTimeout(() => setCopiedAi(false), 1500)
                              }}
                              className="flex items-center gap-1 text-xs px-2 py-1 glass rounded text-slate-500 hover:text-slate-300 transition-colors"
                            >
                              {copiedAi ? <Check size={11} className="text-green-400" /> : <Copy size={11} />}
                              {copiedAi ? 'Copied' : 'Copy'}
                            </button>
                            <button
                              onClick={handleAiTriage}
                              disabled={aiTriaging}
                              className="flex items-center gap-1 text-xs px-2 py-1 glass rounded text-slate-500 hover:text-slate-300 transition-colors"
                            >
                              <RefreshCw size={11} />
                              Re-run
                            </button>
                          </div>
                        </div>
                        <div
                          className="rounded-xl p-5 border border-purple-900/30"
                          style={{ background: 'rgba(88,28,135,0.06)' }}
                        >
                          <div className="text-sm text-slate-300 leading-relaxed whitespace-pre-wrap border-l-2 border-purple-700/40 pl-4">
                            {aiResult}
                          </div>
                        </div>
                        <p className="text-[10px] text-slate-600 mt-3">
                          AI analysis may not be exhaustive. Verify findings manually.
                        </p>
                      </div>
                    )}
                  </div>
                )}

              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
