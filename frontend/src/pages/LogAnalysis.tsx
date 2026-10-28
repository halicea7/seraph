import { useState, useRef } from 'react'
import { getApiBase } from '@/lib/config'
import { useAiModel, completeFeature } from '@/lib/ai'
import AiModelSelect from '../components/AiModelSelect'
import { Brain, AlertTriangle, Globe, Hash, Mail } from 'lucide-react'
import Icon from '../components/Icon'

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

const SEV_STYLE: Record<string, { color: string; background: string; border: string; cardBg: string }> = {
  critical: { color: 'var(--crit)',   background: 'rgba(232,64,64,0.08)',  border: '1px solid rgba(232,64,64,0.3)',   cardBg: 'rgba(232,64,64,0.05)' },
  high:     { color: '#f97316',       background: 'rgba(249,115,22,0.08)', border: '1px solid rgba(249,115,22,0.3)',  cardBg: 'rgba(249,115,22,0.05)' },
  medium:   { color: 'var(--accent)', background: 'rgba(240,168,58,0.08)', border: '1px solid rgba(240,168,58,0.3)',  cardBg: 'rgba(240,168,58,0.05)' },
  low:      { color: 'var(--ok)',     background: 'rgba(84,175,97,0.08)',  border: '1px solid rgba(84,175,97,0.3)',   cardBg: 'rgba(84,175,97,0.05)' },
}

const rule = '1px solid var(--rule)'
const ruleStrong = '1px solid var(--rule-strong)'

// ── IOC helpers ───────────────────────────────────────────────────────────────

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
      title={copied ? 'Copied!' : `Copy ${value}`}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 5,
        fontFamily: 'var(--font-mono)', fontSize: 11, padding: '2px 8px',
        borderRadius: 3, border: `1px solid ${accent}30`,
        background: `${accent}0d`, color: accent, cursor: 'pointer',
      }}
    >
      {value}
      <Icon name={copied ? 'check' : 'copy'} size={9} color="currentColor" />
    </button>
  )
}

function IOCSection({ label, icon, items, accent }: { label: string; icon: React.ReactNode; items: string[]; accent: string }) {
  const [copied, setCopied] = useState(false)
  if (items.length === 0) return null
  function copyAll() {
    navigator.clipboard.writeText(items.join('\n'))
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }
  return (
    <div style={{ marginBottom: 18 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: accent }}>
          {icon}
          <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: 'var(--font-sans)' }}>{label}</span>
          <span style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', marginLeft: 2 }}>({items.length})</span>
        </div>
        <button
          onClick={copyAll}
          style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, padding: '2px 8px', borderRadius: 3, background: 'var(--bg)', border: ruleStrong, color: 'var(--fg-3)', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}
        >
          <Icon name={copied ? 'check' : 'copy'} size={9} color={copied ? 'var(--ok)' : 'currentColor'} />
          {copied ? 'Copied' : 'Copy all'}
        </button>
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
        {items.map((item, i) => <IOCPill key={i} value={item} accent={accent} />)}
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function LogAnalysis() {
  const [logText, setLogText] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [results, setResults] = useState<AnalysisResults | null>(null)
  const [aiTriaging, setAiTriaging] = useState(false)
  const { options: aiModels, modelKey: aiModelKey, setModelKey: setAiModelKey } = useAiModel()
  const [aiResult, setAiResult] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'patterns' | 'iocs' | 'ai'>('patterns')
  const [aiError, setAiError] = useState('')
  const [copiedAi, setCopiedAi] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  async function handleAnalyze() {
    if (!logText.trim()) return
    setAnalyzing(true); setResults(null); setAiResult(null); setAiError('')
    try {
      const res = await fetch(`${getApiBase()}/logs/analyze`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: logText }),
      })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data.detail || `HTTP ${res.status}`)
      }
      setResults(await res.json())
      setActiveTab('patterns')
    } catch (err: any) {
      setAiError(err.message || 'Analysis failed.')
    } finally { setAnalyzing(false) }
  }

  async function handleAiTriage() {
    if (!results) return
    setAiTriaging(true); setAiError('')
    try {
      const text = await completeFeature(aiModelKey, '/logs/ai-triage', { text: logText, patterns: results.patterns })
      setAiResult(text)
      setActiveTab('ai')
    } catch (err: any) {
      setAiError(err.message || 'AI triage failed.')
    } finally { setAiTriaging(false) }
  }

  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = ev => setLogText(ev.target?.result as string)
    reader.readAsText(file)
    e.target.value = ''
  }

  function handleClear() {
    setLogText(''); setResults(null); setAiResult(null); setAiError('')
  }

  const iocs = results?.iocs
  const lineCount = logText ? logText.split('\n').filter(l => l.trim()).length : 0

  const TABS = [
    { key: 'patterns', label: `Patterns (${results?.pattern_count ?? 0})`, icon: <AlertTriangle size={11} />, color: 'var(--accent)' },
    { key: 'iocs',     label: `IOCs (${results?.ioc_count ?? 0})`,         icon: <Hash size={11} />,          color: 'var(--med)' },
    { key: 'ai',       label: 'AI Triage',                                  icon: <Brain size={11} />,         color: '#a855f7' },
  ] as const

  return (
    <div style={{ padding: 24, height: '100%', overflowY: 'auto', background: 'var(--bg)', color: 'var(--fg)' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
        <Icon name="search" size={20} color="var(--accent)" />
        <div>
          <h1 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: 'var(--fg)', fontFamily: 'var(--font-sans)' }}>Log Analysis</h1>
          <p style={{ margin: '2px 0 0', fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>Detect attack patterns and extract IOCs from logs</p>
        </div>
      </div>

      {/* Two-column layout */}
      <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>

        {/* LEFT — Input panel */}
        <div style={{ width: '38%', flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, overflow: 'hidden' }}>
            <div style={{ padding: '10px 14px', borderBottom: rule, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Icon name="file" size={13} color="var(--fg-3)" />
                <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: 'var(--font-sans)' }}>Log Input</span>
              </div>
              {logText && (
                <button onClick={handleClear} title="Clear" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0 }}>
                  <Icon name="x" size={12} color="currentColor" />
                </button>
              )}
            </div>
            <div style={{ padding: 12 }}>
              <textarea
                value={logText}
                onChange={e => setLogText(e.target.value)}
                placeholder={`Paste log output here...\n\nSupports: auth.log, syslog, Apache/Nginx access logs, Windows Event Log, command history`}
                style={{
                  width: '100%', boxSizing: 'border-box',
                  fontFamily: 'var(--font-mono)', fontSize: 11,
                  color: 'var(--fg-2)', background: 'transparent',
                  border: 'none', outline: 'none', resize: 'none',
                  minHeight: 280, lineHeight: 1.6,
                }}
              />
            </div>
          </div>

          {/* Action row */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <input ref={fileInputRef} type="file" accept=".log,.txt,.out,.csv" onChange={handleFileUpload} style={{ display: 'none' }} />
            <button
              onClick={() => fileInputRef.current?.click()}
              style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 12px', borderRadius: 4, background: 'none', border: ruleStrong, fontSize: 12, color: 'var(--fg-3)', cursor: 'pointer', fontFamily: 'var(--font-sans)', flexShrink: 0 }}
            >
              <Icon name="upload" size={12} color="currentColor" /> Upload File
            </button>
            <button
              onClick={handleAnalyze}
              disabled={analyzing || !logText.trim()}
              style={{
                flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                padding: '7px 0', borderRadius: 4,
                background: analyzing || !logText.trim() ? 'var(--bg-2)' : 'var(--accent)',
                color: analyzing || !logText.trim() ? 'var(--fg-3)' : 'var(--bg)',
                border: 'none', fontSize: 12, fontWeight: 700,
                cursor: analyzing || !logText.trim() ? 'not-allowed' : 'pointer',
                fontFamily: 'var(--font-sans)', opacity: analyzing || !logText.trim() ? 0.5 : 1,
              }}
            >
              <Icon name={analyzing ? 'refresh' : 'play'} size={13} color="currentColor" />
              {analyzing ? 'Analyzing…' : 'Analyze'}
            </button>
          </div>

          {logText && (
            <p style={{ margin: 0, fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', paddingLeft: 2 }}>
              {lineCount.toLocaleString()} lines in buffer
            </p>
          )}

          {/* Quick stats */}
          {results && (
            <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, padding: '12px 14px' }}>
              <p style={{ margin: '0 0 10px', fontSize: 10, fontWeight: 700, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: 'var(--font-sans)' }}>Analysis Summary</p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
                <div style={{ textAlign: 'center' }}>
                  <p style={{ margin: 0, fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--fg)' }}>{results.line_count.toLocaleString()}</p>
                  <p style={{ margin: '2px 0 0', fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>Lines</p>
                </div>
                <div style={{ textAlign: 'center' }}>
                  <p style={{ margin: 0, fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>{results.pattern_count}</p>
                  <p style={{ margin: '2px 0 0', fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>Patterns</p>
                </div>
                <div style={{ textAlign: 'center' }}>
                  <p style={{ margin: 0, fontSize: 18, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--med)' }}>{results.ioc_count}</p>
                  <p style={{ margin: '2px 0 0', fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>IOCs</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* RIGHT — Results panel */}
        <div style={{ flex: 1, minWidth: 0 }}>
          {!results ? (
            <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, padding: '64px 24px', textAlign: 'center' }}>
              <Icon name="file" size={44} color="var(--rule-strong)" />
              <p style={{ margin: '12px 0 4px', fontSize: 13, color: 'var(--fg-2)', fontWeight: 600, fontFamily: 'var(--font-sans)' }}>No analysis yet</p>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>
                Paste log data on the left and click Analyze to detect attack patterns and extract IOCs.
              </p>
            </div>
          ) : (
            <div style={{ background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, overflow: 'hidden' }}>
              {/* Tab bar */}
              <div style={{ display: 'flex', alignItems: 'center', borderBottom: rule, padding: '0 4px' }}>
                {TABS.map(tab => {
                  const isActive = activeTab === tab.key
                  return (
                    <button
                      key={tab.key}
                      onClick={() => setActiveTab(tab.key)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 6,
                        padding: '10px 14px', fontSize: 11, fontWeight: isActive ? 600 : 400,
                        background: 'none', border: 'none', cursor: 'pointer',
                        color: isActive ? tab.color : 'var(--fg-3)',
                        borderBottom: isActive ? `2px solid ${tab.color}` : '2px solid transparent',
                        fontFamily: 'var(--font-sans)',
                      }}
                    >
                      {tab.icon} {tab.label}
                    </button>
                  )
                })}
              </div>

              <div style={{ padding: 16, overflowY: 'auto', maxHeight: '65vh' }}>

                {/* ── Patterns tab ── */}
                {activeTab === 'patterns' && (
                  results.patterns.length === 0 ? (
                    <div style={{ textAlign: 'center', padding: '48px 0' }}>
                      <Icon name="shield" size={32} color="var(--ok)" />
                      <p style={{ margin: '10px 0 4px', fontSize: 13, color: 'var(--ok)', fontWeight: 600, fontFamily: 'var(--font-sans)' }}>No attack patterns detected</p>
                      <p style={{ margin: 0, fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>The log appears clean against known attack signatures.</p>
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                      {results.patterns.map((pattern, idx) => {
                        const ss = SEV_STYLE[pattern.severity] ?? SEV_STYLE.low
                        return (
                          <div key={idx} style={{ borderRadius: 4, padding: '12px 14px', background: ss.cardBg, border: ss.border }}>
                            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 6 }}>
                              <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', fontFamily: 'var(--font-sans)', color: ss.color, background: ss.background, border: ss.border, flexShrink: 0 }}>
                                {pattern.severity}
                              </span>
                              <p style={{ margin: 0, fontSize: 13, fontWeight: 600, color: 'var(--fg)', fontFamily: 'var(--font-sans)' }}>{pattern.name}</p>
                            </div>
                            {pattern.description && (
                              <p style={{ margin: '0 0 10px', fontSize: 12, color: 'var(--fg-2)', lineHeight: 1.5, fontFamily: 'var(--font-sans)' }}>{pattern.description}</p>
                            )}
                            {pattern.matches.length > 0 && (
                              <div>
                                <p style={{ margin: '0 0 5px', fontSize: 10, fontWeight: 700, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: 'var(--font-sans)' }}>
                                  Match examples ({pattern.matches.length})
                                </p>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                                  {pattern.matches.slice(0, 3).map((m, mi) => (
                                    <div key={mi} style={{ display: 'flex', alignItems: 'baseline', gap: 8, borderRadius: 2, padding: '4px 8px', background: 'rgba(0,0,0,0.25)' }}>
                                      <span style={{ fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--fg-3)', flexShrink: 0, width: 36, textAlign: 'right' }}>L{m.line}</span>
                                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--fg-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.text}</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  )
                )}

                {/* ── IOCs tab ── */}
                {activeTab === 'iocs' && iocs && (
                  results.ioc_count === 0 ? (
                    <div style={{ textAlign: 'center', padding: '48px 0' }}>
                      <Icon name="shield" size={32} color="var(--rule-strong)" />
                      <p style={{ margin: '10px 0 4px', fontSize: 13, color: 'var(--fg-2)', fontWeight: 600, fontFamily: 'var(--font-sans)' }}>No IOCs extracted</p>
                      <p style={{ margin: 0, fontSize: 12, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>No IPs, domains, hashes, emails or URLs were found.</p>
                    </div>
                  ) : (
                    <div>
                      <IOCSection label="Public IPs"        icon={<Globe size={13} />} items={iocs.public_ips}  accent="#f97316" />
                      <IOCSection label="Private IPs"       icon={<Icon name="shield" size={13} color="currentColor" />} items={iocs.private_ips} accent="#64748b" />
                      <IOCSection label="Domains"           icon={<Globe size={13} />} items={iocs.domains}    accent="var(--med)" />
                      <IOCSection label="MD5 Hashes"        icon={<Hash size={13} />}  items={iocs.md5}        accent="#a78bfa" />
                      <IOCSection label="SHA1 Hashes"       icon={<Hash size={13} />}  items={iocs.sha1}       accent="#a78bfa" />
                      <IOCSection label="SHA256 Hashes"     icon={<Hash size={13} />}  items={iocs.sha256}     accent="#7c3aed" />
                      <IOCSection label="Email Addresses"   icon={<Mail size={13} />}  items={iocs.emails}     accent="var(--accent)" />
                      <IOCSection label="URLs"              icon={<Icon name="link" size={13} color="currentColor" />} items={iocs.urls} accent="var(--ok)" />
                    </div>
                  )
                )}

                {/* ── AI Triage tab ── */}
                {activeTab === 'ai' && (
                  <div>
                    {aiError && (
                      <div style={{ fontSize: 12, color: 'var(--crit)', background: 'rgba(232,64,64,0.08)', border: '1px solid rgba(232,64,64,0.3)', borderRadius: 3, padding: '8px 12px', marginBottom: 14, fontFamily: 'var(--font-sans)' }}>
                        {aiError}
                      </div>
                    )}

                    {!aiResult && !aiTriaging && (
                      <div style={{ textAlign: 'center', padding: '48px 0' }}>
                        <Brain size={40} style={{ margin: '0 auto 14px', color: '#a855f7', display: 'block', opacity: 0.7 }} />
                        <p style={{ margin: '0 0 8px', fontSize: 13, color: 'var(--fg)', fontWeight: 600, fontFamily: 'var(--font-sans)' }}>AI Log Triage</p>
                        <p style={{ margin: '0 0 20px', fontSize: 12, color: 'var(--fg-3)', maxWidth: 300, marginLeft: 'auto', marginRight: 'auto', fontFamily: 'var(--font-sans)' }}>
                          Run AI analysis to get a prioritized assessment of the detected patterns and recommended actions.
                        </p>
                        <button
                          onClick={handleAiTriage}
                          disabled={aiTriaging || !results}
                          style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '8px 20px', borderRadius: 4, background: 'rgba(168,85,247,0.15)', border: '1px solid rgba(168,85,247,0.4)', color: '#a855f7', fontSize: 13, fontWeight: 600, cursor: 'pointer', fontFamily: 'var(--font-sans)' }}
                        >
                          <Brain size={14} /> Run AI Triage
                        </button>
                        <div style={{ marginTop: 14, display: 'flex', justifyContent: 'center' }}>
                          <AiModelSelect value={aiModelKey} onChange={setAiModelKey} options={aiModels} />
                        </div>
                        <p style={{ margin: '14px 0 0', fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>
                          Requires AI to be configured in Settings → AI
                        </p>
                      </div>
                    )}

                    {aiTriaging && (
                      <div style={{ textAlign: 'center', padding: '48px 0' }}>
                        <Icon name="refresh" size={28} color="#a855f7" />
                        <p style={{ margin: '12px 0 0', fontSize: 13, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>Triaging with AI…</p>
                      </div>
                    )}

                    {aiResult && !aiTriaging && (
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#a855f7' }}>
                            <Brain size={15} />
                            <span style={{ fontSize: 13, fontWeight: 600, fontFamily: 'var(--font-sans)' }}>AI Triage Report</span>
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <button
                              onClick={() => { navigator.clipboard.writeText(aiResult); setCopiedAi(true); setTimeout(() => setCopiedAi(false), 1500) }}
                              style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, padding: '4px 10px', borderRadius: 3, background: 'var(--bg)', border: ruleStrong, color: 'var(--fg-3)', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}
                            >
                              <Icon name={copiedAi ? 'check' : 'copy'} size={10} color={copiedAi ? 'var(--ok)' : 'currentColor'} />
                              {copiedAi ? 'Copied' : 'Copy'}
                            </button>
                            <button
                              onClick={handleAiTriage}
                              disabled={aiTriaging}
                              style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, padding: '4px 10px', borderRadius: 3, background: 'var(--bg)', border: ruleStrong, color: 'var(--fg-3)', cursor: 'pointer', fontFamily: 'var(--font-sans)' }}
                            >
                              <Icon name="refresh" size={10} color="currentColor" /> Re-run
                            </button>
                          </div>
                        </div>
                        <div style={{ borderRadius: 4, padding: '16px 18px', background: 'rgba(168,85,247,0.05)', border: '1px solid rgba(168,85,247,0.2)' }}>
                          <div style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.6, whiteSpace: 'pre-wrap', borderLeft: '2px solid rgba(168,85,247,0.4)', paddingLeft: 14, fontFamily: 'var(--font-sans)' }}>
                            {aiResult}
                          </div>
                        </div>
                        <p style={{ margin: '10px 0 0', fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>
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
