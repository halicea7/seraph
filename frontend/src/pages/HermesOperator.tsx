import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getApiBase, wsUrl } from '@/lib/config'
import Icon from '@/components/Icon'
import EmptyState from '@/components/EmptyState'
import { useToast } from '@/contexts/ToastContext'
import { getProjects, getTargets, getHermesStatus, createHermesRun, type HermesStatus } from '@/api/client'
import { MODE_CONFIGS, type OperatorMode } from '@/lib/operator'
import type { Project, TargetSummary } from '@/types'

// ══════════════════════════════════════════════════════════════════════════════
// Hermes Operator — a second, autonomous take on the AI Operator. The Hermes Agent
// runtime (Nous Research) runs its OWN tool loop on the Seraph backend, driven by
// the user's Ollama model, with smart approvals + a target-scoped prompt. Seraph
// just streams the transcript. Complements (doesn't replace) the supervised Operator.
// ══════════════════════════════════════════════════════════════════════════════

const rule = '1px solid var(--rule)'
const MODES: OperatorMode[] = ['recon', 'audit', 'attack']

const labelStyle: React.CSSProperties = {
  fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em',
  color: 'var(--fg-3)', marginBottom: 5, display: 'block',
}
const inputStyle: React.CSSProperties = {
  width: '100%', background: 'var(--bg)', border: '1px solid var(--rule-strong)',
  color: 'var(--fg)', padding: '7px 9px', fontSize: 12, fontFamily: 'var(--font-mono)',
}

function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, '').replace(/\x1b\][^\x07]*\x07/g, '')
}

export default function HermesOperator() {
  const navigate = useNavigate()
  const toast = useToast()

  const [status, setStatus] = useState<HermesStatus | null>(null)
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedProject, setSelectedProject] = useState('')
  const [targets, setTargets] = useState<TargetSummary[]>([])
  const [selectedTarget, setSelectedTarget] = useState('')
  const [mode, setMode] = useState<OperatorMode>('recon')
  const [models, setModels] = useState<string[]>([])
  const [selectedModel, setSelectedModel] = useState('')

  const [running, setRunning] = useState(false)
  const [output, setOutput] = useState('')
  const wsRef = useRef<WebSocket | null>(null)
  const outRef = useRef<HTMLPreElement>(null)

  // ── Init ──────────────────────────────────────────────────────────────────
  useEffect(() => {
    getHermesStatus().then(setStatus).catch(() => setStatus({ installed: false, version: '', ollama_url: '', ollama_reachable: false }))
    getProjects().then(ps => { setProjects(ps); if (ps.length) setSelectedProject(ps[0].id) })
    fetch(`${getApiBase()}/ai/models`)
      .then(r => r.ok ? r.json() : { models: [] })
      .then(d => { setModels(d.models ?? []); if (d.models?.length) setSelectedModel(d.models[0]) })
      .catch(() => { /* offline */ })
  }, [])

  useEffect(() => {
    if (!selectedProject) return
    getTargets(selectedProject).then(ts => { setTargets(ts); setSelectedTarget(ts[0]?.id ?? '') })
  }, [selectedProject])

  // Auto-scroll transcript
  useEffect(() => {
    if (outRef.current) outRef.current.scrollTop = outRef.current.scrollHeight
  }, [output])

  useEffect(() => () => { wsRef.current?.close() }, [])

  async function start() {
    if (!selectedProject || !selectedTarget || !selectedModel) {
      toast.error('Pick a project, target, and model first')
      return
    }
    setOutput('')
    setRunning(true)
    try {
      const run = await createHermesRun({
        project_id: selectedProject, target_id: selectedTarget, mode, model: selectedModel,
      })
      const ws = new WebSocket(wsUrl(`/ws/hermes/${run.scan_id}`))
      wsRef.current = ws
      ws.onopen = () => ws.send(JSON.stringify({ action: 'run' }))
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data)
          if (msg.type === 'stdout' || msg.type === 'stderr') {
            setOutput(o => o + stripAnsi(msg.data))
          } else if (msg.type === 'exit') {
            setOutput(o => o + `\n\n[engagement ended · exit ${msg.code}]\n`)
            setRunning(false)
          } else if (msg.type === 'error') {
            setOutput(o => o + `\n[error] ${msg.data}\n`)
            setRunning(false)
          }
        } catch { /* non-JSON */ }
      }
      ws.onerror = () => { setOutput(o => o + '\n[error] WebSocket connection failed\n'); setRunning(false) }
      ws.onclose = () => setRunning(false)
    } catch (err: any) {
      toast.error(err?.message ?? 'Failed to start Hermes')
      setRunning(false)
    }
  }

  function stop() {
    wsRef.current?.close()
    wsRef.current = null
    setRunning(false)
    setOutput(o => o + '\n[stopped by operator]\n')
  }

  const target = targets.find(t => t.id === selectedTarget)
  const notInstalled = status && !status.installed

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      {/* Header */}
      <div style={{ padding: '16px var(--pad)', borderBottom: rule, background: 'var(--bg)', flexShrink: 0, display: 'flex', alignItems: 'center', gap: 12 }}>
        <Icon name="zap" size={20} color="var(--accent)" />
        <div style={{ flex: 1 }}>
          <div className="smcap" style={{ marginBottom: 2 }}>Autonomous Engagement</div>
          <h1 className="mono" style={{ fontSize: 20, fontWeight: 500, color: 'var(--fg)', margin: 0 }}>Hermes Operator</h1>
        </div>
        {status && (
          <span className="mono" style={{ fontSize: 10, display: 'flex', alignItems: 'center', gap: 6, color: status.installed ? 'var(--ok)' : 'var(--fg-4)' }}>
            <span className={`dot ${status.installed ? 'dot-live' : 'dot-idle'}`} />
            {status.installed ? `Hermes ${status.version || 'ready'}` : 'Hermes not installed'}
          </span>
        )}
      </div>

      {notInstalled ? (
        <EmptyState
          icon="zap"
          title="Hermes Agent isn't installed on the Seraph host"
          hint="Install it on the backend, then reload: pip install hermes-agent"
          pad={72}
        />
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', flex: 1, minHeight: 0 }}>
          {/* Left config panel */}
          <div style={{ borderRight: rule, overflowY: 'auto', padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Mode */}
            <div>
              <label style={labelStyle}>Mode</label>
              <div style={{ display: 'flex', gap: 6 }}>
                {MODES.map(m => {
                  const cfg = MODE_CONFIGS[m]
                  const active = mode === m
                  return (
                    <button key={m} onClick={() => setMode(m)} disabled={running}
                      style={{
                        flex: 1, padding: '7px 4px', fontSize: 11, textTransform: 'capitalize', cursor: 'pointer',
                        background: active ? cfg.bg : 'transparent',
                        border: `1px solid ${active ? cfg.border : 'var(--rule)'}`,
                        color: active ? cfg.color : 'var(--fg-3)', fontFamily: 'var(--font-mono)',
                      }}>
                      {cfg.label}
                    </button>
                  )
                })}
              </div>
              <div style={{ fontSize: 10, color: 'var(--fg-4)', marginTop: 5 }}>{MODE_CONFIGS[mode].desc}</div>
            </div>

            <div>
              <label style={labelStyle}>Project</label>
              <select style={inputStyle} value={selectedProject} disabled={running}
                onChange={e => setSelectedProject(e.target.value)}>
                {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>

            <div>
              <label style={labelStyle}>Target</label>
              <select style={inputStyle} value={selectedTarget} disabled={running}
                onChange={e => setSelectedTarget(e.target.value)}>
                {targets.length === 0 && <option value="">No targets</option>}
                {targets.map(t => <option key={t.id} value={t.id}>{t.hostname_or_ip}</option>)}
              </select>
            </div>

            <div>
              <label style={labelStyle}>Model (Ollama)</label>
              <select style={inputStyle} value={selectedModel} disabled={running}
                onChange={e => setSelectedModel(e.target.value)}>
                {models.length === 0 && <option value="">No models — check AI settings</option>}
                {models.map(m => <option key={m} value={m}>{m}</option>)}
              </select>
              <div style={{ fontSize: 10, color: 'var(--fg-4)', marginTop: 5 }}>
                Served from the backend's Ollama{status?.ollama_url ? ` (${status.ollama_url})` : ''}.
                {status && !status.ollama_reachable && <span style={{ color: 'var(--high)' }}> · unreachable</span>}
              </div>
            </div>

            {/* Safety note */}
            <div style={{ border: rule, padding: 10, background: 'var(--bg-2)', display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--ok)' }}>
                <Icon name="shield" size={12} color="var(--ok)" />
                Smart approvals on
              </div>
              <div style={{ fontSize: 10, color: 'var(--fg-4)', lineHeight: 1.5 }}>
                Hermes runs its own tool loop, scoped to <span className="mono" style={{ color: 'var(--fg-2)' }}>{target?.hostname_or_ip ?? 'the target'}</span>.
                Risky actions are auto-gated; the hardline blocklist always holds.
              </div>
            </div>

            {running ? (
              <button onClick={stop} className="btn btn-sm"
                style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, background: 'rgba(232,92,78,0.1)', color: 'var(--crit)', border: '1px solid rgba(232,92,78,0.3)' }}>
                <Icon name="stop" size={13} /> Stop engagement
              </button>
            ) : (
              <button onClick={start} className="btn btn-primary btn-sm"
                disabled={!selectedTarget || !selectedModel}
                style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}>
                <Icon name="zap" size={13} /> Start engagement
              </button>
            )}

            <button onClick={() => navigate('/operator')} className="btn btn-sm"
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, color: 'var(--fg-3)' }}>
              <Icon name="cube" size={12} /> Supervised AI Operator
            </button>
          </div>

          {/* Transcript */}
          <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0, minHeight: 0, background: 'var(--bg-term, #08070a)' }}>
            {output ? (
              <pre ref={outRef} className="mono" style={{
                flex: 1, margin: 0, padding: 16, overflowY: 'auto', fontSize: 12, lineHeight: 1.55,
                color: 'var(--fg-2)', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
              }}>
                {output}
                {running && <span style={{ color: 'var(--accent)' }}>▋</span>}
              </pre>
            ) : (
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10, color: 'var(--fg-4)' }}>
                <Icon name="zap" size={28} color="var(--fg-4)" />
                <span className="mono" style={{ fontSize: 12 }}>
                  {running ? 'Starting Hermes…' : 'Configure the engagement and press Start.'}
                </span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
