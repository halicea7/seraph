import { useState, useEffect, useRef } from 'react'
import Icon from '@/components/Icon'
import { MODE_CONFIGS, OperatorMode, PENTEST_TOOLS, MSF_MODULES } from '@/lib/operator'
import { useAIOperator, type OperatorStep } from '@/contexts/AIOperatorContext'

const rule = '1px solid var(--rule)'

// ─── T-ID chip renderer ───────────────────────────────────────────────────────
function TechniqueText({ text }: { text: string }) {
  const parts = text.split(/\b(T\d{4}(?:\.\d{3})?)\b/)
  return (
    <>
      {parts.map((part, i) =>
        /^T\d{4}(?:\.\d{3})?$/.test(part) ? (
          <a
            key={i}
            href={`https://attack.mitre.org/techniques/${part.replace('.', '/')}/`}
            target="_blank"
            rel="noreferrer"
            onClick={e => e.stopPropagation()}
            style={{
              color: 'var(--accent)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.88em',
              background: 'rgba(240,168,58,0.08)',
              border: '1px solid rgba(240,168,58,0.3)',
              padding: '1px 5px',
              borderRadius: 2,
              textDecoration: 'none',
              whiteSpace: 'nowrap',
            }}
          >
            {part}
          </a>
        ) : (
          <span key={i}>{part}</span>
        )
      )}
    </>
  )
}

// ─── Mode icon map ─────────────────────────────────────────────────────────────
const modeIconName: Record<OperatorMode, string> = {
  attack: 'swords',
  recon:  'search',
  audit:  'shield',
}

// ─── Custom checkbox ───────────────────────────────────────────────────────────
function ToolCheckbox({
  checked,
  onChange,
  accent,
  disabled,
}: {
  checked: boolean
  onChange: () => void
  accent: string
  disabled: boolean
}) {
  return (
    <button
      onClick={disabled ? undefined : onChange}
      disabled={disabled}
      style={{
        width: 13, height: 13, flexShrink: 0,
        border: `1px solid ${checked ? accent : 'var(--rule-strong)'}`,
        background: checked ? accent : 'transparent',
        cursor: disabled ? 'not-allowed' : 'pointer',
        padding: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
        opacity: disabled ? 0.4 : 1,
      }}
    >
      {checked && <Icon name="check" size={9} color="#0a0807" />}
    </button>
  )
}

// ─── OpField ───────────────────────────────────────────────────────────────────
function OpField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ padding: '12px 16px 0' }}>
      <label className="mono" style={{ fontSize: 9.5, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--fg-3)' }}>
        {label}
      </label>
      <div style={{ marginTop: 5 }}>{children}</div>
    </div>
  )
}

// ─── Idle hero ─────────────────────────────────────────────────────────────────
function OperatorIdleHero({ mode }: { mode: typeof MODE_CONFIGS[OperatorMode] }) {
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 32 }}>
      <div style={{ maxWidth: 460, textAlign: 'center' }}>
        <div style={{
          width: 64, height: 64, margin: '0 auto 18px',
          border: `1px solid ${mode.border}`, background: mode.bg,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Icon name="cube" size={28} color={mode.color} />
        </div>
        <h2 style={{ margin: 0, fontFamily: 'var(--font-mono)', fontWeight: 500, fontSize: 22, color: mode.color, letterSpacing: '-0.01em' }}>
          {mode.label} Mode
        </h2>
        <p style={{ marginTop: 10, color: 'var(--fg-2)', fontSize: 13, lineHeight: 1.6 }}>
          {mode.desc}. Pick a project, target, and model. Enable tools, optionally edit the system prompt, then start a supervised session.
        </p>
        <div style={{ marginTop: 24, display: 'flex', flexDirection: 'column', gap: 8, textAlign: 'left' }}>
          {[
            'You approve every command before it runs',
            'Findings auto-populate the attack path graph',
            'Sessions resume if you navigate away',
          ].map(text => (
            <div key={text} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Icon name="check" size={11} color="var(--ok)" />
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--fg-2)' }}>{text}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Thinking card ─────────────────────────────────────────────────────────────
function OperatorThinking({
  mode,
  showStream,
  llmStream,
  llmThinking,
  thinkingEnabled,
}: {
  mode: typeof MODE_CONFIGS[OperatorMode]
  showStream: boolean
  llmStream: string
  llmThinking: string
  thinkingEnabled: boolean
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px',
        border: rule, background: 'var(--bg)',
      }}>
        <span className="dot dot-warn" />
        <span className="mono" style={{ fontSize: 12, color: 'var(--fg-2)' }}>
          Analyzing and planning next action<span className="cursor" />
        </span>
      </div>
      {thinkingEnabled && llmThinking && (
        <div style={{ border: '1px solid rgba(167,139,250,0.25)', background: 'rgba(167,139,250,0.04)' }}>
          <div style={{ padding: '4px 10px', borderBottom: '1px solid rgba(167,139,250,0.15)', display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#a78bfa', flexShrink: 0 }} />
            <span className="mono" style={{ fontSize: 9, letterSpacing: '0.12em', textTransform: 'uppercase', color: '#a78bfa' }}>Thinking</span>
          </div>
          <pre style={{ margin: 0, padding: '8px 10px', fontSize: 10.5, color: 'rgba(167,139,250,0.7)', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 160, overflowY: 'auto', lineHeight: 1.5 }}>
            {llmThinking}
          </pre>
        </div>
      )}
      {showStream && (
        <div className="on-term" style={{ border: `1px solid ${mode.border}`, background: 'var(--bg-term)' }}>
          <div style={{
            padding: '7px 12px', borderBottom: rule,
            color: mode.color, fontFamily: 'var(--font-mono)', fontSize: 9.5,
            letterSpacing: '0.16em', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: 6,
          }}>
            <span className="dot" style={{ background: mode.color }} /> Model output · live
          </div>
          <pre style={{ margin: 0, padding: '12px 14px', color: 'var(--fg-2)', fontFamily: 'var(--font-mono)', fontSize: 11, lineHeight: 1.55, whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 280, overflowY: 'auto' }}>
            {llmStream
              ? <>{llmStream}<span className="cursor" /></>
              : <span style={{ color: 'var(--fg-3)', fontStyle: 'italic' }}>waiting for first token…</span>
            }
          </pre>
        </div>
      )}
    </div>
  )
}

// ─── Mode confirm dialog ───────────────────────────────────────────────────────
function ModeConfirmDialog({
  pendingMode,
  onReset,
  onKeep,
  onCancel,
}: {
  pendingMode: OperatorMode
  onReset: () => void
  onKeep: () => void
  onCancel: () => void
}) {
  const mode = MODE_CONFIGS[pendingMode]
  return (
    <div
      onClick={onCancel}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.72)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100,
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{ width: 360, background: 'var(--bg-2)', border: `1px solid ${mode.border}`, padding: 22 }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <Icon name={modeIconName[pendingMode]} size={13} color={mode.color} />
          <span className="mono" style={{ fontSize: 12, color: mode.color, letterSpacing: '0.14em', textTransform: 'uppercase', fontWeight: 600 }}>
            Switch to {mode.label} Mode
          </span>
        </div>
        <div style={{ fontSize: 12, color: 'var(--fg-3)', marginBottom: 16, lineHeight: 1.55 }}>{mode.desc}</div>
        <div style={{ fontSize: 12.5, color: 'var(--fg)', marginBottom: 18 }}>
          Reset tool selection to <strong style={{ color: mode.color }}>{mode.label}</strong> defaults?
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <button
            onClick={onReset}
            className="btn btn-lg"
            style={{ background: mode.color, color: '#0a0807', border: `1px solid ${mode.color}`, width: '100%', justifyContent: 'center' }}
          >
            Reset tools to {mode.label} defaults
          </button>
          <button onClick={onKeep} className="btn" style={{ width: '100%', justifyContent: 'center' }}>
            Switch mode, keep current tools
          </button>
          <button onClick={onCancel} className="btn btn-ghost" style={{ width: '100%', justifyContent: 'center' }}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Step card ─────────────────────────────────────────────────────────────────
interface StepCardProps {
  step: OperatorStep
  index: number
  mode: OperatorMode
  isActive: boolean
  isRunning: boolean
  liveOutput: string
  runStartTime: number | null
  onApprove: () => void
  onSkip: () => void
  onStop: () => void
  onToggleOutput: () => void
}

function StepCard({
  step, index, mode, isActive, isRunning,
  liveOutput, runStartTime,
  onApprove, onSkip, onStop,
}: StepCardProps) {
  const modeConfig = MODE_CONFIGS[mode]
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    if (!isRunning || !runStartTime) { setElapsed(0); return }
    setElapsed(Math.floor((Date.now() - runStartTime) / 1000))
    const t = setInterval(() => setElapsed(Math.floor((Date.now() - runStartTime) / 1000)), 1000)
    return () => clearInterval(t)
  }, [isRunning, runStartTime])

  const fmtElapsed = (s: number) => s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`

  const stateColor = step.result === 'approved' ? 'var(--ok)'
    : step.result === 'skipped' ? 'var(--fg-3)'
    : step.result === 'error'   ? 'var(--crit)'
    : isActive                  ? modeConfig.color
    : 'var(--accent)'

  const stateLabel = step.result === 'approved' ? 'Executed'
    : step.result === 'skipped' ? 'Skipped'
    : step.result === 'error'   ? 'Error'
    : isRunning                 ? 'Running…'
    : 'Awaiting approval'

  const borderColor = step.result === 'approved' ? 'rgba(107,138,114,0.35)'
    : step.result === 'skipped' ? 'var(--rule-strong)'
    : step.result === 'error'   ? 'rgba(232,92,78,0.35)'
    : isActive                  ? modeConfig.border
    : 'var(--rule)'

  const isMsf = step.action && (step.action.tool.includes('/') || step.action.command.startsWith('msfconsole'))

  return (
    <div style={{ border: `1px solid ${borderColor}`, background: 'var(--bg)' }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '8px 14px', borderBottom: rule,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className="mono" style={{ fontSize: 9.5, color: 'var(--fg-4)', letterSpacing: '0.14em' }}>
            STEP {String(index).padStart(2, '0')}
          </span>
          {step.result === 'approved' && !isRunning && <Icon name="check" size={11} color="var(--ok)" />}
          {isActive && <span className="dot dot-warn" />}
          {isRunning && <span className="dot dot-live" />}
        </div>
        <span className="mono" style={{ fontSize: 9.5, color: stateColor, letterSpacing: '0.12em', textTransform: 'uppercase' }}>
          {stateLabel}
        </span>
      </div>

      <div style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 12 }}>
        {step.analysis && (
          <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.55, color: 'var(--fg)' }}>
            <TechniqueText text={step.analysis} />
          </p>
        )}

        {step.attackPathNote && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '7px 10px', borderLeft: `2px solid ${modeConfig.color}`, background: modeConfig.bg,
          }}>
            <Icon name="activity" size={11} color={modeConfig.color} />
            <span className="mono" style={{ fontSize: 11, color: modeConfig.color }}>{step.attackPathNote}</span>
          </div>
        )}

        {step.action && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
              <span className="badge" style={{
                color: isMsf ? 'var(--crit)' : 'var(--accent)',
                borderColor: isMsf ? 'rgba(232,92,78,0.4)' : 'var(--accent)',
                background: isMsf ? 'rgba(232,92,78,0.08)' : 'var(--accent-2)',
              }}>
                {isMsf ? 'MSF' : 'TOOL'} · {step.action.tool}
              </span>
              {isRunning && (
                <span className="mono" style={{ fontSize: 9.5, color: 'var(--fg-3)', marginLeft: 'auto' }}>
                  elapsed {fmtElapsed(elapsed)}
                </span>
              )}
            </div>
            <pre className="on-term" style={{
              margin: 0, background: 'var(--bg-term)', color: 'var(--fg)',
              padding: '9px 12px', fontFamily: 'var(--font-mono)', fontSize: 11.5,
              border: rule, whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.55,
            }}>
              <span style={{ color: 'var(--fg-4)' }}>$ </span>{step.action.command}
            </pre>
            {step.action.rationale && (
              <div className="mono" style={{ fontSize: 11, color: 'var(--fg-3)', marginTop: 6, fontStyle: 'italic' }}>
                // {step.action.rationale}
              </div>
            )}
          </div>
        )}

        {isRunning && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            <div className="mono" style={{ fontSize: 9.5, color: 'var(--fg-3)', letterSpacing: '0.14em', textTransform: 'uppercase' }}>
              Live output
            </div>
            <pre className="on-term" style={{
              margin: 0, background: 'var(--bg-term)', color: '#8ad26b',
              padding: '10px 12px', fontFamily: 'var(--font-mono)', fontSize: 11,
              border: '1px solid rgba(107,138,114,0.2)', lineHeight: 1.55,
              maxHeight: 256, overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
            }}>
              {liveOutput
                ? liveOutput.slice(-6000)
                : <span style={{ color: 'var(--fg-3)', fontStyle: 'italic' }}>Waiting for process output…</span>
              }
            </pre>
          </div>
        )}

        {step.result === 'approved' && !isRunning && step.output && (
          <details>
            <summary className="mono" style={{ fontSize: 9.5, color: 'var(--fg-3)', cursor: 'pointer', letterSpacing: '0.14em', textTransform: 'uppercase' }}>
              Output · {step.output.length.toLocaleString()} bytes
            </summary>
            <pre className="on-term" style={{
              marginTop: 8, background: 'var(--bg-term)', color: '#8ad26b',
              padding: '10px 12px', fontFamily: 'var(--font-mono)', fontSize: 11,
              border: rule, lineHeight: 1.55, maxHeight: 260, overflow: 'auto', whiteSpace: 'pre-wrap',
            }}>
              {step.output.slice(0, 12000)}
            </pre>
          </details>
        )}

        {isActive && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingTop: 2 }}>
            <button
              onClick={onApprove}
              className="btn"
              style={{ background: modeConfig.color, color: '#0a0807', border: `1px solid ${modeConfig.color}` }}
            >
              <Icon name="check" size={10} color="#0a0807" /> Approve
            </button>
            <button onClick={onSkip} className="btn">
              <Icon name="arrow_r" size={10} /> Skip
            </button>
            <button onClick={onStop} className="btn btn-danger" style={{ marginLeft: 'auto' }}>
              <Icon name="stop" size={10} color="var(--crit)" /> Stop
            </button>
          </div>
        )}

        {/* completed step output toggle (legacy toggle-based, for non-details fallback) */}
        {step.result === 'approved' && !isRunning && step.output && step.outputOpen !== undefined && (
          /* output is rendered via <details> above — outputOpen kept for context compatibility */
          null
        )}
      </div>
    </div>
  )
}

// ─── Main page ─────────────────────────────────────────────────────────────────
export default function AIOperator() {
  const op = useAIOperator()
  const modeConfig = MODE_CONFIGS[op.mode]
  const sessionActive = op.phase !== 'idle'
  const target = op.targets.find(t => t.id === op.selectedTarget)

  const [pendingMode, setPendingMode] = useState<OperatorMode | null>(null)
  const [promptOpen, setPromptOpen] = useState(false)

  const bottomRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [op.steps, op.phase, op.liveOutput])

  function handleModeClick(newMode: OperatorMode) {
    if (newMode === op.mode || sessionActive) return
    setPendingMode(newMode)
  }

  function confirmModeSwitch(resetTools: boolean) {
    if (!pendingMode) return
    op.applyModeSwitch(pendingMode, resetTools)
    setPendingMode(null)
  }

  const toolCategories = [...new Set(PENTEST_TOOLS.map(t => t.category))]
  const msfCategories  = [...new Set(MSF_MODULES.map(m => m.category))]

  return (
    <div className="page-enter" style={{ display: 'flex', flex: 1, minHeight: 0 }}>

      {/* ─── Left config rail ────────────────────────────────────────────── */}
      <div style={{
        width: 304, flexShrink: 0, borderRight: rule,
        display: 'flex', flexDirection: 'column', background: 'var(--bg)',
        overflow: 'hidden',
      }}>
        {/* Header */}
        <div style={{ padding: '14px 16px', borderBottom: rule }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="cube" size={14} color={modeConfig.color} />
            <span className="mono" style={{ fontSize: 12, fontWeight: 500, letterSpacing: '0.14em', textTransform: 'uppercase' }}>
              AI Operator
            </span>
          </div>
          <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)', marginTop: 4 }}>
            Supervised LLM-driven session
          </div>
        </div>

        {/* Mode selector */}
        <div style={{ padding: '14px 16px', borderBottom: rule }}>
          <div className="smcap smcap-2" style={{ marginBottom: 8 }}>Mode</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 6 }}>
            {(Object.values(MODE_CONFIGS) as typeof MODE_CONFIGS[OperatorMode][]).map(cfg => {
              const active = cfg.id === op.mode
              return (
                <button
                  key={cfg.id}
                  onClick={() => handleModeClick(cfg.id)}
                  disabled={sessionActive}
                  title={cfg.desc}
                  style={{
                    padding: '8px 4px 7px',
                    background: active ? cfg.bg : 'transparent',
                    border: `1px solid ${active ? cfg.border : 'var(--rule)'}`,
                    color: active ? cfg.color : 'var(--fg-3)',
                    fontFamily: 'var(--font-mono)', fontSize: 10,
                    textTransform: 'uppercase', letterSpacing: '0.12em', fontWeight: 500,
                    cursor: sessionActive ? 'not-allowed' : 'pointer',
                    opacity: sessionActive && !active ? 0.4 : 1,
                    display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 5,
                  }}
                >
                  <Icon name={modeIconName[cfg.id]} size={12} color={active ? cfg.color : 'var(--fg-3)'} />
                  <div>{cfg.label}</div>
                </button>
              )
            })}
          </div>
          <div className="mono" style={{ fontSize: 10, color: modeConfig.color, opacity: 0.7, marginTop: 8, lineHeight: 1.5 }}>
            {modeConfig.desc}
          </div>
        </div>

        {/* Body scroll */}
        <div style={{ flex: 1, minHeight: 0, overflowY: 'auto' }}>

          <OpField label="Project">
            <select
              disabled={sessionActive}
              value={op.selectedProject}
              onChange={e => op.setSelectedProject(e.target.value)}
              style={{ width: '100%' }}
            >
              {op.projects.map(p => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </OpField>

          <OpField label="Target">
            <select
              disabled={sessionActive}
              value={op.selectedTarget}
              onChange={e => op.setSelectedTarget(e.target.value)}
              style={{ width: '100%' }}
            >
              {op.targets.map(t => (
                <option key={t.id} value={t.id}>{t.hostname_or_ip}</option>
              ))}
            </select>
          </OpField>

          <OpField label="Model">
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
              <select
                disabled={sessionActive}
                value={op.selectedModelKey}
                onChange={e => op.setSelectedModelKey(e.target.value)}
                style={{ width: '100%' }}
              >
                {op.modelOptions.length > 0
                  ? op.modelOptions.map(o => (
                    <option key={o.key} value={o.key}>{o.label}</option>
                  ))
                  : (
                    <option value="">No tool-capable models found</option>
                  )
                }
              </select>
              <button
                onClick={op.loadModelOptions}
                disabled={op.loadingModels}
                title="Refresh models"
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0, display: 'flex', flexShrink: 0 }}
              >
                <Icon name="refresh" size={11} color={op.loadingModels ? 'var(--accent)' : 'currentColor'} />
              </button>
            </div>
            {op.modelOptions.length === 0 ? (
              <p style={{ fontSize: 10, color: 'var(--high)', margin: 0, lineHeight: 1.5 }}>
                Pull a tool-capable model (e.g. <code style={{ fontFamily: 'var(--font-mono)' }}>ollama pull qwen3</code>).
              </p>
            ) : (
              <p style={{ fontSize: 10, color: 'var(--fg-4)', margin: 0, lineHeight: 1.5 }}>
                Multi-step pentest reasoning needs a strong tool-capable model — small models stall or
                loop. Prefer ≥ ~14B (e.g. qwen2.5/llama3.1) if a run underperforms.
              </p>
            )}
          </OpField>

          {/* Pentest tools */}
          <div style={{ padding: '12px 16px 0' }}>
            <div className="smcap smcap-2" style={{ marginBottom: 6 }}>
              Pentest Tools · {op.enabledTools.size}
            </div>
            {toolCategories.map(cat => (
              <div key={cat} style={{ marginBottom: 8 }}>
                <div className="mono" style={{ fontSize: 9.5, color: 'var(--fg-4)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 3 }}>
                  {cat}
                </div>
                {PENTEST_TOOLS.filter(t => t.category === cat).map(tool => {
                  const on = op.enabledTools.has(tool.id)
                  return (
                    <label key={tool.id} title={tool.desc} style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '3px 0', cursor: 'pointer' }}>
                      <ToolCheckbox
                        checked={on}
                        onChange={() => op.toggleTool(tool.id)}
                        accent={modeConfig.color}
                        disabled={sessionActive}
                      />
                      <span className="mono" style={{ fontSize: 11, color: on ? 'var(--fg)' : 'var(--fg-4)' }}>
                        {tool.label}
                      </span>
                    </label>
                  )
                })}
              </div>
            ))}
          </div>

          <div style={{ borderTop: rule, margin: '8px 0' }} />

          {/* MSF modules */}
          <div style={{ padding: '0 16px 12px' }}>
            <div className="smcap smcap-2" style={{ marginBottom: 6 }}>
              Metasploit Modules · {op.enabledMsf.size}
            </div>
            {msfCategories.map(cat => (
              <div key={cat} style={{ marginBottom: 8 }}>
                <div className="mono" style={{ fontSize: 9.5, color: 'var(--fg-4)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 3 }}>
                  {cat}
                </div>
                {MSF_MODULES.filter(m => m.category === cat).map(mod => {
                  const on = op.enabledMsf.has(mod.id)
                  return (
                    <label key={mod.id} title={mod.desc} style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '3px 0', cursor: 'pointer' }}>
                      <ToolCheckbox
                        checked={on}
                        onChange={() => op.toggleMsf(mod.id)}
                        accent="var(--crit)"
                        disabled={sessionActive}
                      />
                      <span className="mono" style={{ fontSize: 11, color: on ? 'var(--fg)' : 'var(--fg-4)' }}>
                        {mod.label}
                      </span>
                    </label>
                  )
                })}
              </div>
            ))}
          </div>

          <div style={{ borderTop: rule }} />

          {/* System prompt collapsible */}
          <div style={{ padding: '12px 16px' }}>
            <button
              onClick={() => setPromptOpen(o => !o)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6, width: '100%',
                background: 'transparent', border: 'none', cursor: 'pointer', padding: 0, color: 'var(--fg-3)',
              }}
            >
              <Icon name={promptOpen ? 'chev_d' : 'chev_r'} size={10} color="var(--fg-3)" />
              <span className="mono" style={{ fontSize: 10, letterSpacing: '0.14em', textTransform: 'uppercase' }}>
                System Prompt
              </span>
              {!op.promptIsAuto && (
                <span className="badge badge-high" style={{ marginLeft: 'auto' }}>custom</span>
              )}
            </button>
            {promptOpen && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span className="mono" style={{ fontSize: 10, color: 'var(--fg-4)' }}>
                    {op.promptIsAuto ? 'Auto-generated · edits lock prompt' : 'Custom · used as-is'}
                  </span>
                  {!op.promptIsAuto && (
                    <button
                      onClick={op.regeneratePrompt}
                      title="Reset to auto-generated prompt"
                      style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, color: 'var(--fg-3)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
                    >
                      <Icon name="refresh" size={10} /> Reset
                    </button>
                  )}
                </div>
                <textarea
                  value={op.promptDraft}
                  onChange={e => { op.setPromptDraft(e.target.value); op.setPromptIsAuto(false) }}
                  disabled={sessionActive}
                  rows={10}
                  style={{ width: '100%', fontSize: 10.5, lineHeight: 1.45, height: 180, boxSizing: 'border-box', opacity: sessionActive ? 0.5 : 1 }}
                />
              </div>
            )}
          </div>
        </div>

        {/* Footer — LHOST + stream toggle + Start/Stop */}
        <div style={{ padding: 14, borderTop: rule, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div>
            <label className="mono" style={{ fontSize: 9.5, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--fg-3)', display: 'flex', alignItems: 'center', gap: 4 }}>
              <Icon name="network" size={10} color="var(--fg-3)" /> LHOST · your IP
            </label>
            <input
              value={op.lhostIp}
              onChange={e => op.setLhostIp(e.target.value)}
              style={{ width: '100%', marginTop: 4, fontSize: 11, boxSizing: 'border-box' }}
              placeholder="e.g. 192.168.1.10"
            />
          </div>

          {/* Three option toggles */}
          {(
            [
              { label: 'Use tools',     active: op.useToolCalling,   set: () => op.setUseToolCalling(!op.useToolCalling) },
              { label: 'Thinking',      active: op.thinkingEnabled,  set: () => op.setThinkingEnabled(!op.thinkingEnabled) },
              { label: 'Live stream',   active: op.showStream,       set: () => op.setShowStream(s => !s) },
            ] as const
          ).map(({ label, active, set }) => (
            <button
              key={label}
              onClick={set}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '7px 10px', border: `1px solid ${active ? modeConfig.border : 'var(--rule)'}`,
                background: active ? modeConfig.bg : 'transparent',
                color: active ? modeConfig.color : 'var(--fg-3)',
                fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: '0.1em', textTransform: 'uppercase', cursor: 'pointer',
              }}
            >
              <span>{label}</span>
              <span style={{ fontSize: 9, fontWeight: 600 }}>{active ? 'ON' : 'OFF'}</span>
            </button>
          ))}

          {/* Auto-run budget — auto-approve the next N steps without prompting */}
          <div style={{
            border: `1px solid ${op.autoBudget > 0 ? modeConfig.border : 'var(--rule)'}`,
            background: op.autoBudget > 0 ? modeConfig.bg : 'transparent',
            padding: '6px 10px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8,
          }}>
            <span className="mono" style={{ fontSize: 10, letterSpacing: '0.1em', textTransform: 'uppercase', color: op.autoBudget > 0 ? modeConfig.color : 'var(--fg-3)' }}>
              Auto-run{op.autoBudget > 0 ? ` · ${op.autoBudget} left` : ''}
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <button onClick={() => op.setAutoBudget(Math.max(0, op.autoBudget - 1))}
                style={{ background: 'none', border: '1px solid var(--rule)', color: 'var(--fg-2)', cursor: 'pointer', width: 20, height: 20, lineHeight: '1', fontSize: 13 }}>−</button>
              <span className="mono tnum" style={{ minWidth: 14, textAlign: 'center', fontSize: 12, color: 'var(--fg)' }}>{op.autoBudget}</span>
              <button onClick={() => op.setAutoBudget(op.autoBudget + 1)}
                style={{ background: 'none', border: '1px solid var(--rule)', color: 'var(--fg-2)', cursor: 'pointer', width: 20, height: 20, lineHeight: '1', fontSize: 13 }}>+</button>
            </div>
          </div>

          {op.phase === 'idle' ? (
            <button
              onClick={op.startSession}
              disabled={!op.selectedProject || !op.selectedTarget || !op.selectedModelKey}
              className="btn btn-lg"
              style={{
                background: modeConfig.color, color: '#0a0807', border: `1px solid ${modeConfig.color}`,
                width: '100%', justifyContent: 'center',
                opacity: (!op.selectedProject || !op.selectedTarget || !op.selectedModelKey) ? 0.4 : 1,
              }}
            >
              <Icon name="play" size={11} color="#0a0807" /> Start {modeConfig.label} Session
            </button>
          ) : op.phase === 'done' ? (
            <button
              onClick={op.resetSession}
              className="btn btn-lg"
              style={{ width: '100%', justifyContent: 'center' }}
            >
              <Icon name="refresh" size={11} /> New Session
            </button>
          ) : (
            <button
              onClick={op.handleStop}
              className="btn btn-lg btn-danger"
              style={{ width: '100%', justifyContent: 'center' }}
            >
              <Icon name="stop" size={11} color="var(--crit)" /> Stop Session
            </button>
          )}
        </div>
      </div>

      {/* ─── Right session pane ──────────────────────────────────────────── */}
      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {op.phase === 'idle' ? (
          <OperatorIdleHero mode={modeConfig} />
        ) : (
          <>
            {/* Context banner */}
            <div style={{
              padding: '12px 22px', borderBottom: rule,
              display: 'flex', alignItems: 'center', gap: 16, fontSize: 11,
              background: 'var(--bg-2)',
            }}>
              <span style={{
                display: 'inline-flex', alignItems: 'center', gap: 5,
                padding: '3px 8px', background: modeConfig.bg, border: `1px solid ${modeConfig.border}`,
                color: modeConfig.color, fontFamily: 'var(--font-mono)', fontSize: 9,
                letterSpacing: '0.14em', textTransform: 'uppercase', fontWeight: 600,
              }}>
                <Icon name={modeIconName[op.mode]} size={9} color={modeConfig.color} /> {modeConfig.label}
              </span>
              <span style={{ color: 'var(--fg-4)' }}>·</span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <Icon name="target" size={10} color="var(--accent)" />
                <span className="mono" style={{ color: 'var(--fg)' }}>{target?.hostname_or_ip ?? '—'}</span>
              </span>
              <span style={{ color: 'var(--fg-4)' }}>·</span>
              <span className="mono" style={{ color: 'var(--fg-3)' }}>
                {op.modelOptions.find(o => o.key === op.selectedModelKey)?.label ?? op.selectedModelKey}
              </span>
              <span style={{ color: 'var(--fg-4)' }}>·</span>
              <span className="mono" style={{ color: 'var(--fg-3)' }}>
                {op.enabledTools.size + op.enabledMsf.size} tools
              </span>
              {!op.promptIsAuto && (
                <>
                  <span style={{ color: 'var(--fg-4)' }}>·</span>
                  <span className="mono" style={{ color: 'var(--high)' }}>custom prompt</span>
                </>
              )}
              <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8, color: 'var(--fg-3)' }}>
                <span className="dot dot-live" />
                <span className="mono">{op.phase}</span>
              </span>
            </div>

            {/* Step list */}
            <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', padding: '22px 22px 40px', display: 'flex', flexDirection: 'column', gap: 14 }}>
              {op.steps.map((step, idx) => (
                <StepCard
                  key={step.id}
                  step={step}
                  index={idx + 1}
                  mode={op.mode}
                  isActive={step.result === 'pending' && op.phase === 'awaiting'}
                  isRunning={step.result === 'approved' && op.phase === 'running'}
                  liveOutput={step.result === 'approved' && op.phase === 'running' ? op.liveOutput : ''}
                  runStartTime={step.result === 'approved' && op.phase === 'running' ? op.runStartTime : null}
                  onApprove={() => op.handleApprove(step)}
                  onSkip={() => op.handleSkip(step)}
                  onStop={op.handleStop}
                  onToggleOutput={() => op.toggleStepOutput(step.id)}
                />
              ))}

              {op.phase === 'thinking' && (
                <OperatorThinking mode={modeConfig} showStream={op.showStream} llmStream={op.llmStream} llmThinking={op.llmThinking} thinkingEnabled={op.thinkingEnabled} />
              )}

              {op.errorMsg && (
                <div style={{
                  display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 14px',
                  border: '1px solid rgba(232,92,78,0.3)', background: 'rgba(232,92,78,0.06)',
                }}>
                  <Icon name="x" size={14} color="var(--crit)" />
                  <span className="mono" style={{ fontSize: 12, color: 'var(--crit)' }}>{op.errorMsg}</span>
                </div>
              )}

              {op.phase === 'done' && !op.errorMsg && (
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '14px 18px', border: '1px solid rgba(107,138,114,0.4)', background: 'rgba(107,138,114,0.06)',
                }}>
                  <Icon name="check" size={13} color="var(--ok)" />
                  <span className="mono" style={{ fontSize: 12, color: 'var(--ok)' }}>
                    Session complete · {op.steps.filter(s => s.result === 'approved').length} steps executed · check Attack Paths for the updated graph.
                  </span>
                </div>
              )}

              <div ref={bottomRef} />
            </div>
          </>
        )}
      </div>

      {/* Mode-switch confirmation dialog */}
      {pendingMode && (
        <ModeConfirmDialog
          pendingMode={pendingMode}
          onReset={() => confirmModeSwitch(true)}
          onKeep={() => confirmModeSwitch(false)}
          onCancel={() => setPendingMode(null)}
        />
      )}
    </div>
  )
}
