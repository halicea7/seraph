import { useState, useMemo, useEffect, useRef } from 'react'
import { Loader, Sparkles, Save, ChevronDown, ChevronUp, X } from 'lucide-react'
import Icon from '@/components/Icon'
import { getApiBase } from '@/lib/config'
import { useToast } from '@/contexts/ToastContext'
import {
  TEMPLATES,
  ALL_CATEGORIES,
  ALL_PHASES,
  CATEGORY_COLORS,
  PHASE_COLORS,
  PHASE_LABELS,
  type CommandTemplate,
  type Category,
  type Phase,
} from '@/lib/templates'

// User-defined templates persist locally (the built-in TEMPLATES are read-only).
const CUSTOM_TEMPLATES_KEY = 'seraph:commandlib:custom'
function loadCustomTemplates(): CommandTemplate[] {
  try {
    const raw = JSON.parse(localStorage.getItem(CUSTOM_TEMPLATES_KEY) ?? '[]')
    return Array.isArray(raw) ? raw : []
  } catch { return [] }
}
function parseVars(command: string): string[] {
  const found = command.match(/\{\{\s*([^}]+?)\s*\}\}/g) ?? []
  return Array.from(new Set(found.map(v => v.replace(/\{\{\s*|\s*\}\}/g, ''))))
}

// ── Static data shaped for the filter UI ─────────────────────────────────────

const CATS = ALL_CATEGORIES.map(id => ({ id, color: CATEGORY_COLORS[id] }))

const PHASES = ALL_PHASES.map(id => ({
  id,
  label: PHASE_LABELS[id],
  color: PHASE_COLORS[id].text,
}))

// ── Helpers ───────────────────────────────────────────────────────────────────

function highlightVars(command: string): React.ReactNode[] {
  const parts = command.split(/(\{\{\s*[^}]+\s*\}\})/g)
  return parts.map((part, i) =>
    /^\{\{.+\}\}$/.test(part)
      ? <span key={i} style={{ color: 'var(--accent)', fontWeight: 500 }}>{part}</span>
      : <span key={i}>{part}</span>
  )
}

// ── Sub-components ────────────────────────────────────────────────────────────

function PageHeader({
  breadcrumb, title, sub, right,
}: {
  breadcrumb: string
  title: string
  sub: string
  right?: React.ReactNode
}) {
  return (
    <div style={{
      padding: '18px var(--pad)',
      borderBottom: '1px solid var(--rule)',
      display: 'flex',
      alignItems: 'flex-end',
      justifyContent: 'space-between',
      gap: 16,
      flexShrink: 0,
    }}>
      <div>
        <div className="smcap" style={{ marginBottom: 4 }}>{breadcrumb}</div>
        <h1 className="mono" style={{ margin: 0, fontWeight: 500, fontSize: 22, letterSpacing: '-0.01em' }}>{title}</h1>
        <div style={{ color: 'var(--fg-3)', fontSize: 12, marginTop: 6 }}>{sub}</div>
      </div>
      {right && (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>{right}</div>
      )}
    </div>
  )
}

function FilterPill({
  label, color, active, onClick,
}: {
  label: string
  color: string
  active: boolean
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      style={{
        padding: '4px 10px',
        border: `1px solid ${active ? color : 'var(--rule-strong)'}`,
        background: active ? `${color}1a` : 'transparent',
        color: active ? color : 'var(--fg-3)',
        fontFamily: 'var(--font-mono)',
        fontSize: 10.5,
        letterSpacing: '0.1em',
        textTransform: 'uppercase',
        fontWeight: 500,
        cursor: 'pointer',
        borderRadius: 0,
      }}
    >
      {label}
    </button>
  )
}

function TemplateCard({
  tpl, copied, onCopy,
}: {
  tpl: CommandTemplate
  copied: boolean
  onCopy: () => void
}) {
  const [expanded, setExpanded] = useState(false)
  const cat = CATS.find(c => c.id === tpl.category)
  const ph = PHASES.find(p => p.id === tpl.phase)

  return (
    <div style={{
      border: '1px solid var(--rule)',
      background: 'var(--bg)',
      display: 'flex',
      flexDirection: 'column',
    }}>
      {/* Header */}
      <div style={{ padding: '12px 14px 8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
          <span
            className="badge"
            style={{
              color: cat?.color ?? 'var(--fg-2)',
              borderColor: cat?.color ?? 'var(--rule-strong)',
              background: `${cat?.color ?? '#888'}14`,
            }}
          >
            {tpl.category}
          </span>
          <span
            className="badge"
            style={{
              color: ph?.color ?? 'var(--fg-3)',
              borderColor: ph?.color ?? 'var(--rule-strong)',
            }}
          >
            {ph?.label ?? tpl.phase}
          </span>
          <span className="badge mono" style={{ fontFamily: 'var(--font-mono)' }}>{tpl.tool}</span>
        </div>
        <h3 style={{
          margin: 0,
          fontFamily: 'var(--font-sans)',
          fontSize: 14,
          fontWeight: 500,
          color: 'var(--fg)',
        }}>
          {tpl.label}
        </h3>
      </div>

      {/* When-to-use */}
      <div style={{
        margin: '0 14px 12px',
        padding: '8px 11px',
        borderLeft: `2px solid ${cat?.color ?? 'var(--accent)'}`,
        background: 'var(--bg-2)',
      }}>
        <div className="smcap smcap-2" style={{ marginBottom: 4 }}>When to use</div>
        <div style={{ fontSize: 12, color: 'var(--fg-2)', lineHeight: 1.5 }}>{tpl.when_to_use}</div>
      </div>

      {/* Command block */}
      <div className="on-term" style={{
        margin: '0 14px 12px',
        border: '1px solid var(--rule)',
        background: 'var(--bg-term)',
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '6px 10px',
          borderBottom: '1px solid var(--rule)',
        }}>
          <span className="mono" style={{
            fontSize: 9,
            color: 'var(--fg-4)',
            letterSpacing: '0.18em',
            textTransform: 'uppercase',
          }}>
            command
          </span>
          <button
            onClick={onCopy}
            className="btn btn-sm btn-ghost"
            style={{ color: copied ? 'var(--ok)' : 'var(--fg-3)' }}
          >
            <Icon name={copied ? 'check' : 'file'} size={9} color={copied ? 'var(--ok)' : 'currentColor'} />
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
        <pre style={{
          margin: 0,
          padding: '10px 12px',
          fontFamily: 'var(--font-mono)',
          fontSize: 11.5,
          color: 'var(--fg)',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-all',
          lineHeight: 1.6,
        }}>
          {highlightVars(tpl.command)}
        </pre>
      </div>

      {/* ATT&CK technique chips */}
      {tpl.mitre_techniques && tpl.mitre_techniques.length > 0 && (
        <div style={{ padding: '0 14px 10px', display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center' }}>
          <span style={{ fontSize: 9, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', marginRight: 2 }}>ATT&CK</span>
          {tpl.mitre_techniques.map(tid => (
            <a
              key={tid}
              href={`https://attack.mitre.org/techniques/${tid.replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="mono"
              style={{
                fontSize: 9, padding: '2px 6px',
                background: 'rgba(240,168,58,0.07)', border: '1px solid rgba(240,168,58,0.25)',
                color: 'var(--accent)', textDecoration: 'none',
              }}
              onMouseEnter={e => (e.currentTarget.style.background = 'rgba(240,168,58,0.15)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'rgba(240,168,58,0.07)')}
            >
              {tid}
            </a>
          ))}
        </div>
      )}

      {/* Details toggle */}
      <div style={{ padding: '0 14px 14px' }}>
        <button
          onClick={() => setExpanded(e => !e)}
          className="btn btn-ghost btn-sm"
          style={{ padding: '2px 0', height: 18 }}
        >
          <Icon name={expanded ? 'chev_d' : 'chev_r'} size={9} />
          {expanded ? 'Less' : 'Details'}
        </button>
        {expanded && (
          <>
            <div style={{ marginTop: 8, fontSize: 11.5, color: 'var(--fg-2)', lineHeight: 1.55 }}>
              {tpl.description}
            </div>
            {tpl.vars.length > 0 && (
              <div style={{ marginTop: 10, display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                {tpl.vars.map(v => (
                  <span
                    key={v}
                    className="badge mono"
                    style={{
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--accent)',
                      borderColor: 'var(--accent)',
                      background: 'rgba(240,168,58,0.08)',
                    }}
                  >
                    {`{{ ${v} }}`}
                  </span>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

// ── ATT&CK Technique types ────────────────────────────────────────────────────

interface AttackTechnique {
  technique_id: string
  name: string
  tactic: string
  platforms: string
  description: string
  detection: string
  url: string
}

interface GeneratedCommand {
  tool: string
  label: string
  command: string
  vars: string[]
  description: string
}

interface ModelOption { key: string; label: string }

// ── TechniqueCard ─────────────────────────────────────────────────────────────

function TechniqueCard({
  tech, onSave, selectedModelKey,
}: {
  tech: AttackTechnique
  onSave: (cmd: GeneratedCommand, tid: string) => void
  selectedModelKey: string
}) {
  const [expanded, setExpanded] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [generated, setGenerated] = useState<GeneratedCommand[]>([])
  const [genError, setGenError] = useState('')
  const [saved, setSaved] = useState<Set<number>>(new Set())

  const rule = '1px solid var(--rule)'
  const ruleStrong = '1px solid var(--rule-strong)'

  async function callLLM(prompt: string): Promise<string> {
    const messages = [{ role: 'user', content: prompt }]
    const [source, ...parts] = selectedModelKey.split(':')
    const model = parts.join(':')

    if (source === 'local') {
      const settings = await (window as any).electronAPI.ollamaGetSettings()
      const endpoint = (settings?.endpoint || 'http://localhost:11434').replace(/\/$/, '')
      const res = await fetch(`${endpoint}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, messages, stream: false }),
      })
      if (!res.ok) throw new Error(`Local Ollama error: ${res.status}`)
      const data = await res.json()
      return data.message?.content ?? ''
    } else {
      const res = await fetch(`${getApiBase()}/ai/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages, model: model || undefined }),
      })
      if (!res.ok) throw new Error(await res.text())
      const data = await res.json()
      return data.content ?? ''
    }
  }

  async function handleGenerate() {
    if (!selectedModelKey) { setGenError('Select a model first.'); return }
    setGenerating(true)
    setGenError('')
    setGenerated([])
    try {
      const prompt = `You are a penetration tester. Generate 1-3 practical, copy-pasteable command templates for testing or demonstrating the following MITRE ATT&CK technique.

Technique: ${tech.technique_id} — ${tech.name}
Tactic: ${tech.tactic}
Platforms: ${tech.platforms}
Description: ${tech.description.slice(0, 400)}
${tech.detection ? `Detection hint: ${tech.detection.slice(0, 200)}` : ''}

Rules:
- Use real, commonly available tools (nmap, hydra, impacket, netexec, curl, etc.)
- Use {{ variable_name }} placeholders for values the user must fill in (e.g. {{ target }}, {{ username }})
- Return ONLY a JSON array. No markdown fences, no explanation outside the JSON.
- Each element: { "tool": string, "label": string, "command": string, "vars": string[], "description": string }
- "vars" must list every placeholder name used in "command" (without the braces)
- Keep commands concise and realistic`

      const raw = (await callLLM(prompt)).trim()
      const json = raw.replace(/^```[a-z]*\n?/i, '').replace(/\n?```$/i, '').trim()
      const parsed: GeneratedCommand[] = JSON.parse(json)
      setGenerated(Array.isArray(parsed) ? parsed : [])
    } catch (e: any) {
      setGenError(e.message ?? 'Generation failed')
    } finally {
      setGenerating(false)
    }
  }

  function handleSave(cmd: GeneratedCommand, idx: number) {
    onSave(cmd, tech.technique_id)
    setSaved(prev => new Set(prev).add(idx))
  }

  const tacticColor = '#f0a83a'

  return (
    <div style={{ border: rule, background: 'var(--bg)', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <div style={{ padding: '12px 14px 10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
          <a
            href={tech.url || `https://attack.mitre.org/techniques/${tech.technique_id.replace('.', '/')}/`}
            target="_blank" rel="noopener noreferrer"
            className="mono"
            style={{ fontSize: 10, padding: '2px 7px', background: 'rgba(240,168,58,0.08)', border: '1px solid rgba(240,168,58,0.3)', color: 'var(--accent)', textDecoration: 'none' }}
          >
            {tech.technique_id}
          </a>
          {tech.tactic.split(',').map(t => t.trim()).filter(Boolean).map(t => (
            <span key={t} className="badge" style={{ color: tacticColor, borderColor: 'rgba(240,168,58,0.3)', background: 'rgba(240,168,58,0.06)', fontSize: 9 }}>
              {t}
            </span>
          ))}
          {tech.platforms && (
            <span style={{ fontSize: 10, color: 'var(--fg-3)', marginLeft: 'auto' }}>
              {tech.platforms.split(',').slice(0, 3).join(' · ')}
            </span>
          )}
        </div>
        <h3 style={{ margin: 0, fontSize: 13, fontWeight: 500, color: 'var(--fg)', fontFamily: 'var(--font-sans)' }}>
          {tech.name}
        </h3>
      </div>

      {/* Description (collapsed) */}
      <div style={{ margin: '0 14px 10px', padding: '7px 10px', borderLeft: '2px solid rgba(240,168,58,0.25)', background: 'var(--bg-2)' }}>
        <div style={{ fontSize: 11.5, color: 'var(--fg-2)', lineHeight: 1.5 }}>
          {expanded ? tech.description : tech.description.slice(0, 180) + (tech.description.length > 180 ? '…' : '')}
        </div>
        {tech.description.length > 180 && (
          <button onClick={() => setExpanded(e => !e)} style={{ marginTop: 4, background: 'none', border: 'none', cursor: 'pointer', fontSize: 10, color: 'var(--fg-3)', padding: 0, display: 'flex', alignItems: 'center', gap: 3 }}>
            {expanded ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
            {expanded ? 'Less' : 'More'}
          </button>
        )}
      </div>

      {/* Detection hint */}
      {tech.detection && (
        <div style={{ margin: '0 14px 10px', fontSize: 10.5, color: 'var(--fg-3)', lineHeight: 1.4 }}>
          <span style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fg-4)', marginRight: 6 }}>Detection</span>
          {tech.detection.slice(0, 160)}{tech.detection.length > 160 ? '…' : ''}
        </div>
      )}

      {/* Generate button */}
      <div style={{ padding: '0 14px 12px' }}>
        <button
          onClick={handleGenerate}
          disabled={generating}
          style={{
            display: 'flex', alignItems: 'center', gap: 6, padding: '6px 14px',
            border: '1px solid rgba(240,168,58,0.3)', background: 'rgba(240,168,58,0.06)',
            color: 'var(--accent)', fontSize: 11, fontWeight: 600, cursor: generating ? 'not-allowed' : 'pointer',
            opacity: generating ? 0.6 : 1,
          }}
        >
          {generating
            ? <Loader size={11} style={{ animation: 'spin 1s linear infinite' }} />
            : <Sparkles size={11} />}
          {generating ? 'Generating…' : 'Generate Command(s)'}
        </button>

        {genError && (
          <div style={{ marginTop: 8, fontSize: 11, color: 'var(--crit)' }}>{genError}</div>
        )}

        {generated.length > 0 && (
          <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 8 }}>
            {generated.map((cmd, i) => (
              <div key={i} style={{ border: ruleStrong, background: 'var(--bg-2)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 10px', borderBottom: rule }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span className="badge mono" style={{ fontFamily: 'var(--font-mono)', fontSize: 9 }}>{cmd.tool}</span>
                    <span style={{ fontSize: 11, fontWeight: 500, color: 'var(--fg-2)' }}>{cmd.label}</span>
                  </div>
                  <button
                    onClick={() => handleSave(cmd, i)}
                    disabled={saved.has(i)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 4, padding: '3px 10px',
                      border: saved.has(i) ? '1px solid rgba(84,175,97,0.4)' : '1px solid rgba(240,168,58,0.3)',
                      background: saved.has(i) ? 'rgba(84,175,97,0.08)' : 'transparent',
                      color: saved.has(i) ? 'var(--ok)' : 'var(--accent)',
                      fontSize: 10, fontWeight: 600, cursor: saved.has(i) ? 'default' : 'pointer',
                    }}
                  >
                    <Save size={10} />
                    {saved.has(i) ? 'Saved' : 'Save to Library'}
                  </button>
                </div>
                <pre style={{ margin: 0, padding: '8px 10px', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.5 }}>
                  {cmd.command}
                </pre>
                {cmd.description && (
                  <div style={{ padding: '0 10px 8px', fontSize: 10.5, color: 'var(--fg-3)' }}>{cmd.description}</div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── TechniquesTab ─────────────────────────────────────────────────────────────

function TechniquesTab() {
  const [tactics, setTactics] = useState<string[]>([])
  const [activeTactic, setActiveTactic] = useState('')
  const [techQuery, setTechQuery] = useState('')
  const [techniques, setTechniques] = useState<AttackTechnique[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [offset, setOffset] = useState(0)
  const LIMIT = 24
  const searchDebounce = useRef<ReturnType<typeof setTimeout> | null>(null)

  const [modelOptions, setModelOptions] = useState<ModelOption[]>([])
  const [selectedModelKey, setSelectedModelKey] = useState('')
  const [loadingModels, setLoadingModels] = useState(false)

  const rule = '1px solid var(--rule)'
  const ruleStrong = '1px solid var(--rule-strong)'

  useEffect(() => {
    fetch(`${getApiBase()}/ai/attack/tactics`)
      .then(r => r.json())
      .then(d => setTactics(d.tactics ?? []))
      .catch(() => {})
    loadModels()
  }, [])

  async function loadModels() {
    setLoadingModels(true)
    const opts: ModelOption[] = []
    try {
      const localModels: string[] = await (window as any).electronAPI.ollamaModels()
      localModels.forEach(m => opts.push({ key: `local:${m}`, label: `[Local] ${m}` }))
    } catch { /* not in Electron or no local Ollama */ }
    try {
      const res = await fetch(`${getApiBase()}/ai/models`)
      if (res.ok) {
        const data = await res.json()
        ;(data.models as string[]).forEach(m => opts.push({ key: `server:${m}`, label: `[Server] ${m}` }))
      }
    } catch { /* ignore */ }
    setModelOptions(opts)
    if (opts.length) setSelectedModelKey(opts[0].key)
    setLoadingModels(false)
  }

  useEffect(() => {
    setOffset(0)
    load(0)
  }, [activeTactic, techQuery])

  async function load(off: number) {
    setLoading(true)
    try {
      let url: string
      if (techQuery.trim().length >= 2) {
        url = `${getApiBase()}/ai/attack/search?q=${encodeURIComponent(techQuery.trim())}&limit=${LIMIT}`
      } else {
        url = `${getApiBase()}/ai/attack/browse?limit=${LIMIT}&offset=${off}${activeTactic ? `&tactic=${encodeURIComponent(activeTactic)}` : ''}`
      }
      const res = await fetch(url)
      const data = await res.json()
      if (techQuery.trim().length >= 2) {
        setTechniques(data.results ?? [])
        setTotal(data.count ?? 0)
      } else {
        setTechniques(data.results ?? [])
        setTotal(data.total ?? 0)
      }
    } catch { /* ignore */ } finally {
      setLoading(false)
    }
  }

  function handleQueryChange(q: string) {
    setTechQuery(q)
    if (searchDebounce.current) clearTimeout(searchDebounce.current)
    searchDebounce.current = setTimeout(() => load(0), 300)
  }

  function handleTacticClick(t: string) {
    setActiveTactic(prev => prev === t ? '' : t)
    setTechQuery('')
  }

  async function handleSave(cmd: GeneratedCommand, tid: string) {
    const step = {
      name: cmd.tool, scan_type: cmd.tool,
      cmd_template: cmd.command,
      description: cmd.description,
      conditional: false, trigger_ports: [], timeout: 300, parallel: false,
    }
    await fetch(`${getApiBase()}/playbooks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: cmd.label,
        description: cmd.description,
        steps: [step],
        mitre_techniques: [tid],
      }),
    })
  }

  const tacticLabel = (t: string) => t.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase())

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
      {/* Tactic filter strip */}
      <div style={{ padding: '12px var(--pad)', borderBottom: rule, background: 'var(--bg-2)', display: 'flex', flexDirection: 'column', gap: 10, flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="search" size={13} color="var(--fg-3)" />
          <input
            value={techQuery}
            onChange={e => handleQueryChange(e.target.value)}
            placeholder="search by name, T-ID, keyword…"
            style={{ flex: 1, height: 32, fontSize: 12 }}
          />
          {(techQuery || activeTactic) && (
            <button onClick={() => { setTechQuery(''); setActiveTactic('') }} className="btn btn-ghost">
              <Icon name="x" size={10} /> Clear
            </button>
          )}
          {/* Model selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
            <Sparkles size={12} color="var(--fg-3)" />
            {loadingModels ? (
              <span style={{ fontSize: 11, color: 'var(--fg-3)' }}>Loading models…</span>
            ) : modelOptions.length === 0 ? (
              <span style={{ fontSize: 11, color: 'var(--fg-3)' }}>No models</span>
            ) : (
              <select
                value={selectedModelKey}
                onChange={e => setSelectedModelKey(e.target.value)}
                style={{
                  background: 'var(--bg)', border: ruleStrong, color: 'var(--fg)',
                  fontSize: 11, padding: '4px 8px', fontFamily: 'var(--font-mono)', maxWidth: 220,
                }}
              >
                {modelOptions.map(o => (
                  <option key={o.key} value={o.key}>{o.label}</option>
                ))}
              </select>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span className="smcap smcap-2" style={{ marginRight: 4 }}>Tactic</span>
          {tactics.map(t => (
            <button
              key={t}
              onClick={() => handleTacticClick(t)}
              style={{
                padding: '4px 10px', border: `1px solid ${activeTactic === t ? 'rgba(240,168,58,0.5)' : ruleStrong}`,
                background: activeTactic === t ? 'rgba(240,168,58,0.08)' : 'transparent',
                color: activeTactic === t ? 'var(--accent)' : 'var(--fg-3)',
                fontFamily: 'var(--font-mono)', fontSize: 10, cursor: 'pointer', textTransform: 'uppercase', letterSpacing: '0.06em',
              }}
            >
              {tacticLabel(t)}
            </button>
          ))}
          <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>
            {loading ? '…' : `${total} techniques`}
          </span>
        </div>
      </div>

      {/* Grid */}
      <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', padding: '20px var(--pad) 40px' }}>
        {loading && techniques.length === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '60px 0', gap: 8, color: 'var(--fg-3)' }}>
            <Loader size={14} style={{ animation: 'spin 1s linear infinite' }} />
            <span style={{ fontSize: 12 }}>Loading techniques…</span>
          </div>
        ) : techniques.length === 0 ? (
          <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--fg-3)', fontSize: 12 }}>
            No techniques found.
          </div>
        ) : (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(440px, 1fr))', gap: 14 }}>
              {techniques.map(t => (
                <TechniqueCard key={t.technique_id} tech={t} onSave={handleSave} selectedModelKey={selectedModelKey} />
              ))}
            </div>
            {!techQuery && total > offset + LIMIT && (
              <div style={{ display: 'flex', justifyContent: 'center', marginTop: 24 }}>
                <button
                  onClick={() => { const next = offset + LIMIT; setOffset(next); load(next) }}
                  className="btn"
                  style={{ padding: '8px 24px' }}
                >
                  Load more ({total - offset - LIMIT} remaining)
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function CommandLibrary() {
  const toast = useToast()
  const [activeTab, setActiveTab] = useState<'commands' | 'techniques'>('commands')
  const [query, setQuery] = useState('')
  const [activeCats, setActiveCats] = useState<Set<Category>>(new Set())
  const [activePhases, setActivePhases] = useState<Set<Phase>>(new Set())
  const [copiedId, setCopiedId] = useState<string | null>(null)

  // Custom (user-created) templates, persisted in localStorage and merged with built-ins.
  const [customTemplates, setCustomTemplates] = useState<CommandTemplate[]>(() => loadCustomTemplates())
  const [showNewModal, setShowNewModal] = useState(false)
  const [ntForm, setNtForm] = useState({ label: '', tool: '', category: ALL_CATEGORIES[0] as Category, phase: ALL_PHASES[0] as Phase, command: '', description: '' })
  useEffect(() => { localStorage.setItem(CUSTOM_TEMPLATES_KEY, JSON.stringify(customTemplates)) }, [customTemplates])

  const allTemplates = useMemo(() => [...TEMPLATES, ...customTemplates], [customTemplates])

  function saveNewTemplate() {
    if (!ntForm.label.trim() || !ntForm.command.trim()) { toast.error('Label and command are required'); return }
    const tpl: CommandTemplate = {
      id: `custom-${Date.now()}`,
      tool: ntForm.tool.trim() || ntForm.command.trim().split(/\s+/)[0],
      label: ntForm.label.trim(),
      category: ntForm.category,
      phase: ntForm.phase,
      description: ntForm.description.trim(),
      when_to_use: '',
      command: ntForm.command.trim(),
      vars: parseVars(ntForm.command),
      tags: ['custom'],
    }
    setCustomTemplates(prev => [...prev, tpl])
    setShowNewModal(false)
    setNtForm({ label: '', tool: '', category: ALL_CATEGORIES[0] as Category, phase: ALL_PHASES[0] as Phase, command: '', description: '' })
    toast.success(`Added template "${tpl.label}"`)
  }

  function exportLibrary() {
    const blob = new Blob([JSON.stringify(allTemplates, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'seraph-command-library.json'
    a.click()
    URL.revokeObjectURL(url)
    toast.success(`Exported ${allTemplates.length} templates`)
  }

  function toggleCat(id: Category) {
    setActiveCats(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  function togglePhase(id: Phase) {
    setActivePhases(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  function clearFilters() {
    setQuery('')
    setActiveCats(new Set())
    setActivePhases(new Set())
  }

  function copyCommand(id: string, command: string) {
    try { navigator.clipboard?.writeText(command) } catch (_) { /* ignore */ }
    setCopiedId(id)
    setTimeout(() => setCopiedId(prev => (prev === id ? null : prev)), 1800)
  }

  const hasFilters = query !== '' || activeCats.size > 0 || activePhases.size > 0

  const filtered = useMemo(() => {
    const q = query.toLowerCase().trim()
    return allTemplates.filter(t => {
      if (activeCats.size > 0 && !activeCats.has(t.category)) return false
      if (activePhases.size > 0 && !activePhases.has(t.phase)) return false
      if (!q) return true
      return (
        t.label.toLowerCase().includes(q) ||
        t.tool.toLowerCase().includes(q) ||
        t.command.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.when_to_use.toLowerCase().includes(q) ||
        (t.tags ?? []).some(tag => tag.toLowerCase().includes(q)) ||
        (t.mitre_techniques ?? []).some(tid => tid.toLowerCase().includes(q))
      )
    })
  }, [query, activeCats, activePhases, allTemplates])

  const grouped = useMemo(() => {
    const map = new Map<string, CommandTemplate[]>()
    for (const t of filtered) {
      if (!map.has(t.category)) map.set(t.category, [])
      map.get(t.category)!.push(t)
    }
    return map
  }, [filtered])

  const showGrouped = !hasFilters

  const rule = '1px solid var(--rule)'

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>

      {/* Page header */}
      <PageHeader
        breadcrumb="Knowledge Base"
        title="Command Library"
        sub={activeTab === 'commands'
          ? `${allTemplates.length} command templates · filter by category or phase`
          : '697 MITRE ATT&CK techniques · browse by tactic or search · generate commands with AI'}
        right={
          <>
            <button className="btn" onClick={exportLibrary}>
              <Icon name="download" size={11} /> Export
            </button>
            <button className="btn" onClick={() => setShowNewModal(true)}>
              <Icon name="plus" size={11} /> New template
            </button>
          </>
        }
      />

      {/* Tab bar */}
      <div style={{ display: 'flex', borderBottom: rule, flexShrink: 0 }}>
        {(['commands', 'techniques'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              padding: '10px 20px', border: 'none', borderBottom: activeTab === tab ? '2px solid var(--accent)' : '2px solid transparent',
              background: 'transparent', color: activeTab === tab ? 'var(--accent)' : 'var(--fg-3)',
              fontSize: 12, fontWeight: activeTab === tab ? 600 : 400, cursor: 'pointer',
              fontFamily: 'var(--font-sans)', textTransform: 'capitalize',
            }}
          >
            {tab === 'commands' ? `Commands (${allTemplates.length})` : 'ATT&CK Techniques'}
          </button>
        ))}
      </div>

      {activeTab === 'techniques' ? <TechniquesTab /> : null}
      {activeTab !== 'techniques' && <>

      {/* Filter strip */}
      <div style={{
        padding: '14px var(--pad)',
        borderBottom: rule,
        background: 'var(--bg-2)',
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
        flexShrink: 0,
      }}>

        {/* Row 1 — search */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="search" size={13} color="var(--fg-3)" />
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="search tools · keywords · commands · variables…"
            style={{ flex: 1, height: 32, fontSize: 12 }}
          />
          {hasFilters && (
            <button onClick={clearFilters} className="btn btn-ghost">
              <Icon name="x" size={10} /> Clear
            </button>
          )}
        </div>

        {/* Row 2 — categories */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span className="smcap smcap-2" style={{ marginRight: 4 }}>Category</span>
          {CATS.map(c => (
            <FilterPill
              key={c.id}
              label={c.id}
              color={c.color}
              active={activeCats.has(c.id as Category)}
              onClick={() => toggleCat(c.id as Category)}
            />
          ))}
        </div>

        {/* Row 3 — phases + count */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span className="smcap smcap-2" style={{ marginRight: 4 }}>Phase</span>
          {PHASES.map(p => (
            <FilterPill
              key={p.id}
              label={p.label}
              color={p.color}
              active={activePhases.has(p.id as Phase)}
              onClick={() => togglePhase(p.id as Phase)}
            />
          ))}
          <span style={{ marginLeft: 'auto' }} className="mono">
            <span style={{ fontSize: 11, color: 'var(--fg-3)' }}>
              {filtered.length} of {allTemplates.length} templates
            </span>
          </span>
        </div>
      </div>

      {/* Results area */}
      <div style={{ flex: 1, minHeight: 0, overflowY: 'auto', padding: '20px var(--pad) 40px' }}>
        {filtered.length === 0 ? (
          <div style={{ padding: '60px 20px', textAlign: 'center', color: 'var(--fg-3)' }}>
            <Icon name="search" size={20} color="var(--fg-4)" />
            <div className="mono" style={{ fontSize: 12, marginTop: 12 }}>No templates match your search.</div>
          </div>
        ) : showGrouped ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 28 }}>
            {Array.from(grouped.entries()).map(([catId, list]) => {
              const cat = CATS.find(c => c.id === catId)
              return (
                <div key={catId}>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginBottom: 12 }}>
                    <span className="mono" style={{
                      fontSize: 11,
                      color: cat?.color ?? 'var(--fg)',
                      letterSpacing: '0.18em',
                      textTransform: 'uppercase',
                      fontWeight: 600,
                    }}>
                      {catId}
                    </span>
                    <span className="mono" style={{ fontSize: 11, color: 'var(--fg-4)' }}>
                      ({list.length})
                    </span>
                  </div>
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fill, minmax(440px, 1fr))',
                    gap: 14,
                  }}>
                    {list.map(t => (
                      <TemplateCard
                        key={t.id}
                        tpl={t}
                        copied={copiedId === t.id}
                        onCopy={() => copyCommand(t.id, t.command)}
                      />
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        ) : (
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(440px, 1fr))',
            gap: 14,
          }}>
            {filtered.map(t => (
              <TemplateCard
                key={t.id}
                tpl={t}
                copied={copiedId === t.id}
                onCopy={() => copyCommand(t.id, t.command)}
              />
            ))}
          </div>
        )}
      </div>
      </>}

      {/* ── New template modal ── */}
      {showNewModal && (
        <div
          style={{ position: 'fixed', inset: 0, zIndex: 60, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.75)' }}
          onClick={() => setShowNewModal(false)}
        >
          <div onClick={e => e.stopPropagation()} style={{ background: 'var(--bg-2)', border: rule, padding: 24, width: '100%', maxWidth: 480, boxShadow: '0 8px 32px rgba(0,0,0,0.5)' }}>
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: 16 }}>
              <h2 className="mono" style={{ margin: 0, fontSize: 14, fontWeight: 500, marginRight: 'auto' }}>New command template</h2>
              <button className="btn btn-sm" onClick={() => setShowNewModal(false)}><X size={11} /></button>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <input value={ntForm.label} onChange={e => setNtForm(f => ({ ...f, label: e.target.value }))} placeholder="Label (e.g. Full TCP scan)"
                style={{ background: 'var(--bg)', border: rule, padding: '6px 10px', fontSize: 12, color: 'var(--fg)' }} />
              <input value={ntForm.tool} onChange={e => setNtForm(f => ({ ...f, tool: e.target.value }))} placeholder="Tool (optional — defaults to first word of command)"
                style={{ background: 'var(--bg)', border: rule, padding: '6px 10px', fontSize: 12, color: 'var(--fg)', fontFamily: 'var(--font-mono)' }} />
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <select value={ntForm.category} onChange={e => setNtForm(f => ({ ...f, category: e.target.value as Category }))}
                  style={{ background: 'var(--bg)', border: rule, padding: '6px 10px', fontSize: 12, color: 'var(--fg)' }}>
                  {ALL_CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
                </select>
                <select value={ntForm.phase} onChange={e => setNtForm(f => ({ ...f, phase: e.target.value as Phase }))}
                  style={{ background: 'var(--bg)', border: rule, padding: '6px 10px', fontSize: 12, color: 'var(--fg)' }}>
                  {ALL_PHASES.map(p => <option key={p} value={p}>{PHASE_LABELS[p]}</option>)}
                </select>
              </div>
              <textarea value={ntForm.command} onChange={e => setNtForm(f => ({ ...f, command: e.target.value }))} rows={2} placeholder="Command — use {{ target }} for variables"
                style={{ background: 'var(--bg)', border: rule, padding: '6px 10px', fontSize: 12, color: 'var(--fg)', fontFamily: 'var(--font-mono)', resize: 'vertical' }} />
              <textarea value={ntForm.description} onChange={e => setNtForm(f => ({ ...f, description: e.target.value }))} rows={2} placeholder="Description (optional)"
                style={{ background: 'var(--bg)', border: rule, padding: '6px 10px', fontSize: 12, color: 'var(--fg)', resize: 'vertical' }} />
            </div>
            <div style={{ display: 'flex', gap: 8, marginTop: 18 }}>
              <button className="btn btn-ghost" style={{ flex: 1, justifyContent: 'center' }} onClick={() => setShowNewModal(false)}>Cancel</button>
              <button className="btn btn-primary" style={{ flex: 1, justifyContent: 'center', opacity: ntForm.label.trim() && ntForm.command.trim() ? 1 : 0.5 }} disabled={!ntForm.label.trim() || !ntForm.command.trim()} onClick={saveNewTemplate}>Add template</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
