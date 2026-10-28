import { createContext, useContext, useState, useRef, useEffect, useCallback } from 'react'
import { getApiBase, wsUrl } from '@/lib/config'
import { getProjects, getTargets, getFindings, getPentestScans, createRawPentestScan } from '@/api/client'
import {
  MODE_CONFIGS, OperatorMode,
  PENTEST_TOOLS, MSF_MODULES,
  buildSystemPrompt, buildPreviewPrompt,
  buildInitialUserMessage, buildOutputUserMessage, buildSkipUserMessage,
  buildTools, parseOperatorResponse, assembleCliCommand, assembleMsfCommand,
  type PentestScanRecord,
} from '@/lib/operator'
import { TEMPLATES } from '@/lib/templates'
import type { Project, TargetSummary } from '@/types'

// ── Types (exported so the page can use them) ─────────────────────────────────

export interface ChatMessage {
  role: string
  content: string
  tool_calls?: Array<{ function: { name: string; arguments: Record<string, any> } }>
  name?: string  // tool name on role:'tool' result messages
}

export interface OperatorStep {
  id: number
  analysis: string
  attackPathNote: string | null
  action: { tool: string; command: string; rationale: string } | null
  result: 'pending' | 'approved' | 'skipped' | 'error'
  output: string
  outputOpen: boolean
}

export type OperatorPhase = 'idle' | 'thinking' | 'awaiting' | 'running' | 'done'

export interface ModelOption { key: string; label: string }

// ── Context type ──────────────────────────────────────────────────────────────

export interface AIOperatorContextValue {
  // Config
  mode: OperatorMode
  projects: Project[]
  targets: TargetSummary[]
  selectedProject: string
  selectedTarget: string
  modelOptions: ModelOption[]
  selectedModelKey: string
  loadingModels: boolean
  enabledTools: Set<string>
  enabledMsf: Set<string>
  lhostIp: string
  useToolCalling: boolean
  thinkingEnabled: boolean
  autoBudget: number

  // Prompt editor
  promptDraft: string
  promptIsAuto: boolean

  // Session
  phase: OperatorPhase
  steps: OperatorStep[]
  liveOutput: string
  llmStream: string
  llmThinking: string
  errorMsg: string
  showStream: boolean
  runStartTime: number | null

  // Config setters
  setSelectedProject: (id: string) => void
  setSelectedTarget: (id: string) => void
  setSelectedModelKey: (key: string) => void
  toggleTool: (id: string) => void
  toggleMsf: (id: string) => void
  setShowStream: (fn: boolean | ((p: boolean) => boolean)) => void
  setPromptDraft: (v: string) => void
  setPromptIsAuto: (v: boolean) => void
  setLhostIp: (ip: string) => void
  setUseToolCalling: (v: boolean) => void
  setThinkingEnabled: (v: boolean) => void
  setAutoBudget: (n: number) => void

  // Actions
  loadModelOptions: () => Promise<void>
  applyModeSwitch: (newMode: OperatorMode, resetTools: boolean) => void
  regeneratePrompt: () => void
  startSession: () => Promise<void>
  handleApprove: (step: OperatorStep) => Promise<void>
  handleSkip: (step: OperatorStep) => Promise<void>
  handleStop: () => void
  toggleStepOutput: (stepId: number) => void
  resetSession: () => void
}

// ── Context ───────────────────────────────────────────────────────────────────

const AIOperatorContext = createContext<AIOperatorContextValue | null>(null)

export function useAIOperator(): AIOperatorContextValue {
  const ctx = useContext(AIOperatorContext)
  if (!ctx) throw new Error('useAIOperator must be used inside AIOperatorProvider')
  return ctx
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function isMsfTool(toolId: string): boolean {
  return toolId.includes('/') || toolId.startsWith('auxiliary') || toolId.startsWith('exploit') || toolId.startsWith('post')
}

function phaseIdFor(mode: OperatorMode, toolId: string): string {
  if (mode === 'recon') return 'recon'
  if (mode === 'audit') return 'scanning'
  return isMsfTool(toolId) ? 'exploitation' : 'scanning'
}

// Persisted operator config (model/tools/mode/etc.) — survives reloads.
const LS_CONFIG = 'ai-operator-config'
function loadConfig(): Record<string, any> {
  try { return JSON.parse(localStorage.getItem(LS_CONFIG) || '{}') } catch { return {} }
}

// ── Provider ──────────────────────────────────────────────────────────────────

export function AIOperatorProvider({ children }: { children: React.ReactNode }) {
  // ── Config state (restored from localStorage where available) ────────────────
  const _saved = loadConfig()
  const _initMode: OperatorMode = _saved.mode ?? 'attack'
  const [mode, setMode] = useState<OperatorMode>(_initMode)
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedProject, setSelectedProject] = useState('')
  const [targets, setTargets] = useState<TargetSummary[]>([])
  const [selectedTarget, setSelectedTarget] = useState('')
  const [modelOptions, setModelOptions] = useState<ModelOption[]>([])
  const [selectedModelKey, setSelectedModelKey] = useState(_saved.selectedModelKey ?? '')
  const [loadingModels, setLoadingModels] = useState(false)
  const [enabledTools, setEnabledTools] = useState<Set<string>>(new Set(_saved.enabledTools ?? MODE_CONFIGS[_initMode].defaultTools))
  const [enabledMsf, setEnabledMsf] = useState<Set<string>>(new Set(_saved.enabledMsf ?? MODE_CONFIGS[_initMode].defaultMsf))

  // ── Prompt state ────────────────────────────────────────────────────────────
  const [promptDraft, setPromptDraft] = useState('')
  const [promptIsAuto, setPromptIsAuto] = useState(true)

  // ── Session state ────────────────────────────────────────────────────────────
  const [phase, setPhase] = useState<OperatorPhase>('idle')
  const [steps, setSteps] = useState<OperatorStep[]>([])
  const [liveOutput, setLiveOutput] = useState('')
  const [llmStream, setLlmStream] = useState('')
  const [llmThinking, setLlmThinking] = useState('')
  const [errorMsg, setErrorMsg] = useState('')
  const [showStream, setShowStream] = useState(false)
  const [runStartTime, setRunStartTime] = useState<number | null>(null)
  const [lhostIp, setLhostIp] = useState(_saved.lhostIp ?? '')
  const [useToolCalling, setUseToolCalling] = useState(_saved.useToolCalling ?? true)
  const [thinkingEnabled, setThinkingEnabled] = useState(_saved.thinkingEnabled ?? false)

  // Auto-run budget: number of upcoming steps to auto-approve without prompting.
  const [autoBudget, setAutoBudget] = useState(0)
  const autoBudgetRef = useRef(0)
  useEffect(() => { autoBudgetRef.current = autoBudget }, [autoBudget])

  // ── Refs (survive re-renders, not tied to any mounted component) ─────────────
  const messages = useRef<ChatMessage[]>([])
  const stopped = useRef(false)
  const wsRef = useRef<WebSocket | null>(null)
  const abortRef = useRef<AbortController | null>(null)

  // ── Init ────────────────────────────────────────────────────────────────────

  useEffect(() => {
    getProjects().then(ps => {
      setProjects(ps)
      if (ps.length) setSelectedProject(ps[0].id)
    })
    loadModelOptions()
  }, [])

  useEffect(() => {
    if (!selectedProject) return
    getTargets(selectedProject).then(ts => {
      setTargets(ts)
      setSelectedTarget(ts[0]?.id ?? '')
    })
  }, [selectedProject])

  // Auto-regenerate preview prompt when anything changes (unless user has customised it)
  useEffect(() => {
    if (!promptIsAuto) return
    const t = targets.find(x => x.id === selectedTarget)
    if (!t) return
    setPromptDraft(buildPreviewPrompt(mode, t, [...enabledTools], [...enabledMsf], useToolCalling))
  }, [mode, enabledTools, enabledMsf, selectedTarget, targets, promptIsAuto, useToolCalling])

  // Persist config across reloads.
  useEffect(() => {
    try {
      localStorage.setItem(LS_CONFIG, JSON.stringify({
        mode, selectedModelKey,
        enabledTools: [...enabledTools], enabledMsf: [...enabledMsf],
        useToolCalling, thinkingEnabled, lhostIp,
      }))
    } catch { /* quota / unavailable */ }
  }, [mode, selectedModelKey, enabledTools, enabledMsf, useToolCalling, thinkingEnabled, lhostIp])

  // ── Model loading ────────────────────────────────────────────────────────────

  async function loadModelOptions() {
    setLoadingModels(true)
    const opts: ModelOption[] = []
    try {
      const settings = await window.electronAPI!.ollamaGetSettings()
      const baseUrl = settings.localOllamaUrl.replace(/\/$/, '')
      const localModels = await window.electronAPI!.ollamaModels()

      // Check each model's capabilities via /api/show — only keep models with "tools" support
      const checks = await Promise.all(
        localModels.map(async (m: string) => {
          try {
            const res = await fetch(`${baseUrl}/api/show`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ name: m }),
            })
            const data = await res.json()
            const caps: string[] = data.capabilities ?? []
            return caps.includes('tools') ? m : null
          } catch {
            return null
          }
        })
      )
      checks.filter(Boolean).forEach(m => opts.push({ key: `local:${m}`, label: `[Local] ${m}` }))
    } catch { /* Ollama not running */ }
    try {
      const res = await fetch(`${getApiBase()}/ai/tool-models`)
      if (res.ok) {
        const data = await res.json()
        ;(data.models as string[]).forEach(m => opts.push({ key: `server:${m}`, label: `[Server] ${m}` }))
      }
    } catch { /* server offline */ }
    setModelOptions(opts)
    if (opts.length && !opts.find(o => o.key === selectedModelKey)) setSelectedModelKey(opts[0].key)
    setLoadingModels(false)
  }

  // ── Mode switch ──────────────────────────────────────────────────────────────

  function applyModeSwitch(newMode: OperatorMode, resetTools: boolean) {
    const cfg = MODE_CONFIGS[newMode]
    setMode(newMode)
    if (resetTools) {
      setEnabledTools(new Set(cfg.defaultTools))
      setEnabledMsf(new Set(cfg.defaultMsf))
    }
    if (promptIsAuto) {
      const t = targets.find(x => x.id === selectedTarget)
      if (t) {
        const tools = resetTools ? cfg.defaultTools : [...enabledTools]
        const msf   = resetTools ? cfg.defaultMsf   : [...enabledMsf]
        setPromptDraft(buildPreviewPrompt(newMode, t, tools, msf, useToolCalling))
      }
    }
  }

  // ── Tool toggles ─────────────────────────────────────────────────────────────

  function toggleTool(id: string) {
    setEnabledTools(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n })
  }

  function toggleMsf(id: string) {
    setEnabledMsf(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n })
  }

  // ── Prompt helpers ────────────────────────────────────────────────────────────

  function regeneratePrompt() {
    const t = targets.find(x => x.id === selectedTarget)
    if (!t) return
    setPromptDraft(buildPreviewPrompt(mode, t, [...enabledTools], [...enabledMsf], useToolCalling))
    setPromptIsAuto(true)
  }

  // ── LLM call (Ollama /api/chat with tool calling) ────────────────────────────

  interface LLMResult {
    content: string
    toolCalls: Array<{ function: { name: string; arguments: Record<string, any> } }> | null
  }

  async function callLLM(
    msgs: ChatMessage[],
    onToken: (t: string) => void,
    tools: object[] = [],
    onThinking?: (t: string) => void,
  ): Promise<LLMResult> {
    abortRef.current = new AbortController()
    const { signal } = abortRef.current
    const [source, ...parts] = selectedModelKey.split(':')
    const model = parts.join(':')

    if (source === 'local') {
      const settings = await window.electronAPI!.ollamaGetSettings()
      const baseUrl = settings.localOllamaUrl.replace(/\/$/, '')

      const body: Record<string, unknown> = { model, messages: msgs, tools, stream: true }
      if (thinkingEnabled) body.think = true

      const resp = await fetch(`${baseUrl}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal,
      })
      if (!resp.ok || !resp.body) throw new Error(`Ollama error: ${resp.status}`)

      const reader = resp.body.getReader()
      const decoder = new TextDecoder()
      let content = ''
      let toolCalls: LLMResult['toolCalls'] = null
      let buf = ''
      try {
        while (true) {
          const { done, value } = await reader.read()
          if (done || stopped.current) break
          buf += decoder.decode(value, { stream: true })
          const lines = buf.split('\n')
          buf = lines.pop() ?? ''
          for (const line of lines) {
            const trimmed = line.trim()
            if (!trimmed) continue
            try {
              const chunk = JSON.parse(trimmed)
              const thinkToken: string = chunk.message?.thinking ?? ''
              if (thinkToken && onThinking) onThinking(thinkToken)
              const token: string = chunk.message?.content ?? ''
              if (token) { content += token; onToken(token) }
              if (chunk.done && chunk.message?.tool_calls?.length) {
                toolCalls = chunk.message.tool_calls
              }
            } catch { /* malformed chunk */ }
          }
        }
      } finally {
        reader.releaseLock()
      }
      return { content, toolCalls }
    }

    // Server-side fallback (non-Ollama) — no native tool calling, use JSON prompt
    const res = await fetch(`${getApiBase()}/ai/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: msgs, model }),
      signal,
    })
    const data = await res.json()
    if (!res.ok) throw new Error(data.detail || 'AI chat failed')
    onToken(data.content)
    return { content: data.content, toolCalls: null }
  }

  // ── ATT&CK search helper (auto-executed, no user approval needed) ────────────

  async function executeAttackSearch(query: string): Promise<string> {
    try {
      const r = await fetch(`${getApiBase()}/ai/attack/search?q=${encodeURIComponent(query)}&limit=5`)
      if (!r.ok) return `ATT&CK search failed (${r.status}).`
      const data = await r.json()
      if (!data.results?.length) return `No ATT&CK techniques found for: "${query}"`
      const lines = [`[ATT&CK search: "${query}" — ${data.count} result(s)]`]
      for (const t of data.results as Array<{ technique_id: string; name: string; tactic: string; description: string; detection: string; url: string }>) {
        lines.push(`\n${t.technique_id}: ${t.name}  |  tactic: ${t.tactic}`)
        if (t.description) lines.push(`  ${t.description.slice(0, 300)}`)
        if (t.detection)   lines.push(`  Detection: ${t.detection.slice(0, 200)}`)
        if (t.url)         lines.push(`  ${t.url}`)
      }
      return lines.join('\n')
    } catch {
      return 'ATT&CK knowledge base unavailable.'
    }
  }

  // Resolve any search_attack_techniques tool calls automatically before continuing.
  // Returns the final LLM result after all lookups are resolved (max 3 iterations).
  async function resolveAttackSearches(
    initialResult: { content: string; toolCalls: Array<{ function: { name: string; arguments: Record<string, any> } }> | null },
    currentMsgs: ChatMessage[],
    tools: object[],
    onToken: (t: string) => void,
    onThinking?: (t: string) => void,
  ): Promise<{ result: { content: string; toolCalls: typeof initialResult.toolCalls }; msgs: ChatMessage[] }> {
    let result = initialResult
    let msgs = currentMsgs

    for (let i = 0; i < 3; i++) {
      if (!result.toolCalls?.length) break
      const call = result.toolCalls[0]
      if (call.function?.name !== 'search_attack_techniques') break

      const query = call.function.arguments?.query ?? ''
      const searchResult = await executeAttackSearch(query)

      msgs = [
        ...msgs,
        { role: 'assistant' as const, content: result.content || '', tool_calls: result.toolCalls },
        { role: 'tool' as const,      content: searchResult, name: 'search_attack_techniques' },
      ]
      messages.current = msgs
      setLlmStream('')
      result = await callLLM(msgs, onToken, tools, onThinking)
    }

    return { result, msgs }
  }

  // ── Command sanitizer ─────────────────────────────────────────────────────────

  const SUDO_ALLOWED = new Set(['nmap', 'masscan', 'tcpdump'])

  function sanitizeCommand(cmd: string): string {
    // Walk every token in the command and strip "sudo" unless it precedes an allowed binary.
    // Handles sudo in pipelines, xargs chains, etc.
    return cmd.replace(/sudo\s+(\S+)/g, (_match, nextToken) => {
      const binary = nextToken.split('/').pop() ?? ''
      return SUDO_ALLOWED.has(binary) ? `sudo ${nextToken}` : nextToken
    })
  }

  const KNOWN_TOOL_IDS = new Set([
    ...PENTEST_TOOLS.map(t => t.id),
    ...MSF_MODULES.map(t => t.id),
  ])

  // ── WebSocket execution ───────────────────────────────────────────────────────

  async function executeViaWS(scanId: string, command: string): Promise<string> {
    const TIMEOUT_MS = 5 * 60 * 1000 // 5 minutes
    return new Promise((resolve, reject) => {
      // /ws/execute now only ever runs the server-regenerated audit script for
      // the scan — it ignores any `script` the client sends. Ad-hoc operator
      // commands go through /ws/pentest, which executes the `command` already
      // stored server-side on the scan (from createRawPentestScan below) via
      // argv exec, no shell.
      const ws = new WebSocket(wsUrl(`/ws/pentest/${scanId}`))
      wsRef.current = ws
      let output = ''
      let settled = false

      const finish = (result: string) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        ws.close()
        resolve(result)
      }

      const timer = setTimeout(() => {
        finish(output + '\n[operator] Command timed out after 5 minutes and was killed.')
      }, TIMEOUT_MS)

      ws.onopen = () => ws.send(JSON.stringify({ action: 'run', script: command }))

      ws.onmessage = (e) => {
        if (stopped.current) { finish(output); return }
        try {
          const msg = JSON.parse(e.data)
          if (msg.type === 'stdout' || msg.type === 'stderr') {
            output += msg.data
            setLiveOutput(o => o + msg.data)
          }
          if (msg.type === 'exit') finish(output)
        } catch { /* non-JSON */ }
      }

      ws.onerror = () => { if (!settled) { settled = true; clearTimeout(timer); reject(new Error('WebSocket connection failed')) } }
      ws.onclose = () => finish(output)
    })
  }

  // ── Advance LLM ───────────────────────────────────────────────────────────────

  function parseStepFromResult(result: { content: string; toolCalls: any[] | null }): OperatorStep | 'done' | 'error' {
    // Prefer structured tool calls (Ollama native tool calling)
    if (result.toolCalls?.length) {
      const call = result.toolCalls[0]
      const fname: string = call.function?.name ?? ''
      const args: Record<string, any> = call.function?.arguments ?? {}

      if (fname === 'finish_engagement') return 'done'

      if (fname === 'run_tool') {
        const toolId: string = args.tool_id ?? ''
        let command: string

        if (isMsfTool(toolId)) {
          // MSF: assemble from structured options — never trust a free-form msfconsole string
          command = assembleMsfCommand(toolId, args.msf_options ?? {})
        } else {
          // CLI: fill template slots, append extra_flags
          const available = TEMPLATES.filter(t => t.tool === toolId)
          const template = available.find(t => t.id === args.template_id) ?? available[0]
          if (template) {
            command = assembleCliCommand(template, args.vars ?? {}, args.extra_flags ?? '')
          } else {
            // No template for this tool — fall back to raw command if model provided one
            command = typeof args.command === 'string' ? args.command : `${toolId} {{ target }}`
          }
        }

        return {
          id: Date.now(),
          analysis: args.analysis || result.content || '',
          attackPathNote: args.attack_path_note || null,
          action: { tool: toolId, command, rationale: args.rationale || '' },
          result: 'pending',
          output: '',
          outputOpen: false,
        }
      }
    }

    // Fallback: JSON text parsing (server-side or models without tool calling support)
    const parsed = parseOperatorResponse(result.content)
    if (!parsed) return 'error'
    if (!parsed.next_action) return 'done'
    return {
      id: Date.now(),
      analysis: parsed.analysis,
      attackPathNote: parsed.attack_path_note,
      action: parsed.next_action,
      result: 'pending',
      output: '',
      outputOpen: false,
    }
  }

  // Parse the model's turn into a step; on a malformed/unrecognised response, nudge it
  // to reformat and retry ONCE before giving up (a common cause of "doesn't perform well").
  async function parseOrRetry(
    result: LLMResult, resolvedMsgs: ChatMessage[], tools: object[],
  ): Promise<{ step: OperatorStep | 'done' | 'error'; result: LLMResult; msgs: ChatMessage[] }> {
    const step = parseStepFromResult(result)
    if (step !== 'error') return { step, result, msgs: resolvedMsgs }

    const nudge = useToolCalling
      ? 'Your previous message did not contain a valid function call. Call `run_tool` (or `finish_engagement`) now with proper structured arguments — do not reply in plain text.'
      : 'Your previous message was not valid JSON. Reply with ONLY the JSON object described in RESPONSE FORMAT — no prose, no markdown fences.'
    const retryMsgs: ChatMessage[] = [
      ...resolvedMsgs,
      { role: 'assistant', content: result.content, ...(result.toolCalls ? { tool_calls: result.toolCalls } : {}) },
      { role: 'user', content: nudge },
    ]
    messages.current = retryMsgs
    setLlmStream('')
    const retried = await callLLM(retryMsgs, t => setLlmStream(p => p + t), tools, t => setLlmThinking(p => p + t))
    const { result: r2, msgs: m2 } = await resolveAttackSearches(retried, retryMsgs, tools, t => setLlmStream(p => p + t), t => setLlmThinking(p => p + t))
    return { step: parseStepFromResult(r2), result: r2, msgs: m2 }
  }

  const advanceLLM = useCallback(async (userMsg: string, assistantContent: string, assistantToolCalls?: any[]) => {
    if (stopped.current) { setPhase('done'); return }

    const assistantMsg: ChatMessage = assistantToolCalls?.length
      ? { role: 'assistant', content: assistantContent, tool_calls: assistantToolCalls }
      : { role: 'assistant', content: assistantContent }

    // After a tool call, the result goes as role:'tool'; otherwise as role:'user'
    const resultMsg: ChatMessage = assistantToolCalls?.length
      ? { role: 'tool', content: userMsg, name: 'run_tool' }
      : { role: 'user', content: userMsg }

    const newMsgs: ChatMessage[] = [...messages.current, assistantMsg, resultMsg]
    messages.current = newMsgs
    setPhase('thinking')
    setErrorMsg('')
    setLlmStream('')
    setLlmThinking('')

    const tools = useToolCalling ? buildTools([...enabledTools], [...enabledMsf]) : []

    try {
      const rawResult = await callLLM(newMsgs, t => setLlmStream(prev => prev + t), tools, t => setLlmThinking(prev => prev + t))
      if (stopped.current) { setPhase('done'); return }
      const { result, msgs: resolvedMsgs } = await resolveAttackSearches(rawResult, newMsgs, tools, t => setLlmStream(prev => prev + t), t => setLlmThinking(prev => prev + t))
      if (stopped.current) { setPhase('done'); return }

      const { step, result: finalResult, msgs: finalMsgs } = await parseOrRetry(result, resolvedMsgs, tools)
      if (stopped.current) { setPhase('done'); return }

      messages.current = [
        ...finalMsgs,
        { role: 'assistant', content: finalResult.content, ...(finalResult.toolCalls ? { tool_calls: finalResult.toolCalls } : {}) },
      ]

      if (step === 'done') { setPhase('done'); return }
      if (step === 'error') {
        setErrorMsg('Model returned an unrecognised response twice. Try a stronger tool-capable model.')
        setPhase('done')
        return
      }
      setSteps(prev => [...prev, step])
      setPhase('awaiting')
    } catch (err: any) {
      if (!stopped.current) {
        setErrorMsg(err.message || 'LLM call failed')
        setPhase('done')
      }
    }
  }, [selectedModelKey, enabledTools, enabledMsf]) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Session start ─────────────────────────────────────────────────────────────

  async function startSession() {
    const target = targets.find(t => t.id === selectedTarget)
    if (!selectedProject || !target || !selectedModelKey) return

    stopped.current = false
    messages.current = []
    setSteps([])
    setLiveOutput('')
    setErrorMsg('')
    setLlmStream('')
    setLlmThinking('')
    setPhase('thinking')

    try {
      const [findings, allScans] = await Promise.all([
        getFindings(selectedProject),
        getPentestScans(selectedProject),
      ])

      // Normalise pentest scan records — the API returns more fields than the
      // TypeScript type models, so we cast and defensively extract what we need.
      const priorScans: PentestScanRecord[] = (allScans as any[])
        .filter((s: any) => s.target_id === selectedTarget)
        .map((s: any) => {
          let tool = s.tool_name || ''
          let command = s.command || ''
          if (!tool && s.config_json) {
            try { const c = JSON.parse(s.config_json); tool = c.tool_name || c.tool || ''; command = command || c.command || '' } catch { /* ignore */ }
          }
          if (!tool) tool = s.scan_type || ''
          return { tool_name: tool, command, status: s.status || '', raw_output: s.raw_output || null }
        })
        .filter((s: PentestScanRecord) => !!s.tool_name)
        .slice(-40)   // last 40 runs, most recent context

      const systemPrompt = promptIsAuto
        ? buildSystemPrompt(mode, target, findings, [...enabledTools], [...enabledMsf], priorScans, useToolCalling)
        : promptDraft

      const initMsgs: ChatMessage[] = [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: buildInitialUserMessage(priorScans.length > 0) },
      ]
      messages.current = initMsgs

      const tools = useToolCalling ? buildTools([...enabledTools], [...enabledMsf]) : []
      const rawResult = await callLLM(initMsgs, t => setLlmStream(prev => prev + t), tools, t => setLlmThinking(prev => prev + t))
      if (stopped.current) { setPhase('done'); return }
      const { result, msgs: resolvedMsgs } = await resolveAttackSearches(rawResult, initMsgs, tools, t => setLlmStream(prev => prev + t), t => setLlmThinking(prev => prev + t))
      if (stopped.current) { setPhase('done'); return }

      const { step, result: finalResult, msgs: finalMsgs } = await parseOrRetry(result, resolvedMsgs, tools)
      if (stopped.current) { setPhase('done'); return }

      messages.current = [
        ...finalMsgs,
        { role: 'assistant', content: finalResult.content, ...(finalResult.toolCalls ? { tool_calls: finalResult.toolCalls } : {}) },
      ]

      if (step === 'done' || step === 'error') {
        setErrorMsg(step === 'error' ? 'Model returned an unrecognised response twice. Try a stronger tool-capable model.' : 'Model returned no action.')
        setPhase('done')
        return
      }
      setSteps([step])
      setPhase('awaiting')
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to start session')
      setPhase('idle')
    }
  }

  // ── Approve ───────────────────────────────────────────────────────────────────

  async function handleApprove(step: OperatorStep) {
    if (!step.action) return

    // Resolve the tool ID — the model sometimes writes generic labels like "msf-exploit"
    // instead of the exact module path. Try to recover the real ID from the command.
    let resolvedTool = step.action.tool
    if (!KNOWN_TOOL_IDS.has(resolvedTool)) {
      const msfMatch = step.action.command.match(/use\s+([\w/]+)/)
      if (msfMatch) {
        const candidate = msfMatch[1]
        if (KNOWN_TOOL_IDS.has(candidate)) resolvedTool = candidate
      }
    }

    if (!KNOWN_TOOL_IDS.has(resolvedTool)) {
      const errMsg = `[operator] Rejected: unknown tool "${step.action.tool}". Use the exact tool ID from the enabled list (e.g. "exploit/unix/ftp/vsftpd_234_backdoor"), not a generic label.`
      setSteps(prev => prev.map(s => s.id === step.id ? { ...s, result: 'approved', output: errMsg, outputOpen: true } : s))
      const rawAssistant = JSON.stringify({ analysis: step.analysis, attack_path_note: step.attackPathNote, next_action: step.action })
      await advanceLLM(buildOutputUserMessage(step.action.command, errMsg), rawAssistant)
      return
    }

    setPhase('running')
    setLiveOutput('')
    setRunStartTime(Date.now())
    setSteps(prev => prev.map(s => s.id === step.id ? { ...s, result: 'approved' } : s))

    // Substitute common LHOST placeholders with configured IP
    const LHOST_PATTERNS = [/<PENTESTER_IP>/gi, /<LHOST>/gi, /<YOUR_IP>/gi, /<ATTACKER_IP>/gi, /<LOCAL_IP>/gi, /<KALI_IP>/gi]
    let rawCommand = step.action!.command
    if (lhostIp) {
      LHOST_PATTERNS.forEach(p => { rawCommand = rawCommand.replace(p, lhostIp) })
    }

    // Detect any remaining unfilled placeholders
    const unfilled = rawCommand.match(/<[A-Z][A-Z0-9_]*>/g)
    if (unfilled) {
      const errMsg = `[operator] Command has unfilled placeholder(s): ${unfilled.join(', ')}. Set your LHOST IP in the left panel, or the model must replace all template variables with real values.`
      setRunStartTime(null)
      setSteps(prev => prev.map(s => s.id === step.id ? { ...s, output: errMsg, outputOpen: true } : s))
      const rawAssistant = JSON.stringify({ analysis: step.analysis, attack_path_note: step.attackPathNote, next_action: step.action })
      await advanceLLM(buildOutputUserMessage(step.action!.command, errMsg), rawAssistant)
      return
    }

    const safeCommand = sanitizeCommand(rawCommand)
    let output = ''
    try {
      const scan = await createRawPentestScan({
        project_id: selectedProject,
        target_id: selectedTarget,
        engagement_type: 'ai_operator',
        phase_id: phaseIdFor(mode, resolvedTool),
        tool_name: resolvedTool,
        command: safeCommand,
        notes: `AI Operator [${mode}]: ${step.action!.rationale}`,
      })
      output = await executeViaWS(scan.scan_id, safeCommand)
    } catch (err: any) {
      output = `Error: ${err.message}`
    }

    setRunStartTime(null)
    if (stopped.current) { setPhase('done'); return }

    setSteps(prev => prev.map(s => s.id === step.id ? { ...s, output, outputOpen: true } : s))

    // Reconstruct what the assistant said — either as a tool_call or as raw JSON text,
    // depending on how this step was created.
    const lastAssistantMsg = messages.current.findLast(m => m.role === 'assistant')
    const assistantToolCalls = lastAssistantMsg?.tool_calls
    const assistantContent = lastAssistantMsg?.content ?? JSON.stringify({
      analysis: step.analysis,
      attack_path_note: step.attackPathNote,
      next_action: step.action,
    })
    await advanceLLM(buildOutputUserMessage(safeCommand, output), assistantContent, assistantToolCalls)
  }

  // ── Skip / Stop / Reset ───────────────────────────────────────────────────────

  async function handleSkip(step: OperatorStep) {
    setSteps(prev => prev.map(s => s.id === step.id ? { ...s, result: 'skipped' } : s))
    const lastAssistantMsg = messages.current.findLast(m => m.role === 'assistant')
    const assistantToolCalls = lastAssistantMsg?.tool_calls
    const assistantContent = lastAssistantMsg?.content ?? JSON.stringify({
      analysis: step.analysis,
      attack_path_note: step.attackPathNote,
      next_action: step.action,
    })
    await advanceLLM(buildSkipUserMessage(), assistantContent, assistantToolCalls)
  }

  function handleStop() {
    stopped.current = true
    wsRef.current?.close()
    abortRef.current?.abort()
    setAutoBudget(0)
    setPhase('done')
  }

  // Auto-run budget: when a step is awaiting and budget remains, approve it automatically.
  useEffect(() => {
    if (phase !== 'awaiting' || autoBudgetRef.current <= 0) return
    const last = steps[steps.length - 1]
    if (!last || last.result !== 'pending') return
    setAutoBudget(b => Math.max(0, b - 1))
    handleApprove(last)
  }, [phase, steps]) // eslint-disable-line react-hooks/exhaustive-deps

  function resetSession() {
    setPhase('idle')
    setSteps([])
    setLlmStream('')
    setLlmThinking('')
    setAutoBudget(0)
    messages.current = []
  }

  function toggleStepOutput(stepId: number) {
    setSteps(prev => prev.map(s => s.id === stepId ? { ...s, outputOpen: !s.outputOpen } : s))
  }

  // ── Context value ─────────────────────────────────────────────────────────────

  const value: AIOperatorContextValue = {
    mode, projects, targets, selectedProject, selectedTarget,
    modelOptions, selectedModelKey, loadingModels,
    enabledTools, enabledMsf, lhostIp,
    useToolCalling, thinkingEnabled, autoBudget,
    promptDraft, promptIsAuto,
    phase, steps, liveOutput, llmStream, llmThinking, errorMsg, showStream, runStartTime,

    setSelectedProject, setSelectedTarget, setSelectedModelKey,
    toggleTool, toggleMsf,
    setShowStream: (fn) => setShowStream(fn as any),
    setPromptDraft, setPromptIsAuto, setLhostIp,
    setUseToolCalling, setThinkingEnabled, setAutoBudget,

    loadModelOptions, applyModeSwitch, regeneratePrompt,
    startSession, handleApprove, handleSkip, handleStop,
    toggleStepOutput, resetSession,
  }

  return (
    <AIOperatorContext.Provider value={value}>
      {children}
    </AIOperatorContext.Provider>
  )
}
