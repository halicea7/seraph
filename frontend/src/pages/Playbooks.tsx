import { useState, useEffect, useRef, useMemo } from 'react'
import {
  Play, ChevronRight, CheckCircle, XCircle, SkipForward,
  Loader, Clock, Shield, Terminal, StepForward,
  Zap, History, BookOpen, Target, Brain,
  Plus, Trash2, ArrowUp, ArrowDown, Layers, PenLine, Save, X,
} from 'lucide-react'
import type { Project } from '../types'

// ── Interfaces ────────────────────────────────────────────────────────────────

interface PlaybookStep {
  name: string
  scan_type: string
  cmd_template: string
  description: string
  conditional: boolean
  trigger_ports: number[]
  timeout: number
  parallel: boolean
}

interface Playbook {
  id: string
  name: string
  description: string
  is_builtin: boolean
  step_count: number
  steps: PlaybookStep[]
  created_at: string
}

interface PlaybookRun {
  id: string
  playbook_id: string
  playbook_name: string
  project_id: string
  target_id: string
  target_host: string
  mode: string
  status: string
  current_step: string
  started_at: string | null
  completed_at: string | null
  created_at: string
}

interface StepState {
  step: number
  tool: string
  status: 'pending' | 'running' | 'completed' | 'skipped' | 'failed'
  findings: number
  reason?: string
  parallel: boolean
}

interface PausedState {
  step: number
  tool: string
  description: string
  parallel: boolean
  groupSteps: { tool: string; description: string }[]
}

interface TargetOption {
  id: string
  hostname_or_ip: string
}

// Builder step — mirrors PlaybookStep but all fields are strings during editing
interface BuilderStep {
  name: string
  scan_type: string
  cmd_template: string
  description: string
  conditional: boolean
  trigger_ports_raw: string   // comma-separated string
  timeout: number
  parallel: boolean
}

const BLANK_STEP: BuilderStep = {
  name: '', scan_type: '', cmd_template: '', description: '',
  conditional: false, trigger_ports_raw: '', timeout: 300, parallel: false,
}

// ── Display maps ──────────────────────────────────────────────────────────────

const STATUS_BG: Record<string, string> = {
  completed: 'bg-green-500/10 border-green-500/30 text-green-400',
  running:   'bg-blue-500/10 border-blue-500/30 text-blue-400',
  paused:    'bg-amber-500/10 border-amber-500/30 text-amber-400',
  failed:    'bg-red-500/10 border-red-500/30 text-red-400',
  pending:   'bg-slate-500/10 border-slate-500/20 text-slate-400',
  skipped:   'bg-slate-700/20 border-slate-700/20 text-slate-500',
}

const STEP_ICONS: Record<string, React.ReactNode> = {
  completed: <CheckCircle size={14} className="text-green-400" />,
  running:   <Loader size={14} className="animate-spin text-blue-400" />,
  skipped:   <SkipForward size={14} className="text-slate-500" />,
  failed:    <XCircle size={14} className="text-red-400" />,
  pending:   <Clock size={14} className="text-slate-600" />,
}

// Group colours cycle through a palette so adjacent groups look distinct
const GROUP_COLORS = [
  'border-l-cyan-500/40',
  'border-l-purple-500/40',
  'border-l-emerald-500/40',
  'border-l-amber-500/40',
  'border-l-pink-500/40',
]

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Compute execution groups from a flat step list (same logic as backend). */
function buildGroups<T extends { parallel: boolean }>(steps: T[]): number[][] {
  const groups: number[][] = []
  steps.forEach((s, i) => {
    if (s.parallel && groups.length > 0) groups[groups.length - 1].push(i)
    else groups.push([i])
  })
  return groups
}

/** Map each step index → its group index. */
function stepGroupMap(groups: number[][]): Record<number, number> {
  const m: Record<number, number> = {}
  groups.forEach((g, gi) => g.forEach(si => (m[si] = gi)))
  return m
}

export default function Playbooks() {
  const [view, setView] = useState<'library' | 'run' | 'history' | 'builder'>('library')
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [runs, setRuns] = useState<PlaybookRun[]>([])
  const [projects, setProjects] = useState<Project[]>([])
  const [targets, setTargets] = useState<TargetOption[]>([])

  // ── Run wizard state ────────────────────────────────────────────────────────
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null)
  const [selectedProject, setSelectedProject] = useState('')
  const [selectedTarget, setSelectedTarget] = useState('')
  const [mode, setMode] = useState<'auto' | 'step_through'>('auto')
  const [useAi, setUseAi] = useState(false)
  const [showWizard, setShowWizard] = useState(false)
  const [starting, setStarting] = useState(false)

  // ── Active run state ────────────────────────────────────────────────────────
  const [activeRunId, setActiveRunId] = useState<string | null>(null)
  const [runStatus, setRunStatus] = useState<string>('pending')
  const [steps, setSteps] = useState<StepState[]>([])
  const [totalFindings, setTotalFindings] = useState(0)
  const [currentTool, setCurrentTool] = useState('')
  const [paused, setPaused] = useState(false)
  const [pausedState, setPausedState] = useState<PausedState | null>(null)
  const [stepInsights, setStepInsights] = useState<Record<number, string>>({})
  const [lastInsight, setLastInsight] = useState('')
  const termRef = useRef<HTMLDivElement>(null)
  const [termLines, setTermLines] = useState<string[]>([])
  const wsRef = useRef<WebSocket | null>(null)

  // ── Builder state ───────────────────────────────────────────────────────────
  const [builderName, setBuilderName] = useState('')
  const [builderDesc, setBuilderDesc] = useState('')
  const [builderSteps, setBuilderSteps] = useState<BuilderStep[]>([])
  const [editingIdx, setEditingIdx] = useState<number | null>(null)
  const [saving, setSaving] = useState(false)
  const [editingPlaybookId, setEditingPlaybookId] = useState<string | null>(null)
  const [builderError, setBuilderError] = useState('')

  // ── Derived ─────────────────────────────────────────────────────────────────
  const runGroups = useMemo(() => buildGroups(steps), [steps])
  const builderGroups = useMemo(() => buildGroups(builderSteps), [builderSteps])

  // ── Lifecycle ───────────────────────────────────────────────────────────────
  useEffect(() => { loadPlaybooks(); loadRuns(); loadProjects() }, [])
  useEffect(() => { if (selectedProject) loadTargets(selectedProject); else setTargets([]) }, [selectedProject])
  useEffect(() => { if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight }, [termLines])

  // ── Data loaders ─────────────────────────────────────────────────────────────
  async function loadPlaybooks() {
    const res = await fetch('/api/v1/playbooks')
    if (res.ok) setPlaybooks(await res.json())
  }
  async function loadRuns() {
    const res = await fetch('/api/v1/playbooks/runs')
    if (res.ok) setRuns(await res.json())
  }
  async function loadProjects() {
    const res = await fetch('/api/v1/projects')
    if (res.ok) setProjects(await res.json())
  }
  async function loadTargets(projectId: string) {
    const res = await fetch(`/api/v1/projects/${projectId}/targets`)
    if (res.ok) setTargets(await res.json())
  }

  // ── Wizard ───────────────────────────────────────────────────────────────────
  function openWizard(pb: Playbook) {
    setSelectedPlaybook(pb)
    setSelectedProject('')
    setSelectedTarget('')
    setMode('auto')
    setUseAi(false)
    setShowWizard(true)
  }

  async function handleStartRun() {
    if (!selectedPlaybook || !selectedProject || !selectedTarget) return
    setStarting(true)
    try {
      const res = await fetch('/api/v1/playbooks/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          playbook_id: selectedPlaybook.id,
          project_id: selectedProject,
          target_id: selectedTarget,
          mode,
        }),
      })
      if (!res.ok) throw new Error('Failed to start run')
      const data = await res.json()
      setShowWizard(false)
      beginRun(data.run_id, selectedPlaybook, mode, useAi)
    } catch (err) {
      console.error(err)
    } finally {
      setStarting(false)
    }
  }

  // ── Run execution ─────────────────────────────────────────────────────────────
  function beginRun(runId: string, pb: Playbook, _runMode: string, aiEnabled = false) {
    setActiveRunId(runId)
    setRunStatus('running')
    setTermLines([])
    setTotalFindings(0)
    setPaused(false)
    setPausedState(null)
    setCurrentTool('')
    setStepInsights({})
    setLastInsight('')
    setSteps(pb.steps.map((s, i) => ({
      step: i, tool: s.name, status: 'pending', findings: 0, parallel: s.parallel ?? false,
    })))
    setView('run')

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(
      `${proto}://${window.location.host}/ws/playbooks/${runId}${aiEnabled ? '?use_ai=true' : ''}`
    )
    wsRef.current = ws
    ws.onmessage = (evt) => handleWsMessage(JSON.parse(evt.data))
    ws.onerror = () => appendLine('\x1b[31m[WebSocket error]\x1b[0m')
    ws.onclose = () => appendLine('\x1b[90m[connection closed]\x1b[0m')
  }

  function appendLine(text: string) {
    setTermLines(prev => [...prev, text])
  }

  function handleWsMessage(msg: any) {
    switch (msg.type) {
      case 'run_start':
        appendLine(`\x1b[36m[▶] Playbook started — ${msg.total_steps} steps\x1b[0m`)
        break
      case 'step_start':
        setCurrentTool(msg.tool)
        setSteps(prev => prev.map(s => s.step === msg.step ? { ...s, status: 'running' } : s))
        appendLine(`\n\x1b[33m[${msg.step + 1}] ${msg.tool}\x1b[0m — ${msg.description}`)
        appendLine(`\x1b[90m$ ${msg.cmd}\x1b[0m`)
        break
      case 'step_done':
        setSteps(prev => prev.map(s => s.step === msg.step ? { ...s, status: 'completed', findings: msg.findings } : s))
        setTotalFindings(prev => prev + (msg.findings || 0))
        appendLine(`\x1b[32m[✓] ${msg.tool} done — ${msg.findings} finding(s)\x1b[0m`)
        break
      case 'step_skip':
        setSteps(prev => prev.map(s => s.step === msg.step ? { ...s, status: 'skipped', reason: msg.reason } : s))
        appendLine(`\x1b[90m[⤳] ${msg.tool} skipped: ${msg.reason}\x1b[0m`)
        break
      case 'paused': {
        const gs: { tool: string; description: string }[] = msg.group_steps ?? [{ tool: msg.tool, description: msg.description }]
        setPaused(true)
        setPausedState({
          step: msg.step, tool: msg.tool, description: msg.description,
          parallel: msg.parallel ?? false, groupSteps: gs,
        })
        setRunStatus('paused')
        const label = msg.parallel ? `parallel group (${gs.length} tools)` : msg.tool
        appendLine(`\n\x1b[33m[⏸] Paused before: ${label}\x1b[0m`)
        break
      }
      case 'stdout':
        appendLine(msg.data.replace(/\n$/, ''))
        break
      case 'step_ai':
        setStepInsights(prev => ({ ...prev, [msg.step]: msg.insight }))
        setLastInsight(msg.insight)
        appendLine(`\x1b[35m[AI] ${msg.insight}\x1b[0m`)
        break
      case 'complete':
        setRunStatus('completed')
        setCurrentTool('')
        setTotalFindings(msg.total_findings)
        appendLine(`\n\x1b[32m[✓] Playbook complete — ${msg.total_findings} total findings\x1b[0m`)
        loadRuns()
        break
      case 'error':
        setRunStatus('failed')
        appendLine(`\x1b[31m[✗] ${msg.data}\x1b[0m`)
        break
    }
  }

  function handleContinue() {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'continue' }))
      setPaused(false)
      setPausedState(null)
      setRunStatus('running')
    }
  }

  // ── Builder helpers ───────────────────────────────────────────────────────────
  function resetBuilder() {
    setBuilderName('')
    setBuilderDesc('')
    setBuilderSteps([])
    setEditingIdx(null)
    setEditingPlaybookId(null)
    setBuilderError('')
  }

  function loadPlaybookForEdit(pb: Playbook) {
    setBuilderName(pb.name)
    setBuilderDesc(pb.description)
    setBuilderSteps(pb.steps.map(s => ({
      name: s.name,
      scan_type: s.scan_type,
      cmd_template: s.cmd_template,
      description: s.description,
      conditional: s.conditional,
      trigger_ports_raw: s.trigger_ports.join(','),
      timeout: s.timeout,
      parallel: s.parallel ?? false,
    })))
    setEditingIdx(null)
    setEditingPlaybookId(pb.id)
    setBuilderError('')
    setView('builder')
  }

  function addStep() {
    const newStep = { ...BLANK_STEP }
    setBuilderSteps(prev => [...prev, newStep])
    setEditingIdx(builderSteps.length)
  }

  function removeStep(i: number) {
    setBuilderSteps(prev => {
      const next = prev.filter((_, idx) => idx !== i)
      // If the removed step was the anchor of a parallel group, the next step
      // (which had parallel=true) would become the new anchor — unset its parallel flag.
      if (next[i]?.parallel && (i === 0 || !next[i - 1])) {
        next[i] = { ...next[i], parallel: false }
      }
      return next
    })
    if (editingIdx === i) setEditingIdx(null)
    else if (editingIdx !== null && editingIdx > i) setEditingIdx(editingIdx - 1)
  }

  function moveStep(i: number, dir: -1 | 1) {
    const j = i + dir
    if (j < 0 || j >= builderSteps.length) return
    setBuilderSteps(prev => {
      const next = [...prev]
      ;[next[i], next[j]] = [next[j], next[i]]
      return next
    })
    if (editingIdx === i) setEditingIdx(j)
    else if (editingIdx === j) setEditingIdx(i)
  }

  function updateStep(i: number, patch: Partial<BuilderStep>) {
    setBuilderSteps(prev => prev.map((s, idx) => idx === i ? { ...s, ...patch } : s))
  }

  function toApiStep(s: BuilderStep) {
    const ports = s.trigger_ports_raw
      .split(',')
      .map(p => parseInt(p.trim(), 10))
      .filter(p => !isNaN(p))
    return {
      name: s.name.trim(),
      scan_type: s.scan_type.trim() || s.name.trim(),
      cmd_template: s.cmd_template.trim(),
      description: s.description.trim(),
      conditional: s.conditional,
      trigger_ports: ports,
      timeout: s.timeout,
      parallel: s.parallel,
    }
  }

  async function handleSavePlaybook() {
    setBuilderError('')
    if (!builderName.trim()) { setBuilderError('Playbook name is required.'); return }
    if (builderSteps.length === 0) { setBuilderError('Add at least one step.'); return }
    for (const s of builderSteps) {
      if (!s.name.trim() || !s.cmd_template.trim()) {
        setBuilderError('Each step needs a tool name and command template.'); return
      }
    }
    setSaving(true)
    try {
      const body = {
        name: builderName.trim(),
        description: builderDesc.trim(),
        steps: builderSteps.map(toApiStep),
      }
      const url = editingPlaybookId
        ? `/api/v1/playbooks/${editingPlaybookId}`
        : '/api/v1/playbooks'
      const res = await fetch(url, {
        method: editingPlaybookId ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!res.ok) throw new Error(await res.text())
      await loadPlaybooks()
      resetBuilder()
      setView('library')
    } catch (err: any) {
      setBuilderError(err.message ?? 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  async function handleDeletePlaybook(id: string) {
    if (!confirm('Delete this playbook?')) return
    await fetch(`/api/v1/playbooks/${id}`, { method: 'DELETE' })
    loadPlaybooks()
  }

  function formatDate(s: string | null) {
    if (!s || s === 'None') return '—'
    try { return new Date(s).toLocaleString() } catch { return s }
  }

  // ── Render ────────────────────────────────────────────────────────────────────
  return (
    <div className="p-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <BookOpen size={22} className="text-cyan-400" />
            <h1 className="text-2xl font-semibold text-white">Playbooks</h1>
          </div>
          <p className="text-sm text-slate-400 mt-1">Pre-defined and custom tool chains with parallel execution support</p>
        </div>
        {view === 'library' && (
          <button
            onClick={() => { resetBuilder(); setView('builder') }}
            className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white bg-blue-600 hover:bg-blue-500 transition-colors"
          >
            <Plus size={14} /> New Playbook
          </button>
        )}
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 glass rounded-lg p-1 w-fit">
        {[
          { id: 'library', label: 'Library',     icon: <BookOpen size={13} /> },
          { id: 'run',     label: 'Active Run',  icon: <Terminal size={13} /> },
          { id: 'history', label: 'Run History', icon: <History size={13} /> },
          { id: 'builder', label: 'Builder',     icon: <PenLine size={13} /> },
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setView(tab.id as any)}
            className={`flex items-center gap-1.5 px-4 py-1.5 rounded text-sm font-medium transition-colors ${
              view === tab.id ? 'bg-blue-600 text-white shadow-glow-blue' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {tab.icon} {tab.label}
            {tab.id === 'run' && activeRunId && (
              <span className={`w-1.5 h-1.5 rounded-full ml-0.5 ${
                runStatus === 'running' ? 'bg-blue-400 animate-pulse' :
                runStatus === 'paused' ? 'bg-amber-400' :
                runStatus === 'completed' ? 'bg-green-400' : 'bg-slate-500'
              }`} />
            )}
          </button>
        ))}
      </div>

      {/* ── Library ─────────────────────────────────────────────────────────────── */}
      {view === 'library' && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {playbooks.map(pb => {
            const pbGroups = buildGroups(pb.steps)
            const parallelCount = pbGroups.filter(g => g.length > 1).length
            return (
              <div key={pb.id} className="glass glass-hover rounded-xl p-5 space-y-3 flex flex-col">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Shield size={15} className="text-cyan-400 shrink-0" />
                      <h3 className="text-sm font-semibold text-white">{pb.name}</h3>
                      {pb.is_builtin && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded text-cyan-400 border border-cyan-500/30" style={{ background: 'rgba(6,182,212,0.08)' }}>
                          built-in
                        </span>
                      )}
                      {parallelCount > 0 && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded text-purple-400 border border-purple-500/30 flex items-center gap-1" style={{ background: 'rgba(168,85,247,0.08)' }}>
                          <Layers size={9} /> {parallelCount} parallel
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-400 mt-1">{pb.description}</p>
                  </div>
                  {!pb.is_builtin && (
                    <div className="flex gap-1 shrink-0">
                      <button onClick={() => loadPlaybookForEdit(pb)} title="Edit" className="text-slate-500 hover:text-cyan-400 transition-colors p-1">
                        <PenLine size={13} />
                      </button>
                      <button onClick={() => handleDeletePlaybook(pb.id)} title="Delete" className="text-slate-500 hover:text-red-400 transition-colors p-1">
                        <Trash2 size={13} />
                      </button>
                    </div>
                  )}
                </div>

                {/* Step list with parallel indicators */}
                <div className="flex-1 space-y-0.5">
                  {(() => {
                    const gs = buildGroups(pb.steps)
                    const gm = stepGroupMap(gs)
                    return pb.steps.map((step, i) => {
                      const gi = gm[i]
                      const isParGroup = gs[gi].length > 1
                      return (
                        <div key={i} className={`flex items-center gap-2 text-xs text-slate-400 pl-1 ${isParGroup ? 'border-l-2 border-purple-500/30 ml-0' : ''}`}>
                          <span className="text-slate-600 font-mono w-4 text-right shrink-0">{i + 1}</span>
                          {step.parallel
                            ? <span className="text-purple-500/60 shrink-0">∥</span>
                            : <ChevronRight size={10} className="text-slate-600 shrink-0" />}
                          <span className="font-mono text-slate-300">{step.name}</span>
                          {step.conditional && <span className="text-[10px] text-slate-600 italic shrink-0">cond.</span>}
                        </div>
                      )
                    })
                  })()}
                </div>

                <button
                  onClick={() => openWizard(pb)}
                  className="w-full flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-medium text-white transition-all bg-blue-600 hover:bg-blue-500 hover:shadow-glow-blue"
                >
                  <Play size={13} /> Run Playbook
                </button>
              </div>
            )
          })}
        </div>
      )}

      {/* ── Active Run ──────────────────────────────────────────────────────────── */}
      {view === 'run' && (
        <div className="space-y-4">
          {!activeRunId ? (
            <div className="text-center glass rounded-xl py-16 text-slate-400">
              <Terminal size={40} className="mx-auto mb-3 opacity-30 text-cyan-500" />
              <p className="text-sm">No active run. Select a playbook from the Library tab and click Run.</p>
            </div>
          ) : (
            <div className="grid grid-cols-[300px_1fr] gap-4 h-[calc(100vh-240px)]">
              {/* Step progress panel */}
              <div className="glass rounded-xl p-4 space-y-2 overflow-y-auto">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Steps</span>
                  <span className={`text-xs px-2 py-0.5 rounded border font-medium capitalize ${STATUS_BG[runStatus] || STATUS_BG.pending}`}>
                    {runStatus}
                  </span>
                </div>

                {(() => {
                  // Render steps grouped, with parallel group visual brackets
                  return runGroups.map((group, gi) => {
                    const isParGroup = group.length > 1
                    const color = GROUP_COLORS[gi % GROUP_COLORS.length]
                    return (
                      <div key={gi} className={isParGroup ? `border-l-2 ${color} pl-1.5 space-y-1` : 'space-y-1'}>
                        {isParGroup && (
                          <div className="flex items-center gap-1 mb-0.5">
                            <Layers size={9} className="text-purple-400" />
                            <span className="text-[9px] text-purple-400 font-semibold uppercase tracking-wider">parallel</span>
                          </div>
                        )}
                        {group.map(si => {
                          const s = steps[si]
                          if (!s) return null
                          return (
                            <div key={si} className={`rounded-lg px-3 py-2 border transition-all ${
                              s.status === 'running'    ? 'border-blue-500/40 bg-blue-500/5' :
                              s.status === 'completed'  ? 'border-green-500/20 bg-green-500/5' :
                              s.status === 'skipped'    ? 'border-slate-700/20' :
                              'border-cyan-900/10'
                            }`}>
                              <div className="flex items-center gap-2">
                                {STEP_ICONS[s.status] || STEP_ICONS.pending}
                                <span className={`font-mono text-sm font-medium ${
                                  s.status === 'completed' ? 'text-green-300' :
                                  s.status === 'running'   ? 'text-blue-300' :
                                  s.status === 'skipped'   ? 'text-slate-600' :
                                  'text-slate-300'
                                }`}>{s.tool}</span>
                                {s.findings > 0 && (
                                  <span className="ml-auto text-xs text-amber-400 font-mono">{s.findings}f</span>
                                )}
                              </div>
                              {s.reason && <p className="text-[10px] text-slate-600 mt-0.5 pl-5">{s.reason}</p>}
                              {stepInsights[s.step] && s.status === 'completed' && (
                                <div className="mt-1.5 ml-5 flex items-start gap-1.5 border-l-2 border-purple-500/30 pl-2">
                                  <Brain size={9} className="text-purple-400 mt-0.5 shrink-0" />
                                  <p className="text-[10px] text-purple-300 leading-relaxed">{stepInsights[s.step]}</p>
                                </div>
                              )}
                            </div>
                          )
                        })}
                      </div>
                    )
                  })
                })()}

                {runStatus === 'completed' && (
                  <div className="rounded-lg px-3 py-2 border border-green-500/30 bg-green-500/5 text-center mt-2">
                    <div className="text-sm font-semibold text-green-300">{totalFindings} findings</div>
                    <div className="text-[10px] text-green-600">total discovered</div>
                  </div>
                )}

                {/* Step-through pause card */}
                {paused && pausedState && (
                  <div className="rounded-lg px-3 py-3 border border-amber-500/30 space-y-2 mt-2" style={{ background: 'rgba(245,158,11,0.05)' }}>
                    {lastInsight && (
                      <div className="rounded border border-purple-500/20 px-2.5 py-2 space-y-1" style={{ background: 'rgba(168,85,247,0.06)' }}>
                        <div className="flex items-center gap-1.5">
                          <Brain size={10} className="text-purple-400" />
                          <span className="text-[10px] font-semibold text-purple-400 uppercase tracking-wider">AI Analysis</span>
                        </div>
                        <p className="text-[10px] text-purple-200 leading-relaxed">{lastInsight}</p>
                      </div>
                    )}
                    {pausedState.parallel ? (
                      <>
                        <div className="flex items-center gap-1.5 text-xs text-amber-300 font-medium">
                          <Layers size={11} /> Next: parallel group ({pausedState.groupSteps.length} tools)
                        </div>
                        <div className="space-y-0.5 pl-1">
                          {pausedState.groupSteps.map((gs, i) => (
                            <div key={i} className="flex items-center gap-1.5 text-[10px] text-slate-400">
                              <span className="text-purple-500">∥</span>
                              <span className="font-mono text-slate-300">{gs.tool}</span>
                              <span className="text-slate-500 truncate">{gs.description}</span>
                            </div>
                          ))}
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="text-xs text-amber-300 font-medium">Next: {pausedState.tool}</div>
                        <div className="text-[10px] text-slate-400">{pausedState.description}</div>
                      </>
                    )}
                    <button
                      onClick={handleContinue}
                      className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded text-xs font-medium text-white bg-amber-600 hover:bg-amber-500 transition-colors"
                    >
                      <StepForward size={12} /> Continue
                    </button>
                  </div>
                )}
              </div>

              {/* Terminal */}
              <div
                ref={termRef}
                className="glass rounded-xl p-4 font-mono text-xs text-slate-300 overflow-y-auto leading-relaxed"
                style={{ background: '#030508' }}
              >
                {termLines.map((line, i) => (
                  <div key={i} className="whitespace-pre-wrap break-all"
                    dangerouslySetInnerHTML={{ __html: ansiToHtml(line) }}
                  />
                ))}
                {runStatus === 'running' && currentTool && (
                  <div className="flex items-center gap-2 text-blue-400 mt-1">
                    <Loader size={10} className="animate-spin" />
                    <span>{currentTool} running...</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── History ──────────────────────────────────────────────────────────────── */}
      {view === 'history' && (
        <div className="space-y-3">
          {runs.length === 0 ? (
            <div className="text-center glass rounded-xl py-16 text-slate-400">
              <History size={40} className="mx-auto mb-3 opacity-30" />
              <p className="text-sm">No runs yet.</p>
            </div>
          ) : (
            <div className="rounded-xl overflow-hidden border border-cyan-900/20">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-cyan-900/20 text-left" style={{ background: '#090d14' }}>
                    {['Playbook', 'Target', 'Mode', 'Status', 'Started', 'Completed'].map(h => (
                      <th key={h} className="px-4 py-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {runs.map(run => (
                    <tr key={run.id} className="border-b border-cyan-900/10 last:border-0 hover:bg-cyan-950/10 transition-colors">
                      <td className="px-4 py-3 text-slate-200 font-medium">{run.playbook_name}</td>
                      <td className="px-4 py-3 font-mono text-slate-300 text-xs">{run.target_host}</td>
                      <td className="px-4 py-3">
                        <span className="flex items-center gap-1 text-xs text-slate-400">
                          {run.mode === 'step_through' ? <StepForward size={11} /> : <Zap size={11} />}
                          {run.mode === 'step_through' ? 'Step-through' : 'Auto'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded border font-medium capitalize ${STATUS_BG[run.status] || STATUS_BG.pending}`}>
                          {run.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">{formatDate(run.started_at)}</td>
                      <td className="px-4 py-3 text-xs text-slate-400">{formatDate(run.completed_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Builder ──────────────────────────────────────────────────────────────── */}
      {view === 'builder' && (
        <div className="space-y-4">
          {/* Metadata */}
          <div className="glass rounded-xl p-5 space-y-3">
            <div className="flex items-center gap-2 mb-1">
              <PenLine size={15} className="text-cyan-400" />
              <h2 className="text-sm font-semibold text-white">
                {editingPlaybookId ? 'Edit Playbook' : 'New Playbook'}
              </h2>
              {editingPlaybookId && (
                <button onClick={resetBuilder} className="ml-auto text-xs text-slate-500 hover:text-slate-300 flex items-center gap-1">
                  <X size={11} /> Clear
                </button>
              )}
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Name *</label>
                <input
                  value={builderName}
                  onChange={e => setBuilderName(e.target.value)}
                  placeholder="e.g. Custom Web Audit"
                  className="mt-1 w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                  style={{ background: '#090d14' }}
                />
              </div>
              <div>
                <label className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Description</label>
                <input
                  value={builderDesc}
                  onChange={e => setBuilderDesc(e.target.value)}
                  placeholder="What does this playbook do?"
                  className="mt-1 w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                  style={{ background: '#090d14' }}
                />
              </div>
            </div>
          </div>

          <div className={`grid gap-4 ${editingIdx !== null ? 'grid-cols-[1fr_360px]' : 'grid-cols-1'}`}>
            {/* Step list */}
            <div className="glass rounded-xl p-4 space-y-2">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Steps ({builderSteps.length})
                </span>
                <span className="text-[10px] text-slate-500">
                  Parallel steps run simultaneously within their group
                </span>
              </div>

              {builderSteps.length === 0 && (
                <div className="text-center py-10 text-slate-600 text-sm">
                  No steps yet. Click "Add Step" to begin.
                </div>
              )}

              {(() => {
                return builderGroups.map((group, gi) => {
                  const isParGroup = group.length > 1
                  const color = GROUP_COLORS[gi % GROUP_COLORS.length]
                  return (
                    <div key={gi} className={isParGroup ? `border-l-2 ${color} pl-2 space-y-1` : 'space-y-1'}>
                      {isParGroup && (
                        <div className="flex items-center gap-1 mb-0.5 pt-0.5">
                          <Layers size={9} className="text-purple-400" />
                          <span className="text-[9px] text-purple-400 font-semibold uppercase tracking-wider">
                            parallel group — runs simultaneously
                          </span>
                        </div>
                      )}
                      {group.map(si => {
                        const s = builderSteps[si]
                        const isEditing = editingIdx === si
                        return (
                          <div
                            key={si}
                            onClick={() => setEditingIdx(si)}
                            className={`rounded-lg border px-3 py-2.5 cursor-pointer transition-all ${
                              isEditing
                                ? 'border-cyan-500/50 bg-cyan-500/5'
                                : 'border-cyan-900/20 hover:border-cyan-900/40'
                            }`}
                          >
                            <div className="flex items-center gap-2">
                              {/* Order buttons */}
                              <div className="flex flex-col gap-0.5 shrink-0" onClick={e => e.stopPropagation()}>
                                <button onClick={() => moveStep(si, -1)} disabled={si === 0}
                                  className="text-slate-600 hover:text-slate-300 disabled:opacity-20 transition-colors">
                                  <ArrowUp size={11} />
                                </button>
                                <button onClick={() => moveStep(si, 1)} disabled={si === builderSteps.length - 1}
                                  className="text-slate-600 hover:text-slate-300 disabled:opacity-20 transition-colors">
                                  <ArrowDown size={11} />
                                </button>
                              </div>

                              <span className="text-slate-600 font-mono text-xs w-5 text-right shrink-0">{si + 1}</span>

                              {s.parallel
                                ? <span className="text-purple-400 text-xs font-mono shrink-0" title="Runs in parallel with previous step">∥</span>
                                : <ChevronRight size={10} className="text-slate-600 shrink-0" />
                              }

                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className={`font-mono text-sm font-medium ${s.name ? 'text-slate-200' : 'text-slate-600'}`}>
                                    {s.name || 'unnamed'}
                                  </span>
                                  {s.conditional && (
                                    <span className="text-[10px] text-slate-600 italic">cond.</span>
                                  )}
                                </div>
                                {s.description && (
                                  <p className="text-[10px] text-slate-500 truncate">{s.description}</p>
                                )}
                              </div>

                              {/* Parallel pill */}
                              {si > 0 && (
                                <button
                                  onClick={e => { e.stopPropagation(); updateStep(si, { parallel: !s.parallel }) }}
                                  className={`shrink-0 px-2 py-0.5 rounded-full text-[10px] font-semibold border transition-all ${
                                    s.parallel
                                      ? 'border-purple-500/50 text-purple-300 bg-purple-500/10'
                                      : 'border-slate-700/40 text-slate-600 hover:border-slate-600/60 hover:text-slate-400'
                                  }`}
                                  title={s.parallel ? 'Running in parallel — click to make sequential' : 'Click to run in parallel with previous step'}
                                >
                                  {s.parallel ? '∥ parallel' : '→ seq'}
                                </button>
                              )}

                              <button
                                onClick={e => { e.stopPropagation(); removeStep(si) }}
                                className="text-slate-600 hover:text-red-400 transition-colors shrink-0 p-0.5"
                              >
                                <Trash2 size={12} />
                              </button>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  )
                })
              })()}

              <button
                onClick={addStep}
                className="w-full mt-2 flex items-center justify-center gap-2 py-2 rounded-lg border border-dashed border-cyan-900/30 text-sm text-slate-500 hover:text-slate-300 hover:border-cyan-700/40 transition-colors"
              >
                <Plus size={13} /> Add Step
              </button>
            </div>

            {/* Step editor */}
            {editingIdx !== null && builderSteps[editingIdx] && (() => {
              const s = builderSteps[editingIdx]
              return (
                <div className="glass rounded-xl p-4 space-y-3 self-start sticky top-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300">
                      Edit Step {editingIdx + 1}
                    </span>
                    <button onClick={() => setEditingIdx(null)} className="text-slate-600 hover:text-slate-300">
                      <X size={13} />
                    </button>
                  </div>

                  {[
                    { label: 'Tool Name *', key: 'name', placeholder: 'e.g. nmap', hint: 'Must match the executable name (shutil.which check)' },
                    { label: 'Scan Type', key: 'scan_type', placeholder: 'e.g. nmap (defaults to tool name)' },
                    { label: 'Description', key: 'description', placeholder: 'Human-readable step description' },
                  ].map(({ label, key, placeholder, hint }) => (
                    <div key={key}>
                      <label className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">{label}</label>
                      {hint && <p className="text-[9px] text-slate-600 mt-0.5">{hint}</p>}
                      <input
                        value={(s as any)[key]}
                        onChange={e => updateStep(editingIdx, { [key]: e.target.value })}
                        placeholder={placeholder}
                        className="mt-1 w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                        style={{ background: '#090d14' }}
                      />
                    </div>
                  ))}

                  <div>
                    <label className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Command Template *</label>
                    <p className="text-[9px] text-slate-600 mt-0.5">Use <code className="text-cyan-500">&#123;target&#125;</code> as the target placeholder</p>
                    <textarea
                      value={s.cmd_template}
                      onChange={e => updateStep(editingIdx, { cmd_template: e.target.value })}
                      placeholder="nmap -sV {target}"
                      rows={2}
                      className="mt-1 w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none font-mono resize-none"
                      style={{ background: '#090d14' }}
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Timeout (s)</label>
                      <input
                        type="number"
                        value={s.timeout}
                        onChange={e => updateStep(editingIdx, { timeout: parseInt(e.target.value, 10) || 300 })}
                        className="mt-1 w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                        style={{ background: '#090d14' }}
                      />
                    </div>
                    <div>
                      <label className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Trigger Ports</label>
                      <input
                        value={s.trigger_ports_raw}
                        onChange={e => updateStep(editingIdx, { trigger_ports_raw: e.target.value })}
                        placeholder="80,443 (blank = always)"
                        className="mt-1 w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                        style={{ background: '#090d14' }}
                      />
                    </div>
                  </div>

                  <div className="flex items-center justify-between rounded-lg border border-cyan-900/20 px-3 py-2.5">
                    <div>
                      <div className="text-xs font-medium text-slate-300">Conditional</div>
                      <div className="text-[10px] text-slate-500">Only run if trigger ports are open</div>
                    </div>
                    <button
                      onClick={() => updateStep(editingIdx, { conditional: !s.conditional })}
                      className={`relative w-9 h-5 rounded-full transition-colors ${s.conditional ? 'bg-cyan-600' : 'bg-slate-700'}`}
                    >
                      <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${s.conditional ? 'translate-x-4' : 'translate-x-0'}`} />
                    </button>
                  </div>

                  {editingIdx > 0 && (
                    <div className="flex items-center justify-between rounded-lg border border-cyan-900/20 px-3 py-2.5">
                      <div>
                        <div className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                          <Layers size={11} className="text-purple-400" /> Run in parallel
                        </div>
                        <div className="text-[10px] text-slate-500">Execute alongside the previous step's group</div>
                      </div>
                      <button
                        onClick={() => updateStep(editingIdx, { parallel: !s.parallel })}
                        className={`relative w-9 h-5 rounded-full transition-colors ${s.parallel ? 'bg-purple-600' : 'bg-slate-700'}`}
                      >
                        <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${s.parallel ? 'translate-x-4' : 'translate-x-0'}`} />
                      </button>
                    </div>
                  )}
                </div>
              )
            })()}
          </div>

          {/* Save bar */}
          {builderError && (
            <div className="rounded-lg px-4 py-2.5 border border-red-500/30 bg-red-500/5 text-sm text-red-300">
              {builderError}
            </div>
          )}
          <div className="flex items-center gap-3">
            <button
              onClick={() => { resetBuilder(); setView('library') }}
              className="px-4 py-2 rounded-lg text-sm text-slate-400 glass glass-hover transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSavePlaybook}
              disabled={saving}
              className="flex items-center gap-2 px-6 py-2 rounded-lg text-sm font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 transition-all"
            >
              {saving ? <Loader size={13} className="animate-spin" /> : <Save size={13} />}
              {editingPlaybookId ? 'Save Changes' : 'Create Playbook'}
            </button>
          </div>
        </div>
      )}

      {/* ── Run Wizard Modal ──────────────────────────────────────────────────────── */}
      {showWizard && selectedPlaybook && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)' }}>
          <div className="glass rounded-2xl p-6 w-full max-w-md space-y-5 border border-cyan-900/30">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <Play size={16} className="text-cyan-400" />
                <h2 className="text-lg font-semibold text-white">Run: {selectedPlaybook.name}</h2>
              </div>
              <p className="text-xs text-slate-400">{selectedPlaybook.description}</p>
            </div>

            {/* Steps preview */}
            <div className="rounded-lg px-4 py-3 space-y-1 border border-cyan-900/10 max-h-44 overflow-y-auto" style={{ background: '#090d14' }}>
              {(() => {
                const gs = buildGroups(selectedPlaybook.steps)
                const gm = stepGroupMap(gs)
                return selectedPlaybook.steps.map((s, i) => {
                  const isParGroup = gs[gm[i]].length > 1
                  return (
                    <div key={i} className={`flex items-center gap-2 text-xs text-slate-400 ${isParGroup ? 'pl-2 border-l border-purple-500/30' : ''}`}>
                      <span className="text-slate-600 font-mono w-4 text-right">{i + 1}</span>
                      {s.parallel ? <span className="text-purple-400">∥</span> : <ChevronRight size={10} className="text-slate-700" />}
                      <span className="font-mono text-slate-300">{s.name}</span>
                      <span className="text-slate-500 truncate">{s.description}</span>
                      {s.conditional && <span className="ml-auto text-[10px] text-slate-600 italic shrink-0">if ports</span>}
                    </div>
                  )
                })
              })()}
            </div>

            {/* Project */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Project</label>
              <select value={selectedProject} onChange={e => setSelectedProject(e.target.value)}
                className="w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none"
                style={{ background: '#090d14' }}>
                <option value="">Select project...</option>
                {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>

            {/* Target */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                <Target size={11} /> Target
              </label>
              <select value={selectedTarget} onChange={e => setSelectedTarget(e.target.value)}
                disabled={!selectedProject}
                className="w-full rounded-lg px-3 py-2 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none disabled:opacity-40"
                style={{ background: '#090d14' }}>
                <option value="">Select target...</option>
                {targets.map(t => <option key={t.id} value={t.id}>{t.hostname_or_ip}</option>)}
              </select>
            </div>

            {/* Execution mode */}
            <div className="space-y-2">
              <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Execution Mode</label>
              <div className="grid grid-cols-2 gap-2">
                {([
                  { value: 'auto',        label: 'Auto',         icon: <Zap size={13} />,       desc: 'All steps run automatically' },
                  { value: 'step_through',label: 'Step-through', icon: <StepForward size={13} />,desc: 'Pause before each group' },
                ] as const).map(opt => (
                  <button key={opt.value} onClick={() => setMode(opt.value)}
                    className={`rounded-xl px-3 py-3 text-left border transition-all ${mode === opt.value ? 'border-cyan-500/50 bg-cyan-500/10' : 'border-cyan-900/20 glass'}`}>
                    <div className={`flex items-center gap-1.5 text-sm font-semibold mb-0.5 ${mode === opt.value ? 'text-cyan-300' : 'text-slate-300'}`}>
                      {opt.icon} {opt.label}
                    </div>
                    <div className="text-[10px] text-slate-500">{opt.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* AI toggle */}
            <div className="flex items-center justify-between rounded-xl border border-cyan-900/20 px-4 py-3 glass">
              <div className="flex items-center gap-2.5">
                <Brain size={15} className={useAi ? 'text-purple-400' : 'text-slate-500'} />
                <div>
                  <div className="text-sm font-semibold text-slate-200">AI Assistance</div>
                  <div className="text-[10px] text-slate-500">Analyze each step's output (requires AI model in Settings)</div>
                </div>
              </div>
              <button onClick={() => setUseAi(v => !v)}
                className={`relative w-10 h-5 rounded-full transition-colors shrink-0 ${useAi ? 'bg-purple-600' : 'bg-slate-700'}`}>
                <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${useAi ? 'translate-x-5' : 'translate-x-0'}`} />
              </button>
            </div>

            <div className="flex gap-3 pt-1">
              <button onClick={() => setShowWizard(false)}
                className="flex-1 py-2 rounded-lg text-sm text-slate-400 glass glass-hover transition-colors">
                Cancel
              </button>
              <button onClick={handleStartRun}
                disabled={starting || !selectedProject || !selectedTarget}
                className="flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-sm font-semibold text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 transition-all">
                {starting ? <Loader size={13} className="animate-spin" /> : <Play size={13} />}
                Start Run
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// Minimal ANSI → HTML for the terminal
function ansiToHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/\x1b\[0m/g, '</span>')
    .replace(/\x1b\[(\d+)m/g, (_: string, code: string) => {
      const colorMap: Record<string, string> = {
        '30': '#475569', '31': '#ef4444', '32': '#22c55e', '33': '#f59e0b',
        '34': '#3b82f6', '35': '#a855f7', '36': '#06b6d4', '37': '#e2e8f0',
        '90': '#475569',
      }
      const color = colorMap[code]
      return color ? `<span style="color:${color}">` : ''
    })
}
