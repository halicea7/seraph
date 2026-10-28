import { useState, useEffect, useRef, useMemo, useCallback } from 'react'
import {
  Play,
  Loader, StepForward,
  Zap, Brain,
  Plus, Trash2, ArrowUp, ArrowDown, Layers, PenLine, Save, X, Search,
} from 'lucide-react'
import { load as yamlLoad } from 'js-yaml'
import Icon from '@/components/Icon'
import { getApiBase, wsUrl } from '@/lib/config'
import { useAppStore } from '@/stores/appStore'
import { useToast } from '@/contexts/ToastContext'

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
  mitre_techniques: string[]
  created_at: string
}

interface AttackTechniqueResult {
  technique_id: string
  name: string
  tactic: string
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

interface BuilderStep {
  name: string
  scan_type: string
  cmd_template: string
  description: string
  conditional: boolean
  trigger_ports_raw: string
  timeout: number
  parallel: boolean
}

const BLANK_STEP: BuilderStep = {
  name: '', scan_type: '', cmd_template: '', description: '',
  conditional: false, trigger_ports_raw: '', timeout: 300, parallel: false,
}

// ── Display maps ──────────────────────────────────────────────────────────────

const GROUP_PALETTE = ['var(--med)', '#a855f7', '#10b981', '#f59e0b', '#ec4899']

// ── Helpers ───────────────────────────────────────────────────────────────────

function buildGroups<T extends { parallel: boolean }>(steps: T[]): number[][] {
  const groups: number[][] = []
  steps.forEach((s, i) => {
    if (s.parallel && groups.length > 0) groups[groups.length - 1].push(i)
    else groups.push([i])
  })
  return groups
}

function stepGroupMap(groups: number[][]): Record<number, number> {
  const m: Record<number, number> = {}
  groups.forEach((g, gi) => g.forEach(si => (m[si] = gi)))
  return m
}

const rule = '1px solid var(--rule)'
const ruleStrong = '1px solid var(--rule-strong)'

// ── Sub-components ────────────────────────────────────────────────────────────

function PageHeader({ title, sub, right }: { title: string; sub: string; right?: React.ReactNode }) {
  return (
    <div style={{
      borderBottom: rule, padding: '18px var(--pad)',
      display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: 16, flexShrink: 0,
    }}>
      <div>
        <h1 className="mono" style={{ margin: 0, fontWeight: 500, fontSize: 22, letterSpacing: '-0.01em' }}>{title}</h1>
        <div style={{ color: 'var(--fg-3)', fontSize: 12, marginTop: 6 }}>{sub}</div>
      </div>
      {right && <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>{right}</div>}
    </div>
  )
}

function Pill({ tone, children }: { tone: 'pass' | 'warn' | 'info' | 'fail'; children: React.ReactNode }) {
  const map = {
    pass: { color: 'var(--ok)',   bg: 'rgba(84,175,97,0.1)',  border: 'rgba(84,175,97,0.35)' },
    warn: { color: 'var(--high)', bg: 'rgba(240,168,58,0.1)', border: 'rgba(240,168,58,0.35)' },
    info: { color: 'var(--fg-3)', bg: 'rgba(120,120,120,0.1)', border: 'rgba(120,120,120,0.3)' },
    fail: { color: 'var(--crit)', bg: 'rgba(232,64,64,0.1)',  border: 'rgba(232,64,64,0.35)' },
  }
  const s = map[tone]
  return (
    <span className="mono" style={{
      fontSize: 9, padding: '2px 7px', fontWeight: 700, textTransform: 'uppercase',
      letterSpacing: '0.08em', color: s.color, background: s.bg, border: `1px solid ${s.border}`,
    }}>{children}</span>
  )
}

const INPUT_STYLE: React.CSSProperties = {
  width: '100%', boxSizing: 'border-box',
  background: 'var(--bg)', border: ruleStrong, borderRadius: 3,
  padding: '6px 10px', fontSize: 12, color: 'var(--fg)',
  fontFamily: 'var(--font-sans)', outline: 'none',
}

function Toggle({ checked, onChange, accentColor = 'var(--accent)' }: { checked: boolean; onChange: () => void; accentColor?: string }) {
  return (
    <button
      onClick={onChange}
      style={{ position: 'relative', width: 36, height: 20, borderRadius: 10, border: 'none', cursor: 'pointer', background: checked ? accentColor : 'var(--rule-strong)', transition: 'background 0.2s', flexShrink: 0 }}
    >
      <span style={{ position: 'absolute', top: 2, left: checked ? 18 : 2, width: 16, height: 16, borderRadius: '50%', background: '#fff', transition: 'left 0.2s' }} />
    </button>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function Playbooks() {
  const toast = useToast()
  const importYamlRef = useRef<HTMLInputElement>(null)
  const [runsModalPb, setRunsModalPb] = useState<Playbook | null>(null)
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [runs, setRuns] = useState<PlaybookRun[]>([])
  const { selectedProject: sp } = useAppStore()
  const projectId = sp?.id ?? ''
  const [targets, setTargets] = useState<TargetOption[]>([])

  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null)
  const [selectedTarget, setSelectedTarget] = useState('')
  const [mode, setMode] = useState<'auto' | 'step_through'>('auto')
  const [useAi, setUseAi] = useState(false)
  const [showWizard, setShowWizard] = useState(false)
  const [starting, setStarting] = useState(false)

  const [activeRunId, setActiveRunId] = useState<string | null>(null)
  const [runStatus, setRunStatus] = useState<string>('pending')
  const [steps, setSteps] = useState<StepState[]>([])
  const [totalFindings, setTotalFindings] = useState(0)
  const [currentTool, setCurrentTool] = useState('')
  const [paused, setPaused] = useState(false)
  const [pausedState, setPausedState] = useState<PausedState | null>(null)
  const [, setStepInsights] = useState<Record<number, string>>({})
  const [lastInsight, setLastInsight] = useState('')
  const termRef = useRef<HTMLDivElement>(null)
  const [termLines, setTermLines] = useState<string[]>([])
  const wsRef = useRef<WebSocket | null>(null)

  // Builder state
  const [showBuilder, setShowBuilder] = useState(false)
  const [builderName, setBuilderName] = useState('')
  const [builderDesc, setBuilderDesc] = useState('')
  const [builderSteps, setBuilderSteps] = useState<BuilderStep[]>([])
  const [editingIdx, setEditingIdx] = useState<number | null>(null)
  const [saving, setSaving] = useState(false)
  const [editingPlaybookId, setEditingPlaybookId] = useState<string | null>(null)
  const [builderError, setBuilderError] = useState('')
  const [dragIdx, setDragIdx] = useState<number | null>(null)
  const [dragOverIdx, setDragOverIdx] = useState<number | null>(null)

  // Technique picker state
  const [builderTechniques, setBuilderTechniques] = useState<string[]>([])
  const [techQuery, setTechQuery] = useState('')
  const [techResults, setTechResults] = useState<AttackTechniqueResult[]>([])
  const [techSearching, setTechSearching] = useState(false)
  const techDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const builderGroups = useMemo(() => buildGroups(builderSteps), [builderSteps])

  useEffect(() => { loadPlaybooks(); loadRuns() }, [])
  useEffect(() => { if (projectId) loadTargets(projectId); else setTargets([]) }, [projectId])
  useEffect(() => { if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight }, [termLines])

  async function loadPlaybooks() {
    const res = await fetch(`${getApiBase()}/playbooks`)
    if (res.ok) setPlaybooks(await res.json())
  }
  async function loadRuns() {
    const res = await fetch(`${getApiBase()}/playbooks/runs`)
    if (res.ok) setRuns(await res.json())
  }
  async function loadTargets(pid: string) {
    const res = await fetch(`${getApiBase()}/projects/${pid}/targets`)
    if (res.ok) setTargets(await res.json())
  }

  function openWizard(pb: Playbook) {
    setSelectedPlaybook(pb)
    setSelectedTarget('')
    setMode('auto')
    setUseAi(false)
    setShowWizard(true)
  }

  async function handleStartRun() {
    if (!selectedPlaybook || !projectId || !selectedTarget) return
    setStarting(true)
    try {
      const res = await fetch(`${getApiBase()}/playbooks/runs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ playbook_id: selectedPlaybook.id, project_id: projectId, target_id: selectedTarget, mode }),
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
    setSteps(pb.steps.map((s, i) => ({ step: i, tool: s.name, status: 'pending', findings: 0, parallel: s.parallel ?? false })))

    const ws = new WebSocket(wsUrl(`/ws/playbooks/${runId}${aiEnabled ? '?use_ai=true' : ''}`))
    wsRef.current = ws
    ws.onmessage = (evt) => handleWsMessage(JSON.parse(evt.data))
    ws.onerror = () => appendLine('\x1b[31m[WebSocket error]\x1b[0m')
    ws.onclose = () => appendLine('\x1b[90m[connection closed]\x1b[0m')
  }

  function appendLine(text: string) { setTermLines(prev => [...prev, text]) }

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
        setPausedState({ step: msg.step, tool: msg.tool, description: msg.description, parallel: msg.parallel ?? false, groupSteps: gs })
        setRunStatus('paused')
        const label = msg.parallel ? `parallel group (${gs.length} tools)` : msg.tool
        appendLine(`\n\x1b[33m[⏸] Paused before: ${label}\x1b[0m`)
        break
      }
      case 'stdout': appendLine(msg.data.replace(/\n$/, '')); break
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

  const searchTechniques = useCallback(async (q: string) => {
    if (q.trim().length < 2) { setTechResults([]); return }
    setTechSearching(true)
    try {
      const res = await fetch(`${getApiBase()}/ai/attack/search?q=${encodeURIComponent(q.trim())}&limit=6`)
      if (res.ok) {
        const data = await res.json()
        setTechResults(data.results ?? [])
      }
    } catch { /* ignore */ } finally {
      setTechSearching(false)
    }
  }, [])

  function handleTechQueryChange(q: string) {
    setTechQuery(q)
    if (techDebounceRef.current) clearTimeout(techDebounceRef.current)
    techDebounceRef.current = setTimeout(() => searchTechniques(q), 280)
  }

  function addTechnique(tid: string) {
    setBuilderTechniques(prev => prev.includes(tid) ? prev : [...prev, tid])
    setTechQuery('')
    setTechResults([])
  }

  function removeTechnique(tid: string) {
    setBuilderTechniques(prev => prev.filter(t => t !== tid))
  }

  function resetBuilder() {
    setBuilderName('')
    setBuilderDesc('')
    setBuilderSteps([])
    setBuilderTechniques([])
    setTechQuery('')
    setTechResults([])
    setEditingIdx(null)
    setEditingPlaybookId(null)
    setBuilderError('')
    setShowBuilder(false)
  }

  function loadPlaybookForEdit(pb: Playbook) {
    setBuilderName(pb.name)
    setBuilderDesc(pb.description)
    setBuilderSteps(pb.steps.map(s => ({
      name: s.name, scan_type: s.scan_type, cmd_template: s.cmd_template,
      description: s.description, conditional: s.conditional,
      trigger_ports_raw: s.trigger_ports.join(','), timeout: s.timeout, parallel: s.parallel ?? false,
    })))
    setBuilderTechniques(pb.mitre_techniques ?? [])
    setTechQuery('')
    setTechResults([])
    setEditingIdx(null)
    setEditingPlaybookId(pb.id)
    setBuilderError('')
    setShowBuilder(true)
  }

  function addStep() {
    setBuilderSteps(prev => [...prev, { ...BLANK_STEP }])
    setEditingIdx(builderSteps.length)
  }

  function removeStep(i: number) {
    setBuilderSteps(prev => {
      const next = prev.filter((_, idx) => idx !== i)
      if (next[i]?.parallel && (i === 0 || !next[i - 1])) next[i] = { ...next[i], parallel: false }
      return next
    })
    if (editingIdx === i) setEditingIdx(null)
    else if (editingIdx !== null && editingIdx > i) setEditingIdx(editingIdx - 1)
  }

  function moveStep(i: number, dir: -1 | 1) {
    const j = i + dir
    if (j < 0 || j >= builderSteps.length) return
    setBuilderSteps(prev => { const next = [...prev]; [next[i], next[j]] = [next[j], next[i]]; return next })
    if (editingIdx === i) setEditingIdx(j)
    else if (editingIdx === j) setEditingIdx(i)
  }

  function updateStep(i: number, patch: Partial<BuilderStep>) {
    setBuilderSteps(prev => prev.map((s, idx) => idx === i ? { ...s, ...patch } : s))
  }

  function handleDragStart(i: number) { setDragIdx(i) }
  function handleDragOver(e: React.DragEvent, i: number) { e.preventDefault(); setDragOverIdx(i) }
  function handleDrop(e: React.DragEvent, targetIdx: number) {
    e.preventDefault()
    if (dragIdx === null || dragIdx === targetIdx) { setDragIdx(null); setDragOverIdx(null); return }
    setBuilderSteps(prev => {
      const next = [...prev]
      const [moved] = next.splice(dragIdx, 1)
      next.splice(targetIdx, 0, moved)
      return next
    })
    if (editingIdx === dragIdx) setEditingIdx(targetIdx)
    setDragIdx(null); setDragOverIdx(null)
  }
  function handleDragEnd() { setDragIdx(null); setDragOverIdx(null) }

  function toApiStep(s: BuilderStep) {
    return {
      name: s.name.trim(), scan_type: s.scan_type.trim() || s.name.trim(),
      cmd_template: s.cmd_template.trim(), description: s.description.trim(),
      conditional: s.conditional, trigger_ports: s.trigger_ports_raw.split(',').map(p => parseInt(p.trim(), 10)).filter(p => !isNaN(p)),
      timeout: s.timeout, parallel: s.parallel,
    }
  }

  async function handleSavePlaybook() {
    setBuilderError('')
    if (!builderName.trim()) { setBuilderError('Playbook name is required.'); return }
    if (builderSteps.length === 0) { setBuilderError('Add at least one step.'); return }
    for (const s of builderSteps) {
      if (!s.name.trim() || !s.cmd_template.trim()) { setBuilderError('Each step needs a tool name and command template.'); return }
    }
    setSaving(true)
    try {
      const body = { name: builderName.trim(), description: builderDesc.trim(), steps: builderSteps.map(toApiStep), mitre_techniques: builderTechniques }
      const url = editingPlaybookId ? `${getApiBase()}/playbooks/${editingPlaybookId}` : `${getApiBase()}/playbooks`
      const res = await fetch(url, { method: editingPlaybookId ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      if (!res.ok) throw new Error(await res.text())
      await loadPlaybooks()
      resetBuilder()
    } catch (err: any) {
      setBuilderError(err.message ?? 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  async function handleDeletePlaybook(id: string) {
    if (!confirm('Delete this playbook?')) return
    await fetch(`${getApiBase()}/playbooks/${id}`, { method: 'DELETE' })
    loadPlaybooks()
  }

  // Import a playbook from a YAML file ({ name, description, steps[], mitre_techniques[] }).
  async function handleImportYaml(file: File) {
    try {
      const doc = yamlLoad(await file.text()) as any
      if (!doc || typeof doc !== 'object') throw new Error('Invalid YAML — expected a playbook object')
      const rawSteps = Array.isArray(doc.steps) ? doc.steps : []
      if (rawSteps.length === 0) throw new Error('Playbook has no steps')
      const steps = rawSteps.map((s: any) => ({
        name: String(s.name ?? s.scan_type ?? 'step'),
        scan_type: String(s.scan_type ?? s.name ?? 'step'),
        cmd_template: String(s.cmd_template ?? s.cmd ?? s.command ?? ''),
        description: String(s.description ?? ''),
        conditional: Boolean(s.conditional ?? false),
        trigger_ports: Array.isArray(s.trigger_ports) ? s.trigger_ports.map(Number).filter((n: number) => !isNaN(n)) : [],
        timeout: Number(s.timeout ?? 300),
        parallel: Boolean(s.parallel ?? false),
      }))
      const body = {
        name: String(doc.name ?? file.name.replace(/\.(ya?ml)$/i, '')),
        description: String(doc.description ?? ''),
        steps,
        mitre_techniques: Array.isArray(doc.mitre_techniques) ? doc.mitre_techniques.map(String) : [],
      }
      const res = await fetch(`${getApiBase()}/playbooks`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      })
      if (!res.ok) throw new Error(await res.text())
      await loadPlaybooks()
      toast.success(`Imported playbook "${body.name}" (${steps.length} steps)`)
    } catch (err: any) {
      toast.error(`Import failed: ${err.message ?? 'could not parse YAML'}`)
    }
  }

  function formatDate(s: string | null) {
    if (!s || s === 'None') return '—'
    try { return new Date(s).toLocaleString() } catch { return s }
  }

  // Determine left-pane selected playbook to show in right pane
  const [listSelected, setListSelected] = useState<Playbook | null>(null)
  const displayPb = listSelected ?? playbooks[0] ?? null

  // Count runs for a playbook
  function runsFor(pb: Playbook) { return runs.filter(r => r.playbook_id === pb.id).length }
  function lastRunFor(pb: Playbook) {
    const pbRuns = runs.filter(r => r.playbook_id === pb.id)
    if (!pbRuns.length) return 'never'
    const latest = pbRuns.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())[0]
    try {
      const d = new Date(latest.created_at)
      const now = new Date()
      const diff = Math.floor((now.getTime() - d.getTime()) / 60000)
      if (diff < 60) return `${diff}m ago`
      if (diff < 1440) return `${Math.floor(diff / 60)}h ago`
      return `${Math.floor(diff / 1440)}d ago`
    } catch { return '—' }
  }

  // Step display state for right-pane active run
  const stepToneMap: Record<string, 'pass' | 'warn' | 'info' | 'fail'> = {
    completed: 'pass', running: 'warn', pending: 'info', skipped: 'info', failed: 'fail',
  }

  // ── Render ────────────────────────────────────────────────────────────────────
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

      <PageHeader
        title="Playbooks"
        sub="Multi-step automated workflows. Chain tools into repeatable attack and audit sequences."
        right={
          <>
            <input
              ref={importYamlRef}
              type="file"
              accept=".yaml,.yml,text/yaml,application/x-yaml"
              style={{ display: 'none' }}
              onChange={e => {
                const file = e.target.files?.[0]
                if (file) handleImportYaml(file)
                e.target.value = ''
              }}
            />
            <button className="btn btn-sm" style={{ display: 'flex', alignItems: 'center', gap: 6 }} onClick={() => importYamlRef.current?.click()}>
              <Icon name="upload" size={11} /> Import yaml
            </button>
            <button
              className="btn-primary btn-sm"
              style={{ display: 'flex', alignItems: 'center', gap: 6 }}
              onClick={() => { resetBuilder(); setShowBuilder(true) }}
            >
              <Plus size={11} /> New playbook
            </button>
          </>
        }
      />

      {/* ── 2-pane layout ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', flex: 1, minHeight: 0, overflow: 'hidden' }}>

        {/* ── Left pane: Playbook list ── */}
        <div style={{ borderRight: rule, overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>
          {playbooks.length === 0 && (
            <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--fg-3)', fontSize: 12 }}>
              No playbooks yet. Create one to get started.
            </div>
          )}
          {playbooks.map(pb => {
            const isActive = displayPb?.id === pb.id
            return (
              <button
                key={pb.id}
                onClick={() => setListSelected(pb)}
                style={{
                  display: 'block', width: '100%', textAlign: 'left',
                  padding: '12px 16px',
                  background: isActive ? 'var(--accent-2)' : 'transparent',
                  borderLeft: isActive ? '2px solid var(--accent)' : '2px solid transparent',
                  borderTop: 'none', borderRight: 'none',
                  borderBottom: rule, cursor: 'pointer',
                }}
              >
                <div className="mono" style={{ fontSize: 13, color: isActive ? 'var(--accent)' : 'var(--fg-2)', marginBottom: 3 }}>{pb.name}</div>
                <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>
                  {pb.step_count ?? pb.steps?.length ?? 0} steps · {runsFor(pb)} runs · last {lastRunFor(pb)}
                </div>
              </button>
            )
          })}
        </div>

        {/* ── Right pane: Detail / Active run ── */}
        <div style={{ overflowY: 'auto', padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 16 }}>
          {displayPb && !showBuilder && (
            <>
              {/* Title row */}
              <div>
                <div className="smcap" style={{ marginBottom: 6 }}>playbook · {displayPb.id.slice(0, 8)}</div>
                <h2 className="mono" style={{ margin: 0, fontWeight: 500, fontSize: 20, fontFamily: 'var(--font-mono)' }}>{displayPb.name}</h2>
              </div>

              {/* Action row */}
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <button className="btn-primary btn-sm" style={{ display: 'flex', alignItems: 'center', gap: 6 }} onClick={() => openWizard(displayPb)}>
                  <Play size={11} /> Run
                </button>
                <button className="btn btn-sm" style={{ display: 'flex', alignItems: 'center', gap: 6 }} onClick={() => { setMode('step_through'); openWizard(displayPb) }}>
                  <StepForward size={11} /> Step through
                </button>
                <button className="btn btn-sm" style={{ display: 'flex', alignItems: 'center', gap: 6 }} onClick={() => setRunsModalPb(displayPb)}>
                  Runs · {runsFor(displayPb)}
                </button>
                {!displayPb.is_builtin && (
                  <>
                    <button className="btn btn-sm" style={{ marginLeft: 'auto' }} onClick={() => loadPlaybookForEdit(displayPb)}>
                      <Icon name="edit" size={11} />
                    </button>
                    <button className="btn btn-sm" onClick={() => handleDeletePlaybook(displayPb.id)}>
                      <Trash2 size={11} />
                    </button>
                  </>
                )}
              </div>

              {/* ATT&CK technique chips */}
              {displayPb.mitre_techniques?.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, alignItems: 'center' }}>
                  <span style={{ fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', marginRight: 2 }}>ATT&CK</span>
                  {displayPb.mitre_techniques.map(tid => (
                    <a
                      key={tid}
                      href={`https://attack.mitre.org/techniques/${tid.replace('.', '/')}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="mono"
                      style={{
                        fontSize: 10, padding: '2px 7px',
                        background: 'rgba(240,168,58,0.08)', border: '1px solid rgba(240,168,58,0.3)',
                        color: 'var(--accent)', textDecoration: 'none',
                      }}
                      onMouseEnter={e => (e.currentTarget.style.background = 'rgba(240,168,58,0.16)')}
                      onMouseLeave={e => (e.currentTarget.style.background = 'rgba(240,168,58,0.08)')}
                    >
                      {tid}
                    </a>
                  ))}
                </div>
              )}

              {/* Step list */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                {/* Header row */}
                <div style={{
                  display: 'grid', gridTemplateColumns: '30px 130px 1fr 80px 80px 110px',
                  gap: 12, padding: '6px 0', borderBottom: rule,
                }}>
                  {['#', 'Tool', 'Command', 'Timeout', 'State', 'Description'].map(h => (
                    <div key={h} className="mono" style={{ fontSize: 9, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{h}</div>
                  ))}
                </div>
                {displayPb.steps.map((step, i) => {
                  const runStep = steps.find(s => s.step === i)
                  const state = runStep?.status ?? 'pending'
                  const tone = stepToneMap[state] ?? 'info'
                  return (
                    <div key={i} style={{
                      display: 'grid', gridTemplateColumns: '30px 130px 1fr 80px 80px 110px',
                      gap: 12, padding: '10px 0', borderBottom: rule, alignItems: 'center',
                    }}>
                      <div className="mono tnum" style={{ fontSize: 12, color: 'var(--fg-3)' }}>
                        {String(i + 1).padStart(2, '0')}
                      </div>
                      <div className="mono" style={{ fontSize: 11.5, color: 'var(--accent)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {step.name}
                      </div>
                      <div style={{ overflow: 'hidden' }}>
                        <code className="mono" style={{
                          fontSize: 11, color: 'var(--fg-2)', background: 'var(--bg-2)',
                          padding: '3px 8px', overflow: 'hidden', textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap', display: 'block',
                        }}>{step.cmd_template}</code>
                      </div>
                      <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>{step.timeout}s</div>
                      <div>{activeRunId ? <Pill tone={tone}>{state}</Pill> : <Pill tone="info">pending</Pill>}</div>
                      <div className="mono" style={{ fontSize: 10.5, color: 'var(--fg-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {step.description || '—'}
                      </div>
                    </div>
                  )
                })}
              </div>

              {/* Active run terminal output */}
              {activeRunId && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div className="smcap">Live output</div>
                    {runStatus === 'running' && currentTool && (
                      <span className="mono" style={{ fontSize: 10, color: 'var(--accent)' }}>
                        <Loader size={10} style={{ display: 'inline', marginRight: 4 }} />{currentTool}
                      </span>
                    )}
                    {paused && pausedState && (
                      <button
                        className="btn btn-sm"
                        onClick={handleContinue}
                        style={{ display: 'flex', alignItems: 'center', gap: 4 }}
                      >
                        <StepForward size={10} /> Continue
                      </button>
                    )}
                    {runStatus === 'completed' && (
                      <Pill tone="pass">{totalFindings} findings</Pill>
                    )}
                  </div>
                  <div
                    ref={termRef}
                    style={{
                      border: rule, padding: '10px 12px', fontFamily: 'var(--font-mono)', fontSize: 11,
                      color: 'var(--fg-2)', overflowY: 'auto', lineHeight: 1.6, background: 'var(--bg)',
                      maxHeight: 260,
                    }}
                  >
                    {termLines.map((line, i) => (
                      <div key={i} style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}
                        dangerouslySetInnerHTML={{ __html: ansiToHtml(line) }}
                      />
                    ))}
                  </div>
                  {lastInsight && useAi && (
                    <div style={{ border: '1px solid rgba(168,85,247,0.2)', padding: '8px 12px', background: 'rgba(168,85,247,0.05)', display: 'flex', gap: 8 }}>
                      <Brain size={12} color="#a855f7" style={{ flexShrink: 0, marginTop: 1 }} />
                      <span style={{ fontSize: 11, color: '#ddd6fe' }}>{lastInsight}</span>
                    </div>
                  )}
                </div>
              )}
            </>
          )}

          {/* Builder mode */}
          {showBuilder && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <PenLine size={14} color="var(--accent)" />
                <span className="mono" style={{ fontSize: 14, fontWeight: 500 }}>
                  {editingPlaybookId ? 'Edit Playbook' : 'New Playbook'}
                </span>
                <button onClick={resetBuilder} style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--fg-3)', background: 'none', border: 'none', cursor: 'pointer' }}>
                  Cancel
                </button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div>
                  <label style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fg-3)' }}>Name *</label>
                  <input value={builderName} onChange={e => setBuilderName(e.target.value)} placeholder="e.g. Custom Web Audit" style={{ ...INPUT_STYLE, marginTop: 5 }} />
                </div>
                <div>
                  <label style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fg-3)' }}>Description</label>
                  <input value={builderDesc} onChange={e => setBuilderDesc(e.target.value)} placeholder="What does this playbook do?" style={{ ...INPUT_STYLE, marginTop: 5 }} />
                </div>
              </div>

              {/* ATT&CK Technique Picker */}
              <div>
                <label style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fg-3)' }}>
                  MITRE ATT&amp;CK Techniques
                </label>
                <div style={{ marginTop: 5, position: 'relative' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, ...INPUT_STYLE, padding: '5px 10px' }}>
                    {techSearching
                      ? <Loader size={12} color="var(--fg-3)" style={{ flexShrink: 0, animation: 'spin 1s linear infinite' }} />
                      : <Search size={12} color="var(--fg-3)" style={{ flexShrink: 0 }} />}
                    <input
                      value={techQuery}
                      onChange={e => handleTechQueryChange(e.target.value)}
                      placeholder="Search techniques (e.g. credential dumping, T1059)…"
                      style={{ flex: 1, background: 'none', border: 'none', outline: 'none', fontSize: 12, color: 'var(--fg)', fontFamily: 'var(--font-sans)' }}
                    />
                  </div>
                  {techResults.length > 0 && (
                    <div style={{
                      position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 20,
                      background: 'var(--bg-2)', border: ruleStrong, marginTop: 2,
                      maxHeight: 220, overflowY: 'auto',
                    }}>
                      {techResults.map(t => (
                        <button
                          key={t.technique_id}
                          onClick={() => addTechnique(t.technique_id)}
                          style={{
                            display: 'block', width: '100%', textAlign: 'left', padding: '7px 12px',
                            background: 'transparent', border: 'none', borderBottom: rule, cursor: 'pointer',
                          }}
                          onMouseEnter={e => (e.currentTarget.style.background = 'var(--accent-2)')}
                          onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                        >
                          <span className="mono" style={{ fontSize: 11, color: 'var(--accent)', marginRight: 8 }}>{t.technique_id}</span>
                          <span style={{ fontSize: 11, color: 'var(--fg-2)' }}>{t.name}</span>
                          <span style={{ fontSize: 10, color: 'var(--fg-3)', marginLeft: 8 }}>{t.tactic}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
                {builderTechniques.length > 0 && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 7 }}>
                    {builderTechniques.map(tid => (
                      <span key={tid} className="mono" style={{
                        display: 'inline-flex', alignItems: 'center', gap: 4,
                        fontSize: 10, padding: '2px 7px',
                        background: 'rgba(240,168,58,0.08)', border: '1px solid rgba(240,168,58,0.3)',
                        color: 'var(--accent)',
                      }}>
                        {tid}
                        <button onClick={() => removeTechnique(tid)} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, color: 'var(--fg-3)', display: 'flex', alignItems: 'center' }}>
                          <X size={10} />
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fg-3)' }}>Steps ({builderSteps.length})</span>
                </div>

                {builderGroups.map((group, gi) => {
                  const isParGroup = group.length > 1
                  const groupColor = GROUP_PALETTE[gi % GROUP_PALETTE.length]
                  return (
                    <div key={gi} style={{ borderLeft: isParGroup ? `2px solid ${groupColor}40` : 'none', paddingLeft: isParGroup ? 8 : 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
                      {group.map(si => {
                        const s = builderSteps[si]
                        const isEditing = editingIdx === si
                        const isDragging = dragIdx === si
                        const isDragOver = dragOverIdx === si && dragIdx !== si
                        return (
                          <div
                            key={si}
                            draggable
                            onDragStart={() => handleDragStart(si)}
                            onDragOver={e => handleDragOver(e, si)}
                            onDrop={e => handleDrop(e, si)}
                            onDragEnd={handleDragEnd}
                            onClick={() => setEditingIdx(si)}
                            style={{
                              borderRadius: 3, padding: '8px 10px', cursor: 'grab', transition: 'all 0.15s',
                              border: isDragOver ? '1px solid var(--accent)' : isEditing ? '1px solid rgba(240,168,58,0.4)' : ruleStrong,
                              background: isDragOver ? 'rgba(240,168,58,0.08)' : isEditing ? 'rgba(240,168,58,0.04)' : 'transparent',
                              opacity: isDragging ? 0.4 : 1,
                            }}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 2, flexShrink: 0 }} onClick={e => e.stopPropagation()}>
                                <button onClick={() => moveStep(si, -1)} disabled={si === 0} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0, opacity: si === 0 ? 0.2 : 1 }}><ArrowUp size={11} /></button>
                                <button onClick={() => moveStep(si, 1)} disabled={si === builderSteps.length - 1} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0, opacity: si === builderSteps.length - 1 ? 0.2 : 1 }}><ArrowDown size={11} /></button>
                              </div>
                              <span className="mono tnum" style={{ fontSize: 10, color: 'var(--fg-3)', width: 18, textAlign: 'right', flexShrink: 0 }}>{si + 1}</span>
                              {s.parallel ? <span style={{ color: '#a855f7', fontSize: 12, fontFamily: 'var(--font-mono)', flexShrink: 0 }}>∥</span> : <Icon name="chev_r" size={10} color="var(--fg-3)" />}
                              <div style={{ flex: 1, minWidth: 0 }}>
                                <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', fontWeight: 500, color: s.name ? 'var(--fg-2)' : 'var(--fg-3)' }}>
                                  {s.name || 'unnamed'}
                                </div>
                              </div>
                              {si > 0 && (
                                <button
                                  onClick={e => { e.stopPropagation(); updateStep(si, { parallel: !s.parallel }) }}
                                  style={{
                                    flexShrink: 0, padding: '2px 7px', borderRadius: 2, fontSize: 10, fontWeight: 600, cursor: 'pointer',
                                    ...(s.parallel
                                      ? { border: '1px solid rgba(168,85,247,0.5)', color: '#c4b5fd', background: 'rgba(168,85,247,0.1)' }
                                      : { border: ruleStrong, color: 'var(--fg-3)', background: 'transparent' }),
                                  }}
                                >{s.parallel ? '∥ parallel' : '→ seq'}</button>
                              )}
                              <button onClick={e => { e.stopPropagation(); removeStep(si) }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 2, flexShrink: 0 }}>
                                <Trash2 size={12} />
                              </button>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  )
                })}

                <button onClick={addStep} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, padding: '8px 0', border: '1px dashed var(--rule-strong)', cursor: 'pointer', background: 'transparent', color: 'var(--fg-3)', fontSize: 12 }}>
                  <Plus size={13} /> Add Step
                </button>
              </div>

              {/* Step editor */}
              {editingIdx !== null && builderSteps[editingIdx] && (() => {
                const s = builderSteps[editingIdx]
                return (
                  <div style={{ border: rule, padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg)' }}>Edit Step {editingIdx + 1}</span>
                      <button onClick={() => setEditingIdx(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', padding: 0 }}><Icon name="x" size={13} /></button>
                    </div>
                    {[
                      { label: 'Tool Name *', key: 'name', placeholder: 'e.g. nmap' },
                      { label: 'Scan Type', key: 'scan_type', placeholder: 'e.g. nmap (defaults to tool name)' },
                      { label: 'Description', key: 'description', placeholder: 'Human-readable step description' },
                    ].map(({ label, key, placeholder }) => (
                      <div key={key}>
                        <label style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fg-3)' }}>{label}</label>
                        <input value={(s as any)[key]} onChange={e => updateStep(editingIdx, { [key]: e.target.value })} placeholder={placeholder} style={{ ...INPUT_STYLE, marginTop: 5 }} />
                      </div>
                    ))}
                    <div>
                      <label style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fg-3)' }}>Command Template *</label>
                      <textarea value={s.cmd_template} onChange={e => updateStep(editingIdx, { cmd_template: e.target.value })} placeholder="nmap -sV {target}" rows={2} style={{ ...INPUT_STYLE, marginTop: 5, fontFamily: 'var(--font-mono)', resize: 'none', lineHeight: 1.5 }} />
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                      <div>
                        <label style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fg-3)' }}>Timeout (s)</label>
                        <input type="number" value={s.timeout} onChange={e => updateStep(editingIdx, { timeout: parseInt(e.target.value, 10) || 300 })} style={{ ...INPUT_STYLE, marginTop: 5 }} />
                      </div>
                      <div>
                        <label style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fg-3)' }}>Trigger Ports</label>
                        <input value={s.trigger_ports_raw} onChange={e => updateStep(editingIdx, { trigger_ports_raw: e.target.value })} placeholder="80,443 (blank = always)" style={{ ...INPUT_STYLE, marginTop: 5 }} />
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', border: ruleStrong, borderRadius: 3, padding: '9px 12px' }}>
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--fg-2)' }}>Conditional</div>
                        <div style={{ fontSize: 10, color: 'var(--fg-3)' }}>Only run if trigger ports are open</div>
                      </div>
                      <Toggle checked={s.conditional} onChange={() => updateStep(editingIdx, { conditional: !s.conditional })} />
                    </div>
                    {editingIdx > 0 && (
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', border: ruleStrong, borderRadius: 3, padding: '9px 12px' }}>
                        <div>
                          <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--fg-2)', display: 'flex', alignItems: 'center', gap: 6 }}>
                            <Layers size={11} color="#a855f7" /> Run in parallel
                          </div>
                          <div style={{ fontSize: 10, color: 'var(--fg-3)' }}>Execute alongside the previous step's group</div>
                        </div>
                        <Toggle checked={s.parallel} onChange={() => updateStep(editingIdx, { parallel: !s.parallel })} accentColor="#a855f7" />
                      </div>
                    )}
                  </div>
                )
              })()}

              {builderError && (
                <div style={{ padding: '8px 14px', border: '1px solid rgba(232,64,64,0.3)', background: 'rgba(232,64,64,0.06)', fontSize: 12, color: 'var(--crit)' }}>
                  {builderError}
                </div>
              )}

              <div style={{ display: 'flex', gap: 10 }}>
                <button onClick={resetBuilder} style={{ padding: '7px 16px', cursor: 'pointer', background: 'transparent', border: ruleStrong, color: 'var(--fg-3)', fontSize: 12 }}>Cancel</button>
                <button onClick={handleSavePlaybook} disabled={saving} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '7px 20px', border: 'none', cursor: 'pointer', background: 'var(--accent)', color: 'var(--bg)', fontSize: 12, fontWeight: 700, opacity: saving ? 0.6 : 1 }}>
                  {saving ? <Loader size={13} style={{ animation: 'spin 1s linear infinite' }} /> : <Save size={13} />}
                  {editingPlaybookId ? 'Save Changes' : 'Create Playbook'}
                </button>
              </div>
            </div>
          )}

          {!displayPb && !showBuilder && (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 12, padding: '64px 0', color: 'var(--fg-3)' }}>
              <Icon name="book" size={32} color="var(--rule-strong)" />
              <span style={{ fontSize: 13 }}>Select a playbook from the list</span>
            </div>
          )}
        </div>
      </div>

      {/* ── Run Wizard Modal ── */}
      {showWizard && selectedPlaybook && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16, background: 'rgba(0,0,0,0.75)' }}>
          <div style={{ border: rule, padding: 24, width: '100%', maxWidth: 440, display: 'flex', flexDirection: 'column', gap: 18, background: 'var(--bg-2)' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <Icon name="play" size={15} color="var(--accent)" />
                <h2 style={{ fontSize: 14, fontWeight: 700, color: 'var(--fg)', margin: 0 }}>Run: {selectedPlaybook.name}</h2>
              </div>
              <p style={{ fontSize: 12, color: 'var(--fg-3)', margin: 0 }}>{selectedPlaybook.description}</p>
            </div>

            {/* Steps preview */}
            <div style={{ border: ruleStrong, padding: '10px 12px', maxHeight: 140, overflowY: 'auto', background: 'var(--bg)', display: 'flex', flexDirection: 'column', gap: 4 }}>
              {(() => {
                const gs = buildGroups(selectedPlaybook.steps)
                const gm = stepGroupMap(gs)
                return selectedPlaybook.steps.map((s, i) => {
                  const isParGroup = gs[gm[i]].length > 1
                  return (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--fg-3)', paddingLeft: isParGroup ? 8 : 4, borderLeft: isParGroup ? '1px solid rgba(168,85,247,0.3)' : 'none' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', width: 16, textAlign: 'right', flexShrink: 0 }}>{i + 1}</span>
                      {s.parallel ? <span style={{ color: '#a855f7' }}>∥</span> : <Icon name="chev_r" size={10} color="var(--fg-3)" />}
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--fg-2)' }}>{s.name}</span>
                      <span style={{ color: 'var(--fg-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.description}</span>
                    </div>
                  )
                })
              })()}
            </div>

            {/* Target */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              <label style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fg-3)' }}>Target</label>
              <select value={selectedTarget} onChange={e => setSelectedTarget(e.target.value)} disabled={!projectId} style={{ ...INPUT_STYLE, opacity: !projectId ? 0.5 : 1 }}>
                <option value="">Select target…</option>
                {targets.map(t => <option key={t.id} value={t.id}>{t.hostname_or_ip}</option>)}
              </select>
            </div>

            {/* Execution mode */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <label style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--fg-3)' }}>Execution Mode</label>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                {([
                  { value: 'auto', label: 'Auto', icon: <Zap size={13} />, desc: 'All steps run automatically' },
                  { value: 'step_through', label: 'Step-through', icon: <StepForward size={13} />, desc: 'Pause before each group' },
                ] as const).map(opt => (
                  <button key={opt.value} onClick={() => setMode(opt.value)} style={{
                    padding: '10px 12px', textAlign: 'left', cursor: 'pointer',
                    border: mode === opt.value ? '1px solid rgba(240,168,58,0.4)' : ruleStrong,
                    background: mode === opt.value ? 'rgba(240,168,58,0.06)' : 'transparent',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, fontWeight: 600, marginBottom: 3, color: mode === opt.value ? 'var(--accent)' : 'var(--fg-2)' }}>
                      {opt.icon} {opt.label}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--fg-3)' }}>{opt.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* AI toggle */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', border: ruleStrong, padding: '10px 14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Brain size={15} color={useAi ? '#a855f7' : 'var(--fg-3)'} />
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--fg-2)' }}>AI Assistance</div>
                  <div style={{ fontSize: 10, color: 'var(--fg-3)' }}>Analyze each step's output</div>
                </div>
              </div>
              <Toggle checked={useAi} onChange={() => setUseAi(v => !v)} accentColor="#a855f7" />
            </div>

            <div style={{ display: 'flex', gap: 10 }}>
              <button onClick={() => setShowWizard(false)} style={{ flex: 1, padding: '8px 0', cursor: 'pointer', background: 'transparent', border: ruleStrong, color: 'var(--fg-3)', fontSize: 12 }}>Cancel</button>
              <button
                onClick={handleStartRun}
                disabled={starting || !projectId || !selectedTarget}
                style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, padding: '8px 0', border: 'none', cursor: 'pointer', background: 'var(--accent)', color: 'var(--bg)', fontSize: 12, fontWeight: 700, opacity: (starting || !projectId || !selectedTarget) ? 0.5 : 1 }}
              >
                {starting ? <Loader size={13} style={{ animation: 'spin 1s linear infinite' }} /> : <Play size={13} />}
                Start Run
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Runs history modal ── */}
      {runsModalPb && (() => {
        const pbRuns = runs.filter(r => r.playbook_id === runsModalPb.id)
          .sort((a, b) => (b.created_at ?? '').localeCompare(a.created_at ?? ''))
        return (
          <div
            style={{ position: 'fixed', inset: 0, zIndex: 60, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(0,0,0,0.75)' }}
            onClick={() => setRunsModalPb(null)}
          >
            <div onClick={e => e.stopPropagation()} style={{ background: 'var(--bg-2)', border: rule, width: '100%', maxWidth: 640, maxHeight: '80vh', display: 'flex', flexDirection: 'column', boxShadow: '0 8px 32px rgba(0,0,0,0.5)' }}>
              <div className="sec-h" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span className="title" style={{ marginRight: 'auto' }}>Runs · {runsModalPb.name}</span>
                <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>{pbRuns.length} total</span>
                <button className="btn btn-sm" onClick={() => setRunsModalPb(null)}><X size={11} /></button>
              </div>
              <div style={{ overflowY: 'auto' }}>
                {pbRuns.length === 0 ? (
                  <div style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--fg-3)', fontSize: 12 }}>
                    No runs recorded for this playbook yet.
                  </div>
                ) : (
                  <table className="data">
                    <thead>
                      <tr><th>Status</th><th>Target</th><th>Mode</th><th>Step</th><th>Started</th></tr>
                    </thead>
                    <tbody>
                      {pbRuns.map(r => (
                        <tr key={r.id}>
                          <td className="mono" style={{ fontSize: 11 }}>{r.status}</td>
                          <td className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>{r.target_host || '—'}</td>
                          <td className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>{r.mode}</td>
                          <td className="mono" style={{ fontSize: 11, color: 'var(--fg-3)' }}>{r.current_step || '—'}</td>
                          <td className="mono" style={{ fontSize: 10.5, color: 'var(--fg-3)' }}>{formatDate(r.started_at ?? r.created_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>
        )
      })()}
    </div>
  )
}

// ── Minimal ANSI → HTML ───────────────────────────────────────────────────────
function ansiToHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/\x1b\[0m/g, '</span>')
    .replace(/\x1b\[(\d+)m/g, (_: string, code: string) => {
      const colorMap: Record<string, string> = {
        '30': '#475569', '31': '#e84040', '32': '#54af61', '33': '#f0a83a',
        '34': '#f0a83a', '35': '#a855f7', '36': '#f0a83a', '37': '#e8e3d8',
        '90': '#5a5550',
      }
      const color = colorMap[code]
      return color ? `<span style="color:${color}">` : ''
    })
}
