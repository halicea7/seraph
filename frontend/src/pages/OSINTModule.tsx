import { useState, useEffect, useRef } from 'react'
import { Search, Mail, Globe, Network, Plus, AlertCircle } from 'lucide-react'
import ToolCard, { ToolStatus } from '../components/ToolCard'
import Terminal, { TerminalHandle } from '../components/Terminal'
import type { Project, Target } from '../types/index'

interface OSINTTool {
  tool: string
  description: string
  command_template: string
  install: string
  available: boolean
}

interface ToolState {
  status: ToolStatus
  output: string
  scanId: string | null
  renderedCommand: string
  results: { emails: number; subdomains: number; ips: number; new_targets: number } | null
}

const TOOL_KEYS = ['theHarvester', 'amass', 'subfinder']

function renderTemplate(template: string, domain: string): string {
  return template.replace(/\{domain\}/g, domain || '{domain}')
}

export default function OSINTModule() {
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedProject, setSelectedProject] = useState('')
  const [targets, setTargets] = useState<Target[]>([])
  const [selectedTarget, setSelectedTarget] = useState('')
  const [domain, setDomain] = useState('')
  const [tools, setTools] = useState<Record<string, OSINTTool>>({})
  const [toolStates, setToolStates] = useState<Record<string, ToolState>>({})
  const [activeTerminalTool, setActiveTerminalTool] = useState<string | null>(null)
  const terminalRef = useRef<TerminalHandle>(null)

  useEffect(() => {
    fetch('/api/v1/projects').then(r => r.json()).then(data => {
      setProjects(data)
      if (data.length > 0) setSelectedProject(data[0].id)
    })
    fetch('/api/v1/osint/tools').then(r => r.json()).then(data => {
      setTools(data)
      const states: Record<string, ToolState> = {}
      Object.values(data).forEach((t: any) => {
        states[t.tool] = {
          status: 'idle',
          output: '',
          scanId: null,
          renderedCommand: t.command_template,
          results: null,
        }
      })
      setToolStates(states)
    })
  }, [])

  useEffect(() => {
    if (!selectedProject) return
    fetch(`/api/v1/projects/${selectedProject}/targets`)
      .then(r => r.json())
      .then(data => {
        setTargets(data)
        if (data.length > 0) {
          setSelectedTarget(data[0].id)
          setDomain(data[0].hostname_or_ip)
        }
      })
  }, [selectedProject])

  // Update rendered commands when domain changes
  useEffect(() => {
    setToolStates(prev => {
      const next = { ...prev }
      Object.entries(tools).forEach(([key, tool]) => {
        if (next[key] && next[key].status === 'idle') {
          next[key] = { ...next[key], renderedCommand: renderTemplate(tool.command_template, domain) }
        }
      })
      return next
    })
  }, [domain, tools])

  function updateTool(toolName: string, updates: Partial<ToolState>) {
    setToolStates(prev => ({ ...prev, [toolName]: { ...prev[toolName], ...updates } }))
  }

  async function handleRun(toolName: string, command: string) {
    if (!selectedProject || !selectedTarget) {
      alert('Select a project and target first.')
      return
    }
    if (!domain) {
      alert('Enter a domain to recon.')
      return
    }

    updateTool(toolName, { status: 'running', output: '', scanId: null, results: null })
    setActiveTerminalTool(toolName)

    const res = await fetch('/api/v1/osint/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: selectedProject,
        target_id: selectedTarget,
        domain,
        tool_name: toolName,
        command,
      }),
    })

    if (!res.ok) {
      updateTool(toolName, { status: 'failed', output: 'Failed to create scan record' })
      return
    }

    const { scan_id } = await res.json()
    updateTool(toolName, { scanId: scan_id })

    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${wsProto}//${window.location.host}/ws/osint/${scan_id}`)
    let outputBuffer = ''

    ws.onopen = () => {
      terminalRef.current?.writeln(`\x1b[33m[*] Running: ${command}\x1b[0m`)
    }

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data)
      if (msg.type === 'stdout') {
        terminalRef.current?.write(msg.data)
        outputBuffer += msg.data
      } else if (msg.type === 'stderr') {
        terminalRef.current?.write('\x1b[33m' + msg.data + '\x1b[0m')
        outputBuffer += msg.data
      } else if (msg.type === 'exit') {
        const status: ToolStatus = msg.code === 0 ? 'completed' : 'failed'
        updateTool(toolName, { status, output: outputBuffer })
        if (msg.code === 0) {
          terminalRef.current?.writeln('\x1b[32m\r\n[+] Completed (exit 0)\x1b[0m')
        } else {
          terminalRef.current?.writeln(`\x1b[31m\r\n[!] Exited with code ${msg.code}\x1b[0m`)
        }
      } else if (msg.type === 'results') {
        updateTool(toolName, {
          results: {
            emails: msg.emails,
            subdomains: msg.subdomains,
            ips: msg.ips,
            new_targets: msg.new_targets,
          },
        })
        terminalRef.current?.writeln(
          `\x1b[36m\r\n[*] Results: ${msg.emails} emails · ${msg.subdomains} subdomains · ${msg.ips} IPs · ${msg.new_targets} new targets added\x1b[0m`
        )
      } else if (msg.type === 'error') {
        terminalRef.current?.writeln(`\x1b[31m[ERROR] ${msg.data}\x1b[0m`)
        updateTool(toolName, { status: 'failed', output: msg.data })
      }
    }

    ws.onerror = () => {
      updateTool(toolName, { status: 'failed', output: 'WebSocket error' })
    }
  }

  const selectClass = "w-full rounded px-3 py-2 text-xs text-slate-200 focus:outline-none border border-cyan-900/20 focus:border-cyan-500/50"

  return (
    <div className="flex h-full gap-4 min-h-0">
      {/* Left: Config panel */}
      <div className="w-64 flex-shrink-0 flex flex-col gap-4 overflow-y-auto min-h-0">
        <div className="glass glass-hover rounded-xl p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Target</h3>
          <div className="space-y-2">
            <select
              className={selectClass}
              style={{ background: '#05080d' }}
              value={selectedProject}
              onChange={e => setSelectedProject(e.target.value)}
            >
              <option value="">Select project...</option>
              {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
            <select
              className={selectClass}
              style={{ background: '#05080d' }}
              value={selectedTarget}
              onChange={e => {
                setSelectedTarget(e.target.value)
                const t = targets.find(t => t.id === e.target.value)
                if (t) setDomain(t.hostname_or_ip)
              }}
              disabled={targets.length === 0}
            >
              <option value="">Select target...</option>
              {targets.map(t => <option key={t.id} value={t.id}>{t.hostname_or_ip}</option>)}
            </select>
          </div>
        </div>

        <div className="glass glass-hover rounded-xl p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Domain</h3>
          <input
            value={domain}
            onChange={e => setDomain(e.target.value)}
            className={selectClass}
            style={{ background: '#05080d' }}
            placeholder="example.com"
          />
          {domain && (
            <div className="mt-2 text-xs font-mono text-cyan-400 px-1 glow-cyan" style={{ textShadow: '0 0 8px rgba(6,182,212,0.5)' }}>
              ▶ {domain}
            </div>
          )}
        </div>

        {/* Tool availability */}
        <div className="glass rounded-xl p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Tool Status</h3>
          <div className="space-y-2">
            {TOOL_KEYS.map(key => {
              const t = tools[key]
              if (!t) return null
              return (
                <div key={key} className="flex items-center justify-between">
                  <span className="text-xs font-mono text-slate-300">{key}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded-full border font-semibold ${t.available ? 'bg-green-950/50 text-green-400 border-green-700/30' : 'bg-red-950/50 text-red-400 border-red-700/30'}`}>
                    {t.available ? 'ready' : 'missing'}
                  </span>
                </div>
              )
            })}
          </div>
        </div>

        {/* Discovery summary */}
        {TOOL_KEYS.some(k => toolStates[k]?.results) && (
          <div className="glass rounded-xl p-4">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Discoveries</h3>
            <div className="space-y-2">
              {[
                { icon: <Mail size={11} />, label: 'Emails', key: 'emails' as const },
                { icon: <Globe size={11} />, label: 'Subdomains', key: 'subdomains' as const },
                { icon: <Network size={11} />, label: 'IPs', key: 'ips' as const },
                { icon: <Plus size={11} />, label: 'New Targets', key: 'new_targets' as const },
              ].map(({ icon, label, key }) => {
                const total = TOOL_KEYS.reduce((sum, k) => sum + (toolStates[k]?.results?.[key] || 0), 0)
                return (
                  <div key={key} className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-xs text-slate-400">
                      <span className="text-cyan-500">{icon}</span>
                      {label}
                    </div>
                    <span className="text-xs font-mono text-cyan-400">{total}</span>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* Center: Tool cards */}
      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        <div className="mb-4">
          <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
            <Search size={18} className="text-cyan-400" /> OSINT Module
          </h2>
          <p className="text-sm text-slate-400">Passive reconnaissance — no active probing of the target</p>
        </div>

        {!domain && (
          <div className="flex items-center gap-2 mb-4 px-3 py-2 rounded-lg border border-amber-700/30 bg-amber-950/20 text-xs text-amber-400">
            <AlertCircle size={13} /> Enter a domain in the left panel to begin
          </div>
        )}

        <div className="space-y-3">
          {TOOL_KEYS.map(key => {
            const tool = tools[key]
            if (!tool) return null
            const state = toolStates[key] || { status: 'idle' as ToolStatus, output: '', scanId: null, renderedCommand: '', results: null }
            return (
              <div key={key}>
                <ToolCard
                  tool={tool.tool}
                  description={tool.description}
                  commandTemplate={tool.command_template}
                  install={tool.install}
                  renderedCommand={state.renderedCommand}
                  status={state.status}
                  output={state.output}
                  isToolAvailable={tool.available}
                  onRun={(cmd) => handleRun(key, cmd)}
                  onCommandChange={(cmd) => updateTool(key, { renderedCommand: cmd })}
                />
                {/* Results badge */}
                {state.results && (
                  <div className="flex gap-3 mt-1.5 px-2">
                    {[
                      { icon: <Mail size={10} />, val: state.results.emails, label: 'emails' },
                      { icon: <Globe size={10} />, val: state.results.subdomains, label: 'subdomains' },
                      { icon: <Network size={10} />, val: state.results.ips, label: 'IPs' },
                      { icon: <Plus size={10} />, val: state.results.new_targets, label: 'new targets' },
                    ].map(({ icon, val, label }) => (
                      <div key={label} className="flex items-center gap-1 text-[10px] text-slate-400">
                        <span className="text-cyan-500">{icon}</span>
                        <span className="font-mono text-cyan-400">{val}</span> {label}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Right: Terminal */}
      <div className="w-96 flex-shrink-0 flex flex-col">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-200">Live Output</h3>
          {activeTerminalTool && (
            <span className="text-xs text-cyan-400 font-mono" style={{ textShadow: '0 0 8px rgba(6,182,212,0.4)' }}>
              {activeTerminalTool}
            </span>
          )}
        </div>
        <Terminal
          ref={terminalRef}
          className="flex-1 rounded-xl overflow-hidden border border-cyan-900/20 shadow-glow-cyan"
        />
      </div>
    </div>
  )
}
