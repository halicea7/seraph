import { useState, useEffect, useRef, useCallback } from 'react'
import cytoscape from 'cytoscape'
import { GitBranch, RefreshCw, Shield, Download } from 'lucide-react'
import type { Project } from '../types/index'

interface NodeData {
  id: string
  label: string
  type: 'attacker' | 'target'
  target_type?: string
  compromised?: boolean
  finding_counts?: Record<string, number>
}

interface EdgeData {
  id: string
  source: string
  target: string
  label: string
  type: 'c2' | 'finding' | 'lateral'
  count?: number
  username?: string
  session_type?: string
  status?: string
}

interface GraphData {
  nodes: { data: NodeData }[]
  edges: { data: EdgeData }[]
}

const EDGE_COLORS: Record<string, string> = {
  c2:      '#ef4444',
  finding: '#f59e0b',
  lateral: '#a855f7',
}

const TARGET_ICONS: Record<string, string> = {
  linux_host:   '🖥',
  windows_host: '🪟',
  web_app:      '🌐',
  cloud_aws:    '☁',
  network:      '🔗',
}

export default function AttackPaths() {
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedProject, setSelectedProject] = useState('')
  const [graph, setGraph] = useState<GraphData | null>(null)
  const [loading, setLoading] = useState(false)
  const [selectedEl, setSelectedEl] = useState<NodeData | EdgeData | null>(null)
  const cyRef = useRef<cytoscape.Core | null>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    fetch('/api/v1/projects').then(r => r.json()).then(data => {
      setProjects(data)
      if (data.length > 0) setSelectedProject(data[0].id)
    })
  }, [])

  useEffect(() => {
    if (selectedProject) loadGraph()
  }, [selectedProject])

  async function loadGraph() {
    setLoading(true)
    setSelectedEl(null)
    try {
      const res = await fetch(`/api/v1/attack-paths/${selectedProject}`)
      if (res.ok) setGraph(await res.json())
    } finally {
      setLoading(false)
    }
  }

  const initCy = useCallback(() => {
    if (!graph || !containerRef.current) return
    if (cyRef.current) cyRef.current.destroy()

    const elements: cytoscape.ElementDefinition[] = [
      ...graph.nodes.map(n => {
        const isAttacker = n.data.type === 'attacker'
        const isCompromised = n.data.compromised
        const bg = isAttacker ? '#001a2d' : isCompromised ? '#3f0000' : '#0d1520'
        const border = isAttacker ? '#06b6d4' : isCompromised ? '#ef4444' : '#334155'
        const glow = isAttacker ? 'rgba(6,182,212,0.7)' : isCompromised ? 'rgba(239,68,68,0.6)' : 'rgba(51,65,85,0.3)'
        return { data: { ...n.data, bg, border, glow } }
      }),
      ...graph.edges.map(e => ({
        data: { ...e.data, lineColor: EDGE_COLORS[e.data.type] || '#334155' },
      })),
    ]

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(bg)',
            'border-color': 'data(border)',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#e2e8f0',
            'font-size': '11px',
            'font-family': 'JetBrains Mono, monospace',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-max-width': '120px',
            'text-wrap': 'ellipsis',
            'width': 44,
            'height': 44,
            'shadow-blur': 16,
            'shadow-color': 'data(glow)',
            'shadow-opacity': 0.9,
            'shadow-offset-x': 0,
            'shadow-offset-y': 0,
          } as any,
        },
        {
          selector: 'node[type="attacker"]',
          style: { 'shape': 'diamond', 'width': 52, 'height': 52 },
        },
        {
          selector: 'node:selected',
          style: { 'border-width': 3, 'border-color': '#06b6d4' },
        },
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': 'data(lineColor)',
            'target-arrow-color': 'data(lineColor)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-size': '9px',
            'color': '#94a3b8',
            'text-rotation': 'autorotate',
            'opacity': 0.75,
          },
        },
        {
          selector: 'edge:selected',
          style: { 'opacity': 1, 'width': 3 },
        },
      ],
      layout: {
        name: 'cose',
        animate: true,
        animationDuration: 600,
        nodeRepulsion: () => 10000,
        idealEdgeLength: () => 140,
        gravity: 0.8,
        randomize: false,
      } as any,
      minZoom: 0.2,
      maxZoom: 4,
    })

    cy.on('tap', 'node', (evt) => setSelectedEl(evt.target.data() as NodeData))
    cy.on('tap', 'edge', (evt) => setSelectedEl(evt.target.data() as EdgeData))
    cy.on('tap', (evt) => { if (evt.target === cy) setSelectedEl(null) })
    cyRef.current = cy
  }, [graph])

  useEffect(() => { initCy() }, [initCy])

  function exportPNG() {
    if (!cyRef.current) return
    const png = cyRef.current.png({ full: true, scale: 2, bg: '#05080d' })
    const a = document.createElement('a')
    a.href = png
    a.download = 'attack-paths.png'
    a.click()
  }

  const edgeTypeLabel: Record<string, string> = { c2: 'C2 Session', finding: 'Exploit Path', lateral: 'Lateral Movement' }
  const edgeTypeBadge: Record<string, string> = {
    c2:      'bg-red-900/40 text-red-300 border-red-500/30',
    finding: 'bg-amber-900/40 text-amber-300 border-amber-500/30',
    lateral: 'bg-purple-900/40 text-purple-300 border-purple-500/30',
  }

  const nodeCount = graph?.nodes.length ?? 0
  const edgeCount = graph?.edges.length ?? 0
  const compromisedCount = graph?.nodes.filter(n => n.data.compromised).length ?? 0

  return (
    <div className="flex h-full gap-4 p-6 min-h-0">
      {/* Left panel */}
      <div className="w-60 flex-shrink-0 flex flex-col gap-4 overflow-y-auto">
        {/* Header */}
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <GitBranch size={20} className="text-red-400" />
            Attack Paths
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">Visualise compromise paths</p>
        </div>

        {/* Project selector */}
        <div className="glass rounded-xl p-4 space-y-2">
          <label className="text-xs text-slate-400 font-medium">Project</label>
          <select
            className="w-full bg-slate-900/60 border border-slate-700/50 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500/50"
            value={selectedProject}
            onChange={e => setSelectedProject(e.target.value)}
          >
            {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <button
            onClick={loadGraph}
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg glass glass-hover text-xs text-slate-300 transition-all"
          >
            <RefreshCw size={12} className={loading ? 'animate-spin text-cyan-400' : ''} />
            Refresh
          </button>
        </div>

        {/* Stats */}
        {graph && (
          <div className="glass rounded-xl p-4 space-y-2">
            <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Graph Stats</p>
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">Nodes</span>
                <span className="text-white font-mono">{nodeCount}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">Edges</span>
                <span className="text-white font-mono">{edgeCount}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-400">Compromised</span>
                <span className={`font-mono ${compromisedCount > 0 ? 'text-red-400' : 'text-green-400'}`}>{compromisedCount}</span>
              </div>
            </div>
          </div>
        )}

        {/* Legend */}
        <div className="glass rounded-xl p-4 space-y-2">
          <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Legend</p>
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="w-3 h-0.5 rounded" style={{ background: EDGE_COLORS.c2 }} />
              C2 Session
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="w-3 h-0.5 rounded" style={{ background: EDGE_COLORS.finding }} />
              Exploit Path
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="w-3 h-0.5 rounded" style={{ background: EDGE_COLORS.lateral }} />
              Lateral Movement
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <span className="w-3 h-3 rounded border" style={{ background: '#3f0000', borderColor: '#ef4444' }} />
              Compromised target
            </div>
          </div>
        </div>

        {/* Selection detail */}
        {selectedEl && (
          <div className="glass rounded-xl p-4 space-y-2">
            <p className="text-xs text-slate-400 font-medium uppercase tracking-wider">Selected</p>
            {'type' in selectedEl && (selectedEl as NodeData).type === 'attacker' && (
              <div className="space-y-1">
                <p className="text-sm font-semibold text-cyan-300 flex items-center gap-1"><Shield size={12} /> Attacker</p>
              </div>
            )}
            {'type' in selectedEl && (selectedEl as NodeData).type === 'target' && (() => {
              const n = selectedEl as NodeData
              return (
                <div className="space-y-1">
                  <p className="text-sm font-semibold text-white">
                    {TARGET_ICONS[n.target_type || ''] || '?'} {n.label}
                  </p>
                  <p className={`text-xs ${n.compromised ? 'text-red-400' : 'text-green-400'}`}>
                    {n.compromised ? '⚠ Compromised' : '✓ Not compromised'}
                  </p>
                  {n.finding_counts && Object.keys(n.finding_counts).length > 0 && (
                    <div className="pt-1 space-y-0.5">
                      {Object.entries(n.finding_counts).map(([sev, cnt]) => (
                        <p key={sev} className="text-[11px] text-slate-400">{cnt}x {sev}</p>
                      ))}
                    </div>
                  )}
                </div>
              )
            })()}
            {('type' in selectedEl) && (['c2', 'finding', 'lateral'] as const).includes((selectedEl as EdgeData).type as any) && (() => {
              const e = selectedEl as EdgeData
              return (
                <div className="space-y-1">
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border ${edgeTypeBadge[e.type] || ''}`}>
                    {edgeTypeLabel[e.type] || e.type}
                  </span>
                  {e.count && <p className="text-xs text-slate-400 pt-1">{e.count} exploit(s)</p>}
                  {e.username && <p className="text-xs text-slate-400 font-mono">user: {e.username}</p>}
                  {e.session_type && <p className="text-xs text-slate-400">type: {e.session_type}</p>}
                </div>
              )
            })()}
          </div>
        )}

        {/* Export */}
        {graph && (
          <button
            onClick={exportPNG}
            className="flex items-center justify-center gap-2 px-3 py-2 rounded-lg glass glass-hover text-xs text-slate-300 transition-all"
          >
            <Download size={12} /> Export PNG
          </button>
        )}
      </div>

      {/* Graph canvas */}
      <div className="flex-1 glass rounded-xl relative overflow-hidden">
        {loading && (
          <div className="absolute inset-0 flex items-center justify-center z-10 bg-black/30">
            <RefreshCw size={24} className="animate-spin text-cyan-400" />
          </div>
        )}
        {graph && graph.nodes.length === 0 && !loading && (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500 gap-3">
            <GitBranch size={40} className="opacity-20" />
            <p className="text-sm">No targets in this project yet.</p>
          </div>
        )}
        <div ref={containerRef} className="absolute inset-0" />
      </div>
    </div>
  )
}
