import { useState, useEffect, useRef, useCallback } from 'react'
import cytoscape from 'cytoscape'
import {
  Network, ZoomIn, ZoomOut, Maximize2, Download, RefreshCw, Shield,
} from 'lucide-react'
import type { Project } from '../types/index'

interface GraphNode {
  id: string
  label: string
  type: 'root' | 'target'
  severity: string | null
  finding_count: number
  target_type: string | null
}

interface GraphEdge {
  source: string
  target: string
}

interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

const SEVERITY_COLOR: Record<string, { bg: string; border: string; glow: string }> = {
  critical: { bg: '#3f0000', border: '#ef4444', glow: 'rgba(239,68,68,0.6)' },
  high:     { bg: '#3a1500', border: '#f97316', glow: 'rgba(249,115,22,0.5)' },
  medium:   { bg: '#2d2000', border: '#f59e0b', glow: 'rgba(245,158,11,0.4)' },
  low:      { bg: '#002d1a', border: '#22c55e', glow: 'rgba(34,197,94,0.4)' },
  info:     { bg: '#001a2d', border: '#3b82f6', glow: 'rgba(59,130,246,0.4)' },
  none:     { bg: '#0d1520', border: '#334155', glow: 'rgba(51,65,85,0.3)' },
}

const TARGET_ICONS: Record<string, string> = {
  linux_host: '🖥',
  windows_host: '🪟',
  web_app: '🌐',
  cloud_aws: '☁',
  network: '🔗',
}

export default function NetworkMap() {
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedProject, setSelectedProject] = useState('')
  const [graph, setGraph] = useState<GraphData | null>(null)
  const [loading, setLoading] = useState(false)
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null)
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
    setSelectedNode(null)
    const res = await fetch(`/api/v1/network/graph?project_id=${selectedProject}`)
    const data = await res.json()
    setGraph(data)
    setLoading(false)
  }

  const initCy = useCallback(() => {
    if (!graph || !containerRef.current) return
    if (cyRef.current) cyRef.current.destroy()

    const elements: cytoscape.ElementDefinition[] = [
      ...graph.nodes.map(n => {
        const col = n.type === 'root'
          ? { bg: '#001a2d', border: '#06b6d4', glow: 'rgba(6,182,212,0.7)' }
          : SEVERITY_COLOR[n.severity || 'none']
        return {
          data: { ...n, ...col },
        }
      }),
      ...graph.edges.map((e, i) => ({
        data: { id: `e${i}`, source: e.source, target: e.target },
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
          selector: 'node[type="root"]',
          style: {
            'shape': 'diamond',
            'width': 52,
            'height': 52,
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 3,
            'border-color': '#06b6d4',
          },
        },
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color': '#1e3a4a',
            'target-arrow-color': '#1e3a4a',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'opacity': 0.7,
          },
        },
        {
          selector: 'edge:selected',
          style: { 'line-color': '#06b6d4', 'target-arrow-color': '#06b6d4', 'opacity': 1 },
        },
      ],
      layout: {
        name: 'cose',
        animate: true,
        animationDuration: 600,
        nodeRepulsion: () => 8000,
        idealEdgeLength: () => 120,
        gravity: 0.8,
        randomize: false,
      } as any,
      minZoom: 0.2,
      maxZoom: 4,
      userZoomingEnabled: true,
      userPanningEnabled: true,
    })

    cy.on('tap', 'node', (evt) => {
      const nodeData = evt.target.data() as GraphNode & { bg: string; border: string; glow: string }
      setSelectedNode(nodeData)
    })

    cy.on('tap', (evt) => {
      if (evt.target === cy) setSelectedNode(null)
    })

    cyRef.current = cy
  }, [graph])

  useEffect(() => { initCy() }, [initCy])

  function exportPNG() {
    if (!cyRef.current) return
    const png = cyRef.current.png({ full: true, scale: 2, bg: '#05080d' })
    const a = document.createElement('a')
    a.href = png
    a.download = 'network-map.png'
    a.click()
  }

  const severityBadge = (sev: string | null) => {
    const s = sev || 'none'
    const styles: Record<string, string> = {
      critical: 'bg-red-950/60 text-red-400 border-red-500/50',
      high:     'bg-orange-950/60 text-orange-400 border-orange-500/40',
      medium:   'bg-amber-950/40 text-amber-400 border-amber-500/30',
      low:      'bg-green-950/40 text-green-400 border-green-500/30',
      info:     'bg-blue-950/40 text-blue-400 border-blue-500/30',
      none:     'bg-slate-800/60 text-slate-400 border-slate-600/30',
    }
    return (
      <span className={`text-xs px-2 py-0.5 rounded-full border font-semibold uppercase ${styles[s]}`}>
        {s === 'none' ? 'clean' : s}
      </span>
    )
  }

  return (
    <div className="flex h-full gap-4 min-h-0">
      {/* Left panel */}
      <div className="w-64 flex-shrink-0 flex flex-col gap-4 overflow-y-auto min-h-0">
        {/* Project selector */}
        <div className="glass glass-hover rounded-xl p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Project</h3>
          <select
            value={selectedProject}
            onChange={e => setSelectedProject(e.target.value)}
            className="w-full rounded px-3 py-2 text-xs text-slate-200 focus:outline-none border border-cyan-900/20 focus:border-cyan-500/50 bg-[#05080d]"
          >
            <option value="">Select project...</option>
            {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <button
            onClick={loadGraph}
            disabled={!selectedProject || loading}
            className="mt-2 w-full flex items-center justify-center gap-2 py-1.5 rounded-lg border border-cyan-900/30 text-xs text-slate-400 hover:text-cyan-400 hover:border-cyan-700/50 disabled:opacity-40 transition-all"
          >
            <RefreshCw size={11} className={loading ? 'animate-spin' : ''} />
            {loading ? 'Loading...' : 'Refresh'}
          </button>
        </div>

        {/* Legend */}
        <div className="glass rounded-xl p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Legend</h3>
          <div className="space-y-2">
            {(['critical','high','medium','low','info','none'] as const).map(sev => {
              const c = SEVERITY_COLOR[sev]
              return (
                <div key={sev} className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full flex-shrink-0" style={{ background: c.bg, border: `2px solid ${c.border}`, boxShadow: `0 0 6px ${c.glow}` }} />
                  <span className="text-xs text-slate-400 capitalize">{sev === 'none' ? 'No findings' : sev}</span>
                </div>
              )
            })}
            <div className="flex items-center gap-2 mt-1">
              <div className="w-3 h-3 flex-shrink-0" style={{ background: '#001a2d', border: '2px solid #06b6d4', transform: 'rotate(45deg)', boxShadow: '0 0 6px rgba(6,182,212,0.7)' }} />
              <span className="text-xs text-slate-400">Seraph (root)</span>
            </div>
          </div>
        </div>

        {/* Selected node detail */}
        {selectedNode && selectedNode.type === 'target' && (
          <div className="glass rounded-xl p-4 border border-cyan-900/30">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Node Detail</h3>
            <div className="space-y-2">
              <div className="font-mono text-sm text-cyan-400 break-all">{selectedNode.label}</div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-500">Risk:</span>
                {severityBadge(selectedNode.severity)}
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-500">Type:</span>
                <span className="text-xs text-slate-300">
                  {TARGET_ICONS[selectedNode.target_type || ''] || '🎯'} {(selectedNode.target_type || '').replace(/_/g, ' ')}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-500">Findings:</span>
                <span className="text-xs font-mono text-slate-300">{selectedNode.finding_count}</span>
              </div>
            </div>
          </div>
        )}

        {/* Stats */}
        {graph && (
          <div className="glass rounded-xl p-4">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Stats</h3>
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Targets</span>
                <span className="font-mono text-slate-300">{graph.nodes.filter(n => n.type === 'target').length}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-slate-500">Connections</span>
                <span className="font-mono text-slate-300">{graph.edges.length}</span>
              </div>
              {(['critical','high','medium'] as const).map(sev => {
                const count = graph.nodes.filter(n => n.severity === sev).length
                if (!count) return null
                return (
                  <div key={sev} className="flex justify-between text-xs">
                    <span className="text-slate-500 capitalize">{sev}</span>
                    <span className={`font-mono ${sev === 'critical' ? 'text-red-400' : sev === 'high' ? 'text-orange-400' : 'text-amber-400'}`}>{count}</span>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* Graph canvas */}
      <div className="flex-1 flex flex-col min-w-0 min-h-0">
        {/* Toolbar */}
        <div className="flex items-center justify-between mb-3 flex-shrink-0">
          <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
            <Network size={18} className="text-cyan-400" /> Network Map
          </h2>
          <div className="flex items-center gap-2">
            <button
              onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 1.2)}
              className="p-1.5 rounded border border-cyan-900/20 text-slate-400 hover:text-cyan-400 hover:border-cyan-700/40 transition-all"
            ><ZoomIn size={14} /></button>
            <button
              onClick={() => cyRef.current?.zoom(cyRef.current.zoom() / 1.2)}
              className="p-1.5 rounded border border-cyan-900/20 text-slate-400 hover:text-cyan-400 hover:border-cyan-700/40 transition-all"
            ><ZoomOut size={14} /></button>
            <button
              onClick={() => cyRef.current?.fit(undefined, 40)}
              className="p-1.5 rounded border border-cyan-900/20 text-slate-400 hover:text-cyan-400 hover:border-cyan-700/40 transition-all"
              title="Fit all"
            ><Maximize2 size={14} /></button>
            <button
              onClick={exportPNG}
              disabled={!graph}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-cyan-900/20 text-xs text-slate-400 hover:text-cyan-400 hover:border-cyan-700/40 disabled:opacity-40 transition-all"
            ><Download size={12} /> Export PNG</button>
          </div>
        </div>

        {/* Canvas */}
        <div className="flex-1 min-h-0 rounded-xl border border-cyan-900/20 overflow-hidden relative" style={{ background: '#05080d' }}>
          <div ref={containerRef} className="absolute inset-0" />

          {!graph && !loading && (
            <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500">
              <Network size={40} className="mb-3 opacity-30 text-cyan-600" />
              <p className="text-sm">Select a project to visualize its network</p>
            </div>
          )}

          {loading && (
            <div className="absolute inset-0 flex items-center justify-center text-slate-400">
              <RefreshCw size={20} className="animate-spin mr-2 text-cyan-500" />
              <span className="text-sm">Building graph...</span>
            </div>
          )}

          {graph && graph.nodes.filter(n => n.type === 'target').length === 0 && (
            <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-500">
              <Shield size={40} className="mb-3 opacity-30 text-cyan-600" />
              <p className="text-sm">No targets found in this project</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
