import { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import Icon from '@/components/Icon'
import EmptyState from '@/components/EmptyState'
import { getApiBase } from '@/lib/config'
import { useAppStore } from '@/stores/appStore'
import { useToast } from '@/contexts/ToastContext'

// ── Types ─────────────────────────────────────────────────────────────────────

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

// Positioned node (layout computed client-side)
interface PNode extends GraphNode {
  x: number
  y: number
  owned: boolean
  flagged: boolean
}

// ── Constants ─────────────────────────────────────────────────────────────────

const rule = '1px solid var(--rule)'

const SEV_RANK: Record<string, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
}

// "owned" = critical severity, "flagged" = high severity
function nodeOwned(n: GraphNode): boolean {
  return n.severity === 'critical'
}
function nodeFlagged(n: GraphNode): boolean {
  return n.severity === 'high'
}

// Stable layout: root on left perimeter zone, targets spread across canvas
function computeLayout(data: GraphData): PNode[] {
  const H = 400
  const centerY = H / 2

  const targets = data.nodes.filter(n => n.type === 'target')
  const root    = data.nodes.find(n => n.type === 'root')

  const positioned: PNode[] = []

  if (root) {
    positioned.push({ ...root, x: 60, y: centerY, owned: false, flagged: false })
  }

  // Sort by severity so critical nodes cluster at centre
  const sorted = [...targets].sort((a, b) => {
    const ra = SEV_RANK[a.severity ?? ''] ?? 0
    const rb = SEV_RANK[b.severity ?? ''] ?? 0
    return rb - ra
  })

  const count = sorted.length
  if (count === 0) return positioned

  // Distribute across two columns: perimeter (x≈160-380) and internal (x≈440-760)
  // Split roughly in half
  const half = Math.ceil(count / 2)
  sorted.forEach((n, i) => {
    let x: number, y: number
    if (i < half) {
      // Left column (perimeter)
      const rows = half
      const spacing = Math.min(60, (H - 60) / Math.max(rows, 1))
      x = 200 + (i % 2) * 60
      y = 50 + i * spacing
    } else {
      // Right column (internal)
      const j = i - half
      const rows = count - half
      const spacing = Math.min(60, (H - 60) / Math.max(rows, 1))
      x = 480 + (j % 3) * 70
      y = 50 + j * spacing
    }
    positioned.push({
      ...n,
      x,
      y,
      owned: nodeOwned(n),
      flagged: nodeFlagged(n),
    })
  })

  return positioned
}

// Edge kind heuristic based on severity of target node
function edgeKind(edge: GraphEdge, nodeMap: Map<string, PNode>): string {
  const target = nodeMap.get(edge.target)
  if (!target) return 'recon'
  if (target.owned) return 'attack'
  if (target.flagged) return 'cred'
  return 'recon'
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

function SegBtns({ options, value, onChange }: { options: string[]; value: string; onChange: (v: string) => void }) {
  return (
    <div style={{ display: 'flex', border: rule, height: 26 }}>
      {options.map((o, i) => (
        <button key={o} onClick={() => onChange(o)} style={{
          background: value === o ? 'var(--accent-2)' : 'transparent',
          color: value === o ? 'var(--accent)' : 'var(--fg-3)',
          border: 'none', borderLeft: i > 0 ? rule : 'none',
          padding: '0 10px', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em',
          cursor: 'pointer', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap',
        }}>{o}</button>
      ))}
    </div>
  )
}

function Pill({ tone, children }: { tone: 'fail' | 'warn' | 'pass' | 'info'; children: React.ReactNode }) {
  const styles: Record<string, { color: string; bg: string; border: string }> = {
    fail: { color: 'var(--crit)',   bg: 'rgba(232,64,64,0.1)',   border: 'rgba(232,64,64,0.35)' },
    warn: { color: 'var(--accent)', bg: 'rgba(240,168,58,0.1)',  border: 'rgba(240,168,58,0.35)' },
    pass: { color: 'var(--ok)',     bg: 'rgba(84,175,97,0.1)',   border: 'rgba(84,175,97,0.35)' },
    info: { color: 'var(--fg-3)',   bg: 'rgba(120,120,120,0.1)', border: 'rgba(120,120,120,0.3)' },
  }
  const s = styles[tone]
  return (
    <span className="mono" style={{
      fontSize: 9, padding: '2px 7px', fontWeight: 700, textTransform: 'uppercase',
      letterSpacing: '0.08em', color: s.color, background: s.bg, border: `1px solid ${s.border}`,
    }}>{children}</span>
  )
}

function LegendItem({
  color, dashed, label,
}: {
  color?: string; dashed?: boolean; solid?: boolean; label: string
}) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      {color
        ? <div style={{ width: 10, height: 10, background: color, flexShrink: 0 }} />
        : dashed
        ? <div style={{ width: 16, height: 0, borderTop: '1px dashed var(--fg-3)', flexShrink: 0 }} />
        : <div style={{ width: 16, height: 0, borderTop: '1px solid var(--crit)', flexShrink: 0 }} />
      }
      <span className="mono" style={{ fontSize: 9, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</span>
    </div>
  )
}

// ── NodeDetail right pane ─────────────────────────────────────────────────────

interface NodeDetailProps {
  node: PNode | null
  edges: GraphEdge[]
  nodeMap: Map<string, PNode>
  tags: string[]
  onAddTag: (tag: string) => void
  onRemoveTag: (tag: string) => void
  onRescan: (node: PNode) => void
  onSpray: (node: PNode) => void
  onOpenShell: (node: PNode) => void
}

function NodeDetail({ node, edges, nodeMap, tags, onAddTag, onRemoveTag, onRescan, onSpray, onOpenShell }: NodeDetailProps) {
  const tagInputRef = useRef<HTMLInputElement>(null)
  const [tagDraft, setTagDraft] = useState('')
  if (!node) {
    return (
      <div style={{
        background: 'var(--bg-2)', display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center', gap: 10, padding: 'var(--pad)',
      }}>
        <Icon name="target" size={28} color="var(--rule-strong)" />
        <span className="mono" style={{ fontSize: 11, color: 'var(--fg-4)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
          select a node
        </span>
      </div>
    )
  }

  const nodeEdges = edges.filter(e => e.source === node.id || e.target === node.id)

  const kindTone = (k: string): 'fail' | 'warn' | 'pass' | 'info' => {
    if (k === 'attack' || k === 'pivot') return 'fail'
    if (k === 'cred') return 'warn'
    return 'info'
  }

  const sevTone = (sev: string | null): 'fail' | 'warn' | 'pass' | 'info' => {
    if (sev === 'critical') return 'fail'
    if (sev === 'high') return 'warn'
    if (sev === 'medium' || sev === 'low') return 'pass'
    return 'info'
  }

  const kvItems = [
    { k: 'type',     v: node.target_type?.replace(/_/g, ' ') ?? '—' },
    { k: 'severity', v: node.severity ?? 'none' },
    { k: 'findings', v: String(node.finding_count) },
    { k: 'subnet',   v: node.type === 'root' ? 'internal / seraph' : '10.40.0.0/16' },
  ]

  return (
    <div style={{ overflowY: 'auto', background: 'var(--bg-2)' }}>
      {/* Header */}
      <div style={{ padding: '18px var(--pad)', borderBottom: '1px solid var(--rule)' }}>
        <div className="smcap" style={{ color: 'var(--fg-3)', marginBottom: 4 }}>node · {node.id}</div>
        <h2 style={{ margin: '6px 0 0', fontFamily: 'var(--font-mono)', fontWeight: 500, fontSize: 22, color: 'var(--fg)' }}>
          {node.label}
        </h2>
        <div style={{ display: 'flex', gap: 8, marginTop: 10, flexWrap: 'wrap' }}>
          {node.owned && <Pill tone="fail">compromised</Pill>}
          {node.flagged && <Pill tone="warn">flagged</Pill>}
          <Pill tone="info">{node.type}</Pill>
          {node.severity && <Pill tone={sevTone(node.severity)}>{node.severity}</Pill>}
        </div>
      </div>

      {/* Body */}
      <div style={{ padding: 'var(--pad)' }}>
        {/* KV grid */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 0, marginBottom: 18 }}>
          {kvItems.map(({ k, v }) => (
            <div key={k} style={{
              display: 'flex', alignItems: 'baseline', gap: 8,
              padding: '6px 0', borderBottom: '1px solid var(--rule)',
            }}>
              <span className="mono" style={{
                fontSize: 9, color: 'var(--fg-3)', textTransform: 'uppercase',
                letterSpacing: '0.08em', width: 72, flexShrink: 0,
              }}>{k}</span>
              <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>{v}</span>
            </div>
          ))}
        </div>

        {/* Edges */}
        {nodeEdges.length > 0 && (
          <div style={{ marginBottom: 18 }}>
            <div className="smcap" style={{ marginBottom: 8, color: 'var(--fg-3)' }}>
              Edges · {nodeEdges.length}
            </div>
            {nodeEdges.map((e, i) => {
              const isOut = e.source === node.id
              const otherId = isOut ? e.target : e.source
              const other = nodeMap.get(otherId)
              const k = edgeKind(e, nodeMap)
              return (
                <div key={i} style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '6px 0', borderBottom: '1px dashed var(--rule)',
                }}>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>
                    {isOut ? '→ ' : '← '}{other?.label ?? otherId}
                  </span>
                  <Pill tone={kindTone(k)}>{k}</Pill>
                </div>
              )
            })}
          </div>
        )}

        {/* Tags */}
        {node.type === 'target' && (
          <div style={{ marginBottom: 18 }}>
            <div className="smcap" style={{ marginBottom: 8, color: 'var(--fg-3)' }}>Tags</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              {tags.map(tag => (
                <span key={tag} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10, background: 'rgba(240,168,58,0.08)', color: 'var(--accent)', border: '1px solid rgba(240,168,58,0.25)', padding: '2px 8px' }}>
                  {tag}
                  <button onClick={() => onRemoveTag(tag)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--accent)', padding: 0, display: 'flex' }}>
                    <Icon name="x" size={9} />
                  </button>
                </span>
              ))}
              <input
                ref={tagInputRef}
                type="text"
                placeholder="add tag…"
                value={tagDraft}
                onChange={e => setTagDraft(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && tagDraft.trim()) { onAddTag(tagDraft.trim()); setTagDraft('') } }}
                style={{ background: 'transparent', fontSize: 10, color: 'var(--fg-3)', outline: 'none', width: 80, border: 'none', borderBottom: rule }}
              />
            </div>
          </div>
        )}

        {/* Quick actions */}
        {node.type === 'target' && (
          <div>
            <div className="smcap" style={{ marginBottom: 8, color: 'var(--fg-3)' }}>Quick actions</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
              <button className="btn btn-sm" style={{ display: 'flex', alignItems: 'center', gap: 5, justifyContent: 'center' }} onClick={() => onOpenShell(node)}>
                <Icon name="terminal" size={9} />Open shell
              </button>
              <button className="btn btn-sm" style={{ display: 'flex', alignItems: 'center', gap: 5, justifyContent: 'center' }} onClick={() => onRescan(node)}>
                <Icon name="target" size={9} />Re-scan
              </button>
              <button className="btn btn-sm" style={{ display: 'flex', alignItems: 'center', gap: 5, justifyContent: 'center' }} onClick={() => onSpray(node)}>
                <Icon name="key" size={9} />Spray creds
              </button>
              <button className="btn btn-sm" style={{ display: 'flex', alignItems: 'center', gap: 5, justifyContent: 'center' }} onClick={() => tagInputRef.current?.focus()}>
                <Icon name="flag" size={9} />Tag
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

// Node tags persist locally per project (no backend node-tag store).
function tagsStorageKey(projectId: string) { return `seraph:netmap:tags:${projectId}` }
function loadNodeTags(projectId: string): Record<string, string[]> {
  if (!projectId) return {}
  try { return JSON.parse(localStorage.getItem(tagsStorageKey(projectId)) ?? '{}') } catch { return {} }
}

export default function NetworkMap() {
  const { selectedProject: sp } = useAppStore()
  const projectId = sp?.id ?? ''
  const navigate = useNavigate()
  const toast = useToast()

  const [graph,   setGraph]   = useState<GraphData | null>(null)
  const [loading, setLoading] = useState(false)
  const [layout,  setLayout]  = useState('attack-path')
  const [selId,   setSelId]   = useState<string | null>(null)
  const [nodeTags, setNodeTags] = useState<Record<string, string[]>>({})

  // Load/persist per-project node tags from localStorage.
  useEffect(() => { setNodeTags(loadNodeTags(projectId)) }, [projectId])
  useEffect(() => {
    if (projectId) localStorage.setItem(tagsStorageKey(projectId), JSON.stringify(nodeTags))
  }, [projectId, nodeTags])

  function addNodeTag(nodeId: string, tag: string) {
    setNodeTags(prev => {
      const existing = prev[nodeId] ?? []
      if (existing.includes(tag)) return prev
      return { ...prev, [nodeId]: [...existing, tag] }
    })
  }
  function removeNodeTag(nodeId: string, tag: string) {
    setNodeTags(prev => ({ ...prev, [nodeId]: (prev[nodeId] ?? []).filter(t => t !== tag) }))
  }

  // Quick actions: hand the host off to the Pentest Workbench (which runs the tool over WS).
  function rescanNode(node: PNode) {
    navigate('/pentest', { state: { targetId: node.id, phaseId: 'scanning' } })
  }
  function sprayNode(node: PNode) {
    navigate('/pentest', { state: { targetId: node.id, phaseId: 'enumeration' } })
  }
  function openShell(_node: PNode) {
    navigate('/c2')
  }

  // Export the current graph as GraphML (client-side).
  function exportGraphml() {
    if (!graph || graph.nodes.length === 0) { toast.error('No graph to export'); return }
    const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
    const nodeXml = graph.nodes.map(n =>
      `    <node id="${esc(n.id)}">\n` +
      `      <data key="label">${esc(n.label)}</data>\n` +
      `      <data key="type">${esc(n.type)}</data>\n` +
      `      <data key="severity">${esc(n.severity ?? '')}</data>\n` +
      `      <data key="findings">${n.finding_count}</data>\n` +
      `    </node>`
    ).join('\n')
    const edgeXml = graph.edges.map((e, i) =>
      `    <edge id="e${i}" source="${esc(e.source)}" target="${esc(e.target)}"/>`
    ).join('\n')
    const xml =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n` +
      `  <key id="label" for="node" attr.name="label" attr.type="string"/>\n` +
      `  <key id="type" for="node" attr.name="type" attr.type="string"/>\n` +
      `  <key id="severity" for="node" attr.name="severity" attr.type="string"/>\n` +
      `  <key id="findings" for="node" attr.name="findings" attr.type="int"/>\n` +
      `  <graph edgedefault="directed">\n${nodeXml}\n${edgeXml}\n  </graph>\n` +
      `</graphml>\n`
    const url = URL.createObjectURL(new Blob([xml], { type: 'application/xml' }))
    const a = document.createElement('a')
    a.href = url
    a.download = `network-${sp?.name ?? 'graph'}.graphml`
    a.click()
    URL.revokeObjectURL(url)
    toast.success('Exported GraphML')
  }

  // ── Fetch ──────────────────────────────────────────────────────────────────

  const loadGraph = useCallback(async () => {
    if (!projectId) return
    setLoading(true)
    setSelId(null)
    try {
      const res  = await fetch(`${getApiBase()}/network/graph?project_id=${projectId}`)
      const data = await res.json()
      setGraph(data)
    } finally {
      setLoading(false)
    }
  }, [projectId])

  useEffect(() => { loadGraph() }, [loadGraph])

  // ── Derived layout ─────────────────────────────────────────────────────────

  const pNodes: PNode[] = graph ? computeLayout(graph) : []
  const nodeMap = new Map(pNodes.map(n => [n.id, n]))
  const edges   = graph?.edges ?? []
  const selNode = selId ? (nodeMap.get(selId) ?? null) : null

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
      <PageHeader
        breadcrumb={`${sp?.name ?? 'no project'} · network`}
        title="Network Map · Attack Paths"
        sub="Discovered hosts, exploit chains, and credential reuse. Click a node to inspect its neighbourhood and pivot ledger."
        right={(
          <>
            <SegBtns
              options={['attack-path', 'subnet', 'risk-heat']}
              value={layout}
              onChange={setLayout}
            />
            <button className="btn" onClick={loadGraph} disabled={!projectId || loading}>
              <Icon name="refresh" size={11} />{loading ? ' Loading…' : ' Re-scan'}
            </button>
            <button className="btn btn-primary" style={{ color: '#1a1408' }} onClick={exportGraphml} disabled={!graph}>
              <Icon name="download" size={11} color="#1a1408" /> Export graphml
            </button>
          </>
        )}
      />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', flex: 1, minHeight: 0 }}>
        {/* ── Left: canvas pane ── */}
        <div style={{ position: 'relative', overflow: 'hidden', borderRight: '1px solid var(--rule)', background: 'var(--bg)' }}>

          {/* Dot grid */}
          <div style={{
            position: 'absolute', inset: 0, pointerEvents: 'none',
            backgroundImage: 'linear-gradient(var(--rule-2) 1px, transparent 1px), linear-gradient(90deg, var(--rule-2) 1px, transparent 1px)',
            backgroundSize: '40px 40px',
          }} />

          {/* Annotations */}
          <div style={{ position: 'absolute', top: 20, left: 30, pointerEvents: 'none' }}>
            <div className="smcap" style={{ color: 'var(--fg-3)' }}>PERIMETER · /24 EXTERNAL</div>
          </div>
          <div style={{ position: 'absolute', top: 20, left: 440, pointerEvents: 'none' }}>
            <div className="smcap" style={{ color: 'var(--fg-3)' }}>INTERNAL · CORP.ARGENT.LOCAL</div>
          </div>

          {/* Zoom/pan HUD */}
          <div className="mono" style={{
            position: 'absolute', top: 12, right: 16, pointerEvents: 'none',
            fontSize: 9.5, color: 'var(--fg-4)', letterSpacing: '0.1em', textTransform: 'uppercase',
          }}>
            zoom 1.0 · pan 0,0 · nodes {pNodes.length} · edges {edges.length}
          </div>

          {/* Legend */}
          <div style={{
            position: 'absolute', bottom: 16, right: 24,
            display: 'flex', gap: 14, alignItems: 'center',
            background: 'var(--bg)', padding: '8px 12px', border: '1px solid var(--rule)',
          }}>
            <LegendItem color="var(--crit)"   label="compromised" />
            <LegendItem color="var(--accent)" label="flagged" />
            <LegendItem color="var(--fg-3)"   label="seen" />
            <span style={{ width: 1, height: 14, background: 'var(--rule)', flexShrink: 0 }} />
            <LegendItem dashed label="recon" />
            <LegendItem solid  label="exploit" />
          </div>

          {/* Blast-radius overlay */}
          {graph && pNodes.length > 0 && (() => {
            const critNodes = pNodes.filter(n => n.owned)
            if (critNodes.length === 0) return null
            return (
              <div style={{
                position: 'absolute', bottom: 70, left: 24,
                padding: '10px 14px', border: '1px solid var(--rule)',
                background: 'var(--bg-2)', maxWidth: 340,
              }}>
                <div className="smcap" style={{ color: 'var(--crit)', marginBottom: 6 }}>
                  BLAST RADIUS · CHAIN A
                </div>
                <div className="mono" style={{ fontSize: 11.5, color: 'var(--fg-2)', lineHeight: 1.65 }}>
                  {critNodes.slice(0, 5).map((n, i) => (
                    <span key={n.id} style={{ display: 'block' }}>
                      <span style={{ color: i === critNodes.length - 1 ? 'var(--crit)' : 'var(--fg-3)' }}>
                        ({i + 1})
                      </span>{' '}{n.label} · compromised
                    </span>
                  ))}
                </div>
                <div className="mono" style={{
                  fontSize: 10, color: 'var(--accent)', marginTop: 8,
                  textTransform: 'uppercase', letterSpacing: '0.12em',
                }}>
                  nodes compromised · {critNodes.length}
                </div>
              </div>
            )
          })()}

          {/* SVG graph */}
          <svg
            width="100%" height="100%"
            viewBox="0 0 820 400"
            style={{ position: 'absolute', inset: 0, cursor: 'default' }}
            onClick={() => setSelId(null)}
          >
            <defs>
              <marker id="arrow-accent" viewBox="0 -3 6 6" refX="5" refY="0" markerWidth="6" markerHeight="6" orient="auto">
                <path d="M 0 -2 L 5 0 L 0 2" fill="var(--accent)" />
              </marker>
              <marker id="arrow-crit" viewBox="0 -3 6 6" refX="5" refY="0" markerWidth="6" markerHeight="6" orient="auto">
                <path d="M 0 -2 L 5 0 L 0 2" fill="var(--crit)" />
              </marker>
            </defs>

            {/* Edges */}
            {edges.map((e, i) => {
              const a = nodeMap.get(e.source)
              const b = nodeMap.get(e.target)
              if (!a || !b) return null
              const k = edgeKind(e, nodeMap)
              const isAttack = k === 'attack' || k === 'pivot'
              const isCred   = k === 'cred'
              const color    = isAttack ? 'var(--crit)' : isCred ? 'var(--accent)' : 'var(--fg-4)'
              return (
                <line
                  key={i}
                  x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                  stroke={color}
                  strokeWidth={isAttack ? 1.5 : 1}
                  strokeDasharray={!isAttack && !isCred ? '3 4' : undefined}
                  markerEnd={isAttack ? 'url(#arrow-crit)' : isCred ? 'url(#arrow-accent)' : undefined}
                  opacity={isAttack ? 0.95 : isCred ? 0.85 : 0.5}
                />
              )
            })}

            {/* Vertical divider — perimeter vs internal */}
            <line x1="410" y1="40" x2="410" y2="370" stroke="var(--rule-strong)" strokeDasharray="2 6" />

            {/* Nodes */}
            {pNodes.map(n => {
              const isSel = selId === n.id
              return (
                <g
                  key={n.id}
                  style={{ cursor: 'pointer' }}
                  onClick={ev => { ev.stopPropagation(); setSelId(n.id) }}
                >
                  {/* Selection halo */}
                  {isSel && (
                    <rect
                      x={n.x - 38} y={n.y - 18} width={76} height={36}
                      fill="none"
                      stroke="var(--accent)"
                      strokeWidth="1"
                      strokeDasharray="3 3"
                    />
                  )}
                  {/* Node body */}
                  <rect
                    x={n.x - 34} y={n.y - 14} width={68} height={28}
                    fill={n.owned ? 'rgba(232,92,78,0.12)' : 'var(--bg-2)'}
                    stroke={n.owned ? 'var(--crit)' : n.flagged ? 'var(--accent)' : 'var(--fg-4)'}
                    strokeWidth="1.2"
                  />
                  {/* Status dot */}
                  <circle
                    cx={n.x - 28} cy={n.y - 8} r="2.4"
                    fill={n.owned ? 'var(--crit)' : n.flagged ? 'var(--accent)' : 'var(--fg-4)'}
                  />
                  {/* Label */}
                  <text
                    x={n.x} y={n.y + 4}
                    textAnchor="middle"
                    className="mono"
                    style={{ fontSize: 10.5, fill: 'var(--fg)', letterSpacing: '0.04em' }}
                  >
                    {n.label.length > 10 ? n.label.slice(0, 9) + '…' : n.label}
                  </text>
                </g>
              )
            })}
          </svg>

          {/* Empty / loading overlays */}
          {!graph && !loading && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
              <EmptyState icon="network" title="Select an engagement to visualize" hint="Pick a project from the sidebar to render its hosts, services, and relationships." />
            </div>
          )}
          {loading && (
            <div style={{
              position: 'absolute', inset: 0,
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10,
              pointerEvents: 'none',
            }}>
              <Icon name="refresh" size={18} color="var(--accent)" />
              <span className="mono" style={{ fontSize: 12, color: 'var(--fg-3)', letterSpacing: '0.08em' }}>
                BUILDING GRAPH…
              </span>
            </div>
          )}
          {graph && pNodes.filter(n => n.type === 'target').length === 0 && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
              <EmptyState icon="target" title="No targets in this engagement" hint="Add targets to the project to map the network." />
            </div>
          )}
        </div>

        {/* ── Right: node detail pane ── */}
        <NodeDetail
          node={selNode}
          edges={edges}
          nodeMap={nodeMap}
          tags={selNode ? (nodeTags[selNode.id] ?? []) : []}
          onAddTag={tag => selNode && addNodeTag(selNode.id, tag)}
          onRemoveTag={tag => selNode && removeNodeTag(selNode.id, tag)}
          onRescan={rescanNode}
          onSpray={sprayNode}
          onOpenShell={openShell}
        />
      </div>
    </div>
  )
}
