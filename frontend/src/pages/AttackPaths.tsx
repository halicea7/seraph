import { useState, useEffect } from 'react'
import Icon from '@/components/Icon'
import { getApiBase } from '@/lib/config'
import { useAppStore } from '@/stores/appStore'

// ── Types ─────────────────────────────────────────────────────────────────────

interface NodeData {
  id: string
  label: string
  type: 'attacker' | 'target' | 'ad_domain'
  target_type?: string
  compromised?: boolean
  finding_counts?: Record<string, number>
}

interface EdgeData {
  id: string
  source: string
  target: string
  label: string
  type: 'c2' | 'finding' | 'lateral' | 'ad'
  count?: number
  username?: string
  session_type?: string
  status?: string
  platform?: string
  via_payload?: string
  kind?: string
  severity?: string
  command?: string
}

interface GraphData {
  nodes: { data: NodeData }[]
  edges: { data: EdgeData }[]
}

interface PathStep {
  tool: string
  title: string
  sev: string
  description: string
  command: string
}

interface AttackChain {
  id: string
  impact: string
  cvss: number
  steps: PathStep[]
  time: string
}

// ── Constants ─────────────────────────────────────────────────────────────────

const rule = '1px solid var(--rule)'

const SORT_OPTIONS = ['by impact', 'by complexity', 'shortest']

const EDGE_TYPE_TOOL: Record<string, string> = {
  c2:      'C2 implant',
  finding: 'exploit',
  lateral: 'cred-reuse',
  ad:      'AD',
}

const EDGE_TYPE_IMPACT: Record<string, string> = {
  c2:      'Critical',
  finding: 'High',
  lateral: 'Medium',
  ad:      'High',
}

const SEVERITY_TO_IMPACT: Record<string, string> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info',
}

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

function SevBadge({ sev }: { sev: string }) {
  const c = sev === 'Critical' ? 'var(--crit)' : sev === 'High' ? 'var(--high)' : sev === 'Medium' ? 'var(--med)' : 'var(--low)'
  return (
    <span className="mono" style={{ fontSize: 10, color: c, padding: '2px 6px', border: `1px solid ${c}`, background: `${c}18` }}>{sev}</span>
  )
}

// ── Build chains from graph data ───────────────────────────────────────────────

// Picks the real re-exploit command for a C2 entry step instead of a
// hardcoded windows/x64/meterpreter guess, which was wrong for e.g. a Linux
// php/reverse_php shell -- exactly the kind of session this lab produces.
function c2Command(entry: EdgeData): string {
  if (entry.via_payload) {
    return `use exploit/multi/handler; set PAYLOAD ${entry.via_payload}`
  }
  const platform = (entry.platform ?? '').toLowerCase()
  if (platform.includes('win')) return 'use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp'
  if (platform.includes('linux') || platform.includes('unix')) return 'use exploit/multi/handler; set PAYLOAD linux/x64/meterpreter/reverse_tcp'
  if (platform.includes('osx') || platform.includes('mac')) return 'use exploit/multi/handler; set PAYLOAD osx/x64/meterpreter/reverse_tcp'
  if (platform.includes('php')) return 'use exploit/multi/handler; set PAYLOAD php/meterpreter/reverse_tcp'
  // No session platform/payload data at all -- the Windows default is a
  // guess, not a known fact, so say so rather than presenting it as certain.
  return 'use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp  # platform unknown, verify before running'
}

// Same idea for the "exploit a finding" entry step: nxc smb/psexec only
// makes sense against a Windows/SMB-reachable network target, not a web
// app or API endpoint (the lab's actual DVWA/Juice Shop/VAmPI targets).
function findingCommand(targetType: string | undefined): string {
  switch (targetType) {
    case 'web_app':
      return 'sqlmap -u "http://{target}/vuln.php?id=1" --batch --os-shell'
    case 'api_endpoint':
      return 'ffuf -u http://{target}/FUZZ -w endpoints.txt -mc 200,401,403'
    case 'cloud_aws':
    case 'cloud_azure':
    case 'cloud_gcp':
      return 'curl -s http://169.254.169.254/latest/meta-data/ # cloud metadata SSRF'
    default:
      return 'nxc smb {target} -u {user} -p {pass} --exec-method mmcexec'
  }
}

function buildChains(graph: GraphData): AttackChain[] {
  const edges = graph.edges.map(e => e.data)
  const nodeMap = new Map(graph.nodes.map(n => [n.data.id, n.data]))

  // Each edge from attacker is an entry point; lateral edges extend chains
  const attackerEdges = edges.filter(e => e.source === 'attacker')
  const lateralEdges  = edges.filter(e => e.type === 'lateral')

  const chains: AttackChain[] = []

  attackerEdges.forEach((entry, idx) => {
    const target = nodeMap.get(entry.target)
    if (!target) return

    const findingCounts = target.finding_counts ?? {}
    const topSev = ['Critical', 'High', 'Medium', 'Low'].find(s => findingCounts[s.toLowerCase()] || findingCounts[s])
    const impact = entry.type === 'ad'
      ? (SEVERITY_TO_IMPACT[entry.severity ?? 'medium'] ?? 'Medium')
      : (topSev ?? EDGE_TYPE_IMPACT[entry.type] ?? 'Medium')
    const cvss = impact === 'Critical' ? 9.8 : impact === 'High' ? 7.5 : impact === 'Medium' ? 5.0 : 3.0

    const edgeTool = EDGE_TYPE_TOOL[entry.type] ?? 'access'
    let entryStep: PathStep
    let reconStep: PathStep
    if (entry.type === 'c2') {
      reconStep = { tool: 'recon', title: 'Initial recon', sev: 'Info', description: 'Enumerate open ports, services, and OS fingerprint', command: 'nmap -sV -sC -O -T4 {target}' }
      entryStep = { tool: edgeTool, title: target.label, sev: impact, description: 'Deploy implant via exploit and establish callback', command: c2Command(entry) }
    } else if (entry.type === 'finding') {
      reconStep = { tool: 'recon', title: 'Initial recon', sev: 'Info', description: 'Enumerate open ports, services, and OS fingerprint', command: 'nmap -sV -sC -O -T4 {target}' }
      entryStep = { tool: edgeTool, title: target.label, sev: impact, description: 'Exploit identified vulnerability to gain code execution', command: findingCommand(target.target_type) }
    } else if (entry.type === 'ad') {
      // Quick wins are domain-wide BloodHound/SharpHound findings (kerberoast,
      // AS-REP, delegation, ...) -- the command is already the real,
      // correctly-formed impacket/nxc command from services/ad_analysis.py,
      // not a guess, so use it verbatim rather than synthesizing one.
      reconStep = { tool: 'recon', title: 'Domain recon', sev: 'Info', description: 'Collect AD objects and relationships (BloodHound/SharpHound)', command: 'SharpHound.exe -c All' }
      entryStep = { tool: edgeTool, title: entry.label, sev: impact, description: `${entry.count ?? 0} affected principal(s)`, command: entry.command || '# no command available' }
    } else {
      reconStep = { tool: 'recon', title: 'Initial recon', sev: 'Info', description: 'Enumerate open ports, services, and OS fingerprint', command: 'nmap -sV -sC -O -T4 {target}' }
      entryStep = { tool: edgeTool, title: target.label, sev: impact, description: 'Reuse captured credentials for lateral movement', command: 'impacket-psexec {domain}/{user}:{pass}@{target}' }
    }

    const baseSteps: PathStep[] = [reconStep, entryStep]

    // Check for lateral movement from this target
    const laterals = lateralEdges.filter(e => e.source === entry.target)
    laterals.forEach(lat => {
      const latTarget = nodeMap.get(lat.target)
      if (latTarget) {
        baseSteps.push({ tool: 'cred-reuse', title: latTarget.label, sev: 'Medium', description: 'Reuse captured credentials for lateral movement', command: 'impacket-psexec {domain}/{user}:{pass}@{target}' })
      }
    })

    chains.push({
      id: String(idx + 1).padStart(2, '0'),
      impact,
      cvss,
      steps: baseSteps,
      time: `${3 + baseSteps.length * 2}m`,
    })
  })

  return chains
}

function sortChains(chains: AttackChain[], sort: string): AttackChain[] {
  if (sort === 'by impact') {
    const rank: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0 }
    return [...chains].sort((a, b) => (rank[b.impact] ?? 0) - (rank[a.impact] ?? 0))
  }
  if (sort === 'by complexity') {
    return [...chains].sort((a, b) => b.steps.length - a.steps.length)
  }
  if (sort === 'shortest') {
    return [...chains].sort((a, b) => a.steps.length - b.steps.length)
  }
  return chains
}

// ── Main component ────────────────────────────────────────────────────────────

export default function AttackPaths() {
  const { selectedProject: sp } = useAppStore()
  const projectId = sp?.id ?? ''
  const [graph, setGraph] = useState<GraphData | null>(null)
  const [loading, setLoading] = useState(false)
  const [sort, setSort] = useState(SORT_OPTIONS[0])
  const [runningChain, setRunningChain] = useState<string | null>(null)
  const [runResults, setRunResults] = useState<Record<string, string>>({})

  useEffect(() => {
    if (projectId) loadGraph()
  }, [projectId])

  async function loadGraph() {
    setLoading(true)
    try {
      const res = await fetch(`${getApiBase()}/attack-paths/${projectId}`)
      if (res.ok) setGraph(await res.json())
    } finally {
      setLoading(false)
    }
  }

  async function handleRunChain(chain: AttackChain) {
    setRunningChain(chain.id)
    try {
      const res = await fetch(`${getApiBase()}/pentest/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          project_id: projectId,
          name: `Attack Chain ${chain.id}`,
          targets: chain.steps.filter(s => s.command).map(s => s.command),
          mode: 'chain',
        })
      })
      if (res.ok) {
        setRunResults(prev => ({ ...prev, [chain.id]: 'queued' }))
      }
    } finally {
      setRunningChain(null)
    }
  }

  function exportPaths() {
    if (!graph) return
    const chains = buildChains(graph)
    const blob = new Blob([JSON.stringify(chains, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'attack-paths.json'
    a.click()
  }

  const chains = graph ? sortChains(buildChains(graph), sort) : []

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

      <PageHeader
        title="Attack Paths"
        sub="Ranked sequences from initial-access foothold to high-value asset."
        right={
          <>
            <SegBtns options={SORT_OPTIONS} value={sort} onChange={setSort} />
            <button
              className="btn btn-sm"
              style={{ display: 'flex', alignItems: 'center', gap: 6 }}
              onClick={exportPaths}
            >
              <Icon name="download" size={11} /> Export
            </button>
          </>
        }
      />

      {/* ── Content ── */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 18 }}>

        {loading && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--fg-3)', fontSize: 12, padding: '32px 0' }}>
            <Icon name="refresh" size={14} color="var(--accent)" /> Loading attack paths…
          </div>
        )}

        {!loading && !projectId && (
          <div style={{ padding: '64px 0', textAlign: 'center', color: 'var(--fg-3)', fontSize: 13 }}>
            Select a project to view attack paths.
          </div>
        )}

        {!loading && projectId && chains.map((chain) => {
          const last = chain.steps.length - 1
          return (
            <div key={chain.id} className="rule">
              {/* sec-h */}
              <div className="sec-h">
                <span className="title">CHAIN {chain.id} · {chain.impact.toUpperCase()}</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginLeft: 'auto' }}>
                  <span className="badge badge-accent">CVSS {chain.cvss.toFixed(1)}</span>
                  <button
                    className="btn btn-sm"
                    style={{ display: 'flex', alignItems: 'center', gap: 5 }}
                    onClick={() => handleRunChain(chain)}
                    disabled={runningChain === chain.id}
                  >
                    <Icon name="play" size={10} />
                    {runningChain === chain.id ? 'Queuing…' : runResults[chain.id] === 'queued' ? 'Queued' : 'Run'}
                  </button>
                  <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>
                    {chain.steps.length} steps · {chain.time}
                  </span>
                </div>
              </div>

              {/* Chain body */}
              <div style={{
                padding: 'var(--pad)',
                display: 'grid',
                gridTemplateColumns: `repeat(${chain.steps.length}, 1fr)`,
                gap: 0,
              }}>
                {chain.steps.map((step, si) => (
                  <div
                    key={si}
                    style={{
                      padding: '0 14px',
                      borderRight: si < last ? '1px dashed var(--rule)' : 'none',
                      position: 'relative',
                    }}
                  >
                    <div className="mono" style={{ fontSize: 9, color: 'var(--fg-3)', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                      step {si + 1} · {step.tool}
                    </div>
                    <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--fg)', marginBottom: 6, lineHeight: 1.3 }}>
                      {step.title}
                    </div>
                    <SevBadge sev={step.sev} />
                    {step.description && (
                      <div style={{ fontSize: 10, color: 'var(--fg-3)', marginTop: 6, lineHeight: 1.4 }}>{step.description}</div>
                    )}
                    {step.command && (
                      <div className="mono" style={{ fontSize: 9, color: 'var(--accent)', marginTop: 4, wordBreak: 'break-all', opacity: 0.8 }}>{step.command}</div>
                    )}

                    {/* Arrow connector */}
                    {si < last && (
                      <span style={{
                        position: 'absolute', right: -7, top: 12,
                        color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: 14,
                        lineHeight: 1,
                      }}>›</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )
        })}

        {!loading && projectId && graph && chains.length === 0 && (
          <div style={{ padding: '64px 0', textAlign: 'center', color: 'var(--fg-3)', fontSize: 13 }}>
            {graph.nodes.length === 0
              ? 'No targets in this project yet. Add targets and run scans to generate attack paths.'
              : 'No attack paths derived yet. Paths are built from discovered hosts and their relationships — run scans to map services and lateral movement.'}
          </div>
        )}
      </div>
    </div>
  )
}
