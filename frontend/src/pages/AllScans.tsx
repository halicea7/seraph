import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { getApiBase } from '@/lib/config'
import Icon from '@/components/Icon'
import EmptyState from '@/components/EmptyState'
import { SkeletonRows } from '@/components/Skeleton'
import NessusScanModal from '@/components/NessusScanModal'
import { useLiveEvents } from '@/contexts/LiveEventsContext'
import { useToast } from '@/contexts/ToastContext'
import { controlNessusScan, requestNessusExport, nessusExportDownloadUrl } from '@/api/client'

const rule = '1px solid var(--rule)'
const ruleStrong = '1px solid var(--rule-strong)'

// ── Types ──────────────────────────────────────────────────────────────────────

interface ScanRow {
  id: string
  scan_type: string
  status: string
  target: string
  target_id: string | null
  project: string
  project_id: string | null
  finding_count: number
  auto_probe: boolean
  nessus_scan_id: number | null
  nessus_status: string | null
  nessus_progress: number | null
  started_at: string | null
  completed_at: string | null
  created_at: string | null
}

interface ScanDetail extends ScanRow {
  raw_output: string | null
  config_json: string | null
}

interface DiffFinding {
  id: string
  severity: string
  title: string
  description: string
  cve_id: string | null
  cvss_score: string | null
}

interface DiffResult {
  scan_a: string
  scan_b: string
  new: DiffFinding[]
  resolved: DiffFinding[]
  unchanged: DiffFinding[]
}

// ── Style maps ─────────────────────────────────────────────────────────────────

const STATUS_COLORS: Record<string, string> = {
  completed:  '#22c55e',
  running:    'var(--accent)',
  pending:    '#64748b',
  failed:     '#ef4444',
  cancelled:  '#f59e0b',
}

const STATUS_STYLES: Record<string, { color: string; background: string; border: string }> = {
  completed: { color: 'var(--ok)',     background: 'rgba(84,175,97,0.08)',   border: '1px solid rgba(84,175,97,0.3)' },
  running:   { color: 'var(--accent)', background: 'rgba(240,168,58,0.08)', border: '1px solid rgba(240,168,58,0.3)' },
  pending:   { color: 'var(--fg-3)',   background: 'rgba(100,116,139,0.08)', border: '1px solid rgba(100,116,139,0.2)' },
  failed:    { color: 'var(--crit)',   background: 'rgba(232,64,64,0.08)',   border: '1px solid rgba(232,64,64,0.3)' },
  cancelled: { color: 'var(--accent)', background: 'rgba(240,168,58,0.08)', border: '1px solid rgba(240,168,58,0.3)' },
}

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--crit)', high: '#f97316', medium: 'var(--accent)', low: 'var(--ok)', info: 'var(--med)',
}
const SEV_BG: Record<string, string> = {
  critical: 'rgba(232,64,64,0.1)', high: 'rgba(249,115,22,0.1)', medium: 'rgba(240,168,58,0.1)',
  low: 'rgba(84,175,97,0.1)', info: 'rgba(180,140,60,0.1)',
}

const STATUSES = ['all', 'completed', 'running', 'pending', 'failed']

// ── Pill helper ────────────────────────────────────────────────────────────────

function Pill({ tone, children }: { tone: string; children: React.ReactNode }) {
  const c = tone === 'fail' ? 'var(--crit)'
          : tone === 'warn' ? 'var(--high)'
          : tone === 'pass' ? 'var(--ok)'
          : tone === 'info' ? 'var(--accent)'
          : 'var(--fg-3)'
  return (
    <span
      className="mono"
      style={{ fontSize: 10, color: c, padding: '2px 6px', border: `1px solid ${c}`, background: `${c}18` }}
    >
      {children}
    </span>
  )
}

// ── DiffBucket ─────────────────────────────────────────────────────────────────

function DiffBucket({ label, iconName, color, findings }: {
  label: string
  iconName: string
  color: string
  findings: DiffFinding[]
}) {
  return (
    <div style={{ padding: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 12, color }}>
        <Icon name={iconName} size={12} />
        <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</span>
        <span style={{ marginLeft: 'auto', fontSize: 11, fontFamily: 'var(--font-mono)' }}>{findings.length}</span>
      </div>
      {findings.length === 0 ? (
        <p style={{ fontSize: 11, color: 'var(--fg-4)', textAlign: 'center', padding: '16px 0' }}>None</p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, overflowY: 'auto', maxHeight: 240 }}>
          {findings.map(f => (
            <div key={f.id} style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
              <span
                style={{
                  fontSize: 9, fontWeight: 700, padding: '1px 5px', borderRadius: 3,
                  textTransform: 'uppercase', flexShrink: 0, marginTop: 2,
                  background: SEV_BG[f.severity] ?? 'rgba(100,116,139,0.15)',
                  color: SEV_COLOR[f.severity] ?? 'var(--fg-3)',
                }}
              >
                {f.severity}
              </span>
              <p style={{ fontSize: 11, color: 'var(--fg-2)', lineHeight: 1.4 }}>{f.title}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────────

export default function AllScans() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()

  const [scans, setScans]           = useState<ScanRow[]>([])
  const [loading, setLoading]       = useState(true)
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') ?? 'all')
  const [search, setSearch]         = useState(searchParams.get('q') ?? '')
  const [selected, setSelected]     = useState<string[]>([])
  const [diff, setDiff]             = useState<DiffResult | null>(null)
  const [diffLoading, setDiffLoading] = useState(false)
  const [diffError, setDiffError]   = useState('')

  // Detail panel
  const [drawerScan, setDrawerScan]       = useState<ScanDetail | null>(null)
  const [drawerLoading, setDrawerLoading] = useState(false)
  const [parseLoading, setParseLoading]   = useState(false)
  const [parseMsg, setParseMsg]           = useState('')
  const [cancelLoading, setCancelLoading] = useState(false)
  const [deleteLoading, setDeleteLoading] = useState(false)
  const [showLaunch, setShowLaunch]       = useState(false)
  const [ctrlLoading, setCtrlLoading]     = useState(false)

  const toast = useToast()
  const { subscribe } = useLiveEvents()

  function updateFilter(status: string, q: string) {
    const params: Record<string, string> = {}
    if (status !== 'all') params.status = status
    if (q) params.q = q
    setSearchParams(params, { replace: true })
  }

  const openParam = searchParams.get('open')

  function loadScans(): Promise<ScanRow[]> {
    return fetch(`${getApiBase()}/scans`)
      .then(r => r.json())
      .then((data: ScanRow[]) => { setScans(data); return data })
  }

  useEffect(() => {
    loadScans()
      .then(data => {
        if (openParam) {
          const target = data.find(s => s.id === openParam)
          if (target) openDrawer(target)
          setSearchParams(prev => { prev.delete('open'); return prev }, { replace: true })
        }
      })
      .finally(() => setLoading(false))
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Live updates: Nessus poller pushes scan_update (status/progress) and
  // finding_created (fan-out complete) over /ws/events.
  useEffect(() => {
    const unsub = subscribe((msg: any) => {
      if (msg?.type === 'scan_update' && msg.scan_id) {
        setScans(prev => prev.map(s => s.id === msg.scan_id
          ? { ...s, nessus_status: msg.status ?? s.nessus_status,
              nessus_progress: typeof msg.progress === 'number' ? msg.progress : s.nessus_progress,
              status: msg.status === 'completed' ? 'completed' : s.status }
          : s))
      } else if (msg?.type === 'finding_created') {
        loadScans()
      } else if (msg?.type === 'nessus_export_ready' && msg.nessus_scan_id && msg.file_id) {
        const url = nessusExportDownloadUrl(msg.nessus_scan_id, msg.file_id)
        toast.success(`${String(msg.format ?? 'report').toUpperCase()} export ready`)
        window.open(url, '_blank')
      }
    })
    return unsub
  }, [subscribe])

  const filtered = scans.filter(s => {
    if (statusFilter !== 'all' && s.status !== statusFilter) return false
    if (search) {
      const q = search.toLowerCase()
      return s.target.toLowerCase().includes(q) || s.project.toLowerCase().includes(q) || s.scan_type.toLowerCase().includes(q)
    }
    return true
  })

  function toggleSelect(e: React.MouseEvent, id: string) {
    e.stopPropagation()
    setSelected(prev => {
      if (prev.includes(id)) return prev.filter(x => x !== id)
      if (prev.length >= 2) return [prev[1], id]
      return [...prev, id]
    })
    setDiff(null)
    setDiffError('')
  }

  function parseFindings(scanId: string) {
    setParseLoading(true)
    setParseMsg('')
    fetch(`${getApiBase()}/audit/scans/${scanId}/parse`, { method: 'POST' })
      .then(r => r.json())
      .then(d => setParseMsg(`${d.parsed ?? 0} findings parsed`))
      .catch(() => setParseMsg('Parse failed'))
      .finally(() => setParseLoading(false))
  }

  async function cancelScan(scanId: string) {
    setCancelLoading(true)
    try {
      const res = await fetch(`${getApiBase()}/scans/${scanId}/cancel`, { method: 'POST' })
      if (res.ok) {
        setScans(prev => prev.map(s => s.id === scanId ? { ...s, status: 'cancelled' } : s))
        setDrawerScan(prev => prev?.id === scanId ? { ...prev, status: 'cancelled' } : prev)
      }
    } finally {
      setCancelLoading(false)
    }
  }

  async function nessusControl(scan: ScanRow, action: 'pause' | 'resume' | 'stop') {
    if (!scan.nessus_scan_id) return
    setCtrlLoading(true)
    try {
      await controlNessusScan(scan.nessus_scan_id, action)
      const optimistic = action === 'pause' ? 'paused' : action === 'resume' ? 'running' : 'stopping'
      setScans(prev => prev.map(s => s.id === scan.id ? { ...s, nessus_status: optimistic } : s))
      setDrawerScan(prev => prev?.id === scan.id ? { ...prev, nessus_status: optimistic } : prev)
      toast.success(`Scan ${action}d`)
    } catch (e: any) {
      toast.error(e?.message ?? `Failed to ${action} scan`)
    } finally {
      setCtrlLoading(false)
    }
  }

  async function nessusExport(scan: ScanRow, format: 'nessus' | 'pdf' | 'csv') {
    if (!scan.nessus_scan_id) return
    try {
      await requestNessusExport(scan.nessus_scan_id, format)
      toast.info(`Preparing ${format.toUpperCase()} export — you'll be notified when it's ready`)
    } catch (e: any) {
      toast.error(e?.message ?? 'Export failed')
    }
  }

  async function deleteScan(scanId: string) {
    setDeleteLoading(true)
    try {
      const res = await fetch(`${getApiBase()}/scans/${scanId}`, { method: 'DELETE' })
      if (res.ok) {
        setScans(prev => prev.filter(s => s.id !== scanId))
        setDrawerScan(null)
      }
    } finally {
      setDeleteLoading(false)
    }
  }

  function openDrawer(scan: ScanRow) {
    setParseMsg('')
    setDrawerLoading(true)
    setDrawerScan({ ...scan, raw_output: null, config_json: null })
    fetch(`${getApiBase()}/audit/scans/${scan.id}`)
      .then(r => r.json())
      .then(data => setDrawerScan({ ...scan, raw_output: data.raw_output ?? null, config_json: data.config_json ?? null }))
      .catch(() => setDrawerScan(prev => prev ? { ...prev, raw_output: 'Failed to load output.' } : null))
      .finally(() => setDrawerLoading(false))
  }

  function runDiff() {
    if (selected.length !== 2) return
    setDiffLoading(true)
    setDiffError('')
    fetch(`${getApiBase()}/scans/diff?a=${selected[0]}&b=${selected[1]}`)
      .then(r => r.ok ? r.json() : r.json().then((e: { detail: string }) => Promise.reject(e.detail)))
      .then(setDiff)
      .catch(e => setDiffError(String(e)))
      .finally(() => setDiffLoading(false))
  }

  const scanName = (id: string) => {
    const s = scans.find(x => x.id === id)
    return s ? `${s.scan_type} @ ${s.target}` : id.slice(0, 8)
  }

  const badgeStyle = (status: string): React.CSSProperties => {
    const ss = STATUS_STYLES[status] ?? STATUS_STYLES.pending
    return {
      fontSize: 10, padding: '1px 7px', borderRadius: 10,
      fontFamily: 'var(--font-mono)', color: ss.color, background: ss.background, border: ss.border,
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────────

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>

      {/* ── Page header ── */}
      <div style={{ padding: '16px var(--pad)', borderBottom: rule, background: 'var(--bg)', flexShrink: 0, display: 'flex', alignItems: 'center', gap: 12 }}>
        <button
          onClick={() => navigate('/')}
          className="btn btn-ghost btn-sm"
          style={{ padding: '4px 6px', display: 'flex', alignItems: 'center' }}
        >
          <Icon name="arrow_l" size={15} />
        </button>
        <div style={{ flex: 1 }}>
          <div className="smcap" style={{ marginBottom: 2 }}>All Scans</div>
          <h1 className="mono" style={{ fontSize: 20, fontWeight: 500, color: 'var(--fg)', margin: 0 }}>Scans</h1>
        </div>

        <button
          onClick={() => setShowLaunch(true)}
          className="btn btn-primary btn-sm"
          style={{ display: 'flex', alignItems: 'center', gap: 6 }}
        >
          <Icon name="target" size={13} />
          Launch Nessus scan
        </button>

        {/* Right slot: diff controls */}
        {selected.length > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 11, color: 'var(--fg-3)' }}>{selected.length}/2 selected</span>
            {selected.length === 2 && (
              <button
                onClick={runDiff}
                disabled={diffLoading}
                className="btn btn-sm"
                style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(240,168,58,0.1)', color: 'var(--accent)', border: '1px solid rgba(240,168,58,0.3)', opacity: diffLoading ? 0.5 : 1 }}
              >
                <Icon name="activity" size={13} />
                {diffLoading ? 'Comparing…' : 'Diff Scans'}
              </button>
            )}
            <button
              onClick={() => { setSelected([]); setDiff(null) }}
              className="btn btn-ghost btn-sm"
              style={{ padding: '4px 6px', display: 'flex', alignItems: 'center' }}
            >
              <Icon name="x" size={14} />
            </button>
          </div>
        )}
      </div>

      {/* ── Filter/toolbar strip ── */}
      <div style={{ padding: '12px var(--pad)', borderBottom: rule, background: 'var(--bg-2)', display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0, flexWrap: 'wrap' }}>
        {/* Search */}
        <div style={{ position: 'relative', flex: 1, minWidth: 200 }}>
          <Icon name="search" size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--fg-3)' }} />
          <input
            type="text"
            placeholder="Search target, project, type…"
            value={search}
            onChange={e => { setSearch(e.target.value); updateFilter(statusFilter, e.target.value) }}
            style={{
              width: '100%', boxSizing: 'border-box',
              background: 'var(--bg)', border: ruleStrong, borderRadius: 4,
              color: 'var(--fg)', fontFamily: 'var(--font-sans)', fontSize: 13,
              padding: '6px 12px 6px 30px', outline: 'none',
            }}
          />
        </div>

        {/* Status filter pills */}
        <div style={{ display: 'flex', gap: 4, background: 'var(--bg)', border: ruleStrong, borderRadius: 4, padding: 4 }}>
          {STATUSES.map(s => (
            <button
              key={s}
              onClick={() => { setStatusFilter(s); updateFilter(s, search) }}
              style={{
                padding: '4px 12px', borderRadius: 4, fontSize: 11, fontWeight: 500,
                textTransform: 'capitalize', border: 'none', cursor: 'pointer',
                background: statusFilter === s ? 'rgba(240,168,58,0.12)' : 'none',
                color: statusFilter === s ? 'var(--accent)' : 'var(--fg-3)',
              }}
            >
              {s}
            </button>
          ))}
        </div>

        <span style={{ fontSize: 11, color: 'var(--fg-4)' }} className="tnum">{filtered.length} shown</span>
      </div>

      {/* ── Main body: list + detail panel ── */}
      <div style={{ display: 'grid', gridTemplateColumns: drawerScan ? '1fr 460px' : '1fr', flex: 1, minHeight: 0 }}>

        {/* ── Left: scans list ── */}
        <div style={{ overflowY: 'auto', borderRight: drawerScan ? rule : 'none' }}>

          {/* Diff result panel */}
          {diff && (
            <div style={{ margin: 16, background: 'var(--bg-2)', border: ruleStrong, borderRadius: 4, overflow: 'hidden' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 16px', borderBottom: rule }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Icon name="activity" size={14} color="var(--accent)" />
                  <span className="smcap">Scan Diff</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 11 }}>
                  <span style={{ color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>{scanName(diff.scan_a)}</span>
                  <span style={{ color: 'var(--fg-4)' }}>→</span>
                  <span style={{ color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>{scanName(diff.scan_b)}</span>
                </div>
                <button onClick={() => setDiff(null)} className="btn btn-ghost btn-sm" style={{ padding: '4px 6px', display: 'flex', alignItems: 'center' }}>
                  <Icon name="x" size={13} />
                </button>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', borderTop: rule }}>
                <DiffBucket label="New"       iconName="plus"  color="var(--crit)" findings={diff.new} />
                <div style={{ borderLeft: rule, borderRight: rule }}>
                  <DiffBucket label="Resolved"  iconName="minus" color="var(--ok)"   findings={diff.resolved} />
                </div>
                <DiffBucket label="Unchanged" iconName="minus" color="var(--fg-3)"  findings={diff.unchanged} />
              </div>
            </div>
          )}

          {diffError && (
            <div style={{ margin: '0 16px 0', padding: '8px 16px', borderRadius: 4, background: 'rgba(232,64,64,0.08)', border: '1px solid rgba(232,64,64,0.3)', fontSize: 11, color: 'var(--crit)' }}>
              {diffError}
            </div>
          )}

          {/* Selection hint */}
          {selected.length === 0 && !diff && (
            <div style={{ padding: '10px 20px' }}>
              <p style={{ fontSize: 11, color: 'var(--fg-4)', margin: 0 }}>
                Click a row to view output · check the box on two rows to <strong style={{ color: 'var(--fg-3)' }}>Diff Scans</strong>
              </p>
            </div>
          )}

          {/* Scans table */}
          {loading ? (
            <div style={{ paddingTop: 4 }}>
              <SkeletonRows rows={7} cols={5} />
            </div>
          ) : filtered.length === 0 ? (
            <EmptyState
              icon="target"
              title="No scans match the current filter"
              hint="Adjust the filters above, or run a scan from a module to populate this list."
              pad={56}
            />
          ) : (
            <table className="data" style={{ width: '100%', fontSize: 13, borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: rule, textAlign: 'left' }}>
                  <th style={{ padding: '10px 12px', width: 32 }} />
                  <th className="smcap" style={{ padding: '10px 16px' }}>Type</th>
                  <th className="smcap" style={{ padding: '10px 16px' }}>Target</th>
                  <th className="smcap" style={{ padding: '10px 16px' }}>Project</th>
                  <th className="smcap" style={{ padding: '10px 16px' }}>Status</th>
                  <th className="smcap" style={{ padding: '10px 16px', textAlign: 'right' }}>Findings</th>
                  <th className="smcap" style={{ padding: '10px 16px' }}>Started</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((s, idx) => {
                  const isSelected = selected.includes(s.id)
                  const selIdx = selected.indexOf(s.id)
                  const isOpen = drawerScan?.id === s.id
                  return (
                    <tr
                      key={s.id}
                      onClick={() => openDrawer(s)}
                      className={isOpen ? 'selected' : ''}
                      style={{
                        cursor: 'pointer',
                        borderBottom: idx < filtered.length - 1 ? rule : 'none',
                        background: isOpen
                          ? 'rgba(240,168,58,0.06)'
                          : isSelected
                            ? 'rgba(240,168,58,0.03)'
                            : 'none',
                      }}
                    >
                      {/* Checkbox column */}
                      <td style={{ padding: '10px 12px' }} onClick={e => toggleSelect(e, s.id)}>
                        <div style={{
                          width: 20, height: 20, borderRadius: 4,
                          border: isSelected ? '1px solid var(--accent)' : ruleStrong,
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontSize: 10, fontWeight: 700, cursor: 'pointer',
                          background: isSelected ? 'rgba(240,168,58,0.2)' : 'none',
                          color: isSelected ? 'var(--accent)' : 'transparent',
                          flexShrink: 0,
                        }}>
                          {isSelected ? selIdx + 1 : ''}
                        </div>
                      </td>

                      {/* Scan type */}
                      <td style={{ padding: '10px 16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div style={{ width: 3, height: 18, borderRadius: 2, flexShrink: 0, backgroundColor: STATUS_COLORS[s.status] || STATUS_COLORS.pending }} />
                          <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>{s.scan_type}</span>
                          {s.auto_probe && (
                            <Icon name="bolt" size={11} color="var(--ok)" />
                          )}
                        </div>
                      </td>

                      {/* Target */}
                      <td style={{ padding: '10px 16px' }}>
                        <span className="mono" style={{ fontSize: 11, color: 'var(--fg-2)' }}>{s.target}</span>
                      </td>

                      {/* Project */}
                      <td style={{ padding: '10px 16px', fontSize: 11, color: 'var(--fg-3)' }}>{s.project}</td>

                      {/* Status */}
                      <td style={{ padding: '10px 16px' }}>
                        {s.scan_type === 'nessus_job' && s.nessus_status && s.nessus_status !== 'completed' ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 110 }}>
                            <span className="mono" style={{ fontSize: 10, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                              {s.nessus_status} · {s.nessus_progress ?? 0}%
                            </span>
                            <div style={{ height: 3, background: 'var(--rule)', borderRadius: 2, overflow: 'hidden' }}>
                              <div style={{ height: '100%', width: `${s.nessus_progress ?? 0}%`, background: 'var(--accent)', transition: 'width .4s ease' }} />
                            </div>
                          </div>
                        ) : (
                          <span style={badgeStyle(s.status)}>{s.status}</span>
                        )}
                      </td>

                      {/* Findings count */}
                      <td style={{ padding: '10px 16px', textAlign: 'right' }}>
                        {s.finding_count > 0 ? (
                          <span className="mono tnum" style={{ fontSize: 11, color: 'var(--accent)' }}>{s.finding_count}</span>
                        ) : (
                          <span style={{ fontSize: 11, color: 'var(--fg-4)' }}>—</span>
                        )}
                      </td>

                      {/* Started */}
                      <td style={{ padding: '10px 16px' }}>
                        <span className="mono tnum" style={{ fontSize: 11, color: 'var(--fg-3)' }}>
                          {s.started_at ? new Date(s.started_at).toLocaleDateString() : '—'}
                        </span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* ── Right: scan detail / diff ── */}
        {drawerScan && (
          <div style={{ overflowY: 'auto', background: 'var(--bg-2)', borderLeft: rule, display: 'flex', flexDirection: 'column' }}>

            {/* Detail header */}
            <div style={{ padding: '14px 18px', borderBottom: rule, flexShrink: 0, background: 'var(--bg)' }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                <Icon name="terminal" size={15} color="var(--accent)" style={{ marginTop: 2, flexShrink: 0 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="smcap" style={{ marginBottom: 4 }}>scan · {drawerScan.id.slice(0, 8)}</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
                    <span className="mono" style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent)' }}>{drawerScan.scan_type}</span>
                    <span style={badgeStyle(drawerScan.status)}>{drawerScan.status}</span>
                    {drawerScan.auto_probe && (
                      <Pill tone="pass">auto-probe</Pill>
                    )}
                  </div>
                  {drawerScan.started_at && (
                    <div className="mono" style={{ fontSize: 10, color: 'var(--fg-4)' }}>
                      {new Date(drawerScan.started_at).toLocaleString()}
                      {drawerScan.completed_at && ` → ${new Date(drawerScan.completed_at).toLocaleString()}`}
                    </div>
                  )}
                </div>
                <button
                  onClick={() => setDrawerScan(null)}
                  className="btn btn-ghost btn-sm"
                  style={{ padding: '4px 6px', display: 'flex', alignItems: 'center', flexShrink: 0 }}
                >
                  <Icon name="x" size={14} />
                </button>
              </div>
            </div>

            {/* KV strip */}
            <div style={{ padding: '10px 18px', borderBottom: rule, background: 'var(--bg)', flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
              <div style={{ display: 'flex', gap: 8, fontSize: 11 }}>
                <span className="smcap" style={{ width: 72, flexShrink: 0 }}>Target</span>
                <span className="mono" style={{ color: 'var(--fg-2)' }}>{drawerScan.target}</span>
              </div>
              <div style={{ display: 'flex', gap: 8, fontSize: 11 }}>
                <span className="smcap" style={{ width: 72, flexShrink: 0 }}>Project</span>
                <span style={{ color: 'var(--fg-2)' }}>{drawerScan.project}</span>
              </div>
              <div style={{ display: 'flex', gap: 8, fontSize: 11, alignItems: 'center' }}>
                <span className="smcap" style={{ width: 72, flexShrink: 0 }}>Findings</span>
                <span className="mono tnum" style={{ color: drawerScan.finding_count > 0 ? 'var(--accent)' : 'var(--fg-4)' }}>
                  {drawerScan.finding_count > 0 ? drawerScan.finding_count : '—'}
                </span>
              </div>
            </div>

            {/* Action buttons */}
            <div style={{ padding: '10px 18px', borderBottom: rule, background: 'var(--bg)', flexShrink: 0, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              {drawerScan.raw_output !== null && (
                <button
                  onClick={() => parseFindings(drawerScan.id)}
                  disabled={parseLoading}
                  className="btn btn-sm"
                  style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(240,168,58,0.08)', color: 'var(--accent)', border: '1px solid rgba(240,168,58,0.25)', opacity: parseLoading ? 0.5 : 1 }}
                >
                  <Icon name={parseLoading ? 'refresh' : 'cpu'} size={11} className={parseLoading ? 'animate-spin' : undefined} />
                  {parseLoading ? 'Parsing…' : 'Parse Findings'}
                </button>
              )}
              {parseMsg && <span style={{ fontSize: 11, color: 'var(--ok)' }}>{parseMsg}</span>}

              {/* Nessus job lifecycle controls + export */}
              {drawerScan.scan_type === 'nessus_job' && drawerScan.nessus_scan_id && (
                <>
                  {drawerScan.nessus_status && !['completed', 'stopping', 'canceled', 'cancelled'].includes(drawerScan.nessus_status) && (
                    <>
                      <button
                        onClick={() => nessusControl(drawerScan, drawerScan.nessus_status === 'paused' ? 'resume' : 'pause')}
                        disabled={ctrlLoading}
                        className="btn btn-sm"
                        style={{ display: 'flex', alignItems: 'center', gap: 6, opacity: ctrlLoading ? 0.5 : 1 }}
                      >
                        <Icon name={drawerScan.nessus_status === 'paused' ? 'play' : 'pause'} size={11} />
                        {drawerScan.nessus_status === 'paused' ? 'Resume' : 'Pause'}
                      </button>
                      <button
                        onClick={() => nessusControl(drawerScan, 'stop')}
                        disabled={ctrlLoading}
                        className="btn btn-sm"
                        style={{ display: 'flex', alignItems: 'center', gap: 6, opacity: ctrlLoading ? 0.5 : 1 }}
                      >
                        <Icon name="stop" size={11} />
                        Stop
                      </button>
                    </>
                  )}
                  {(['nessus', 'pdf', 'csv'] as const).map(fmt => (
                    <button
                      key={fmt}
                      onClick={() => nessusExport(drawerScan, fmt)}
                      className="btn btn-sm"
                      style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                    >
                      <Icon name="download" size={11} />
                      {fmt.toUpperCase()}
                    </button>
                  ))}
                </>
              )}

              {(drawerScan.status === 'running' || drawerScan.status === 'pending') && drawerScan.scan_type !== 'nessus_job' && (
                <button
                  onClick={() => cancelScan(drawerScan.id)}
                  disabled={cancelLoading}
                  className="btn btn-sm"
                  style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'rgba(240,168,58,0.08)', color: 'var(--accent)', border: '1px solid rgba(240,168,58,0.25)', opacity: cancelLoading ? 0.5 : 1 }}
                >
                  <Icon name={cancelLoading ? 'refresh' : 'stop'} size={11} className={cancelLoading ? 'animate-spin' : undefined} />
                  {cancelLoading ? 'Cancelling…' : 'Cancel'}
                </button>
              )}
              <button
                onClick={() => deleteScan(drawerScan.id)}
                disabled={deleteLoading}
                className="btn btn-danger btn-sm"
                style={{ display: 'flex', alignItems: 'center', gap: 6, marginLeft: 'auto', opacity: deleteLoading ? 0.5 : 1 }}
              >
                <Icon name={deleteLoading ? 'refresh' : 'trash'} size={11} className={deleteLoading ? 'animate-spin' : undefined} />
                {deleteLoading ? 'Deleting…' : 'Delete'}
              </button>
            </div>

            {/* Raw output */}
            <div style={{ flex: 1, overflowY: 'auto', padding: 18 }}>
              {drawerLoading ? (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--fg-3)', fontSize: 13 }}>
                  <Icon name="refresh" size={14} className="animate-spin" />
                  Loading output…
                </div>
              ) : drawerScan.raw_output ? (
                <div className="term" style={{ maxHeight: 400, overflowY: 'auto' }}>
                  <pre className="mono" style={{ fontSize: 11, color: 'var(--fg-2)', whiteSpace: 'pre-wrap', lineHeight: 1.6, margin: 0 }}>{drawerScan.raw_output}</pre>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '48px 0', gap: 12, color: 'var(--fg-4)' }}>
                  <Icon name="terminal" size={32} />
                  <p className="smcap">select a scan</p>
                  <p style={{ fontSize: 12, color: 'var(--fg-4)', margin: 0 }}>No output recorded for this scan.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Empty detail state when no scan selected and detail col visible */}
        {!drawerScan && false && (
          <div style={{ overflowY: 'auto', background: 'var(--bg-2)', borderLeft: rule, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <p className="smcap">select a scan</p>
          </div>
        )}
      </div>

      {showLaunch && (
        <NessusScanModal
          onClose={() => setShowLaunch(false)}
          onLaunched={() => loadScans()}
        />
      )}
    </div>
  )
}
