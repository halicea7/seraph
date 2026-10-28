import { useState, useEffect, useRef } from 'react'
import { useAppStore } from '@/stores/appStore'
import { getApiBase, wsUrl } from '@/lib/config'
import Icon from '@/components/Icon'
import EmptyState from '@/components/EmptyState'
import { useToast } from '@/contexts/ToastContext'

// ── Types ─────────────────────────────────────────────────────────────────────

interface SavedRequest {
  id: string
  name: string
  method: string
  url: string
  headers: Record<string, string>
  body: string
}

interface SendResponse {
  status: number
  reason: string
  headers: Record<string, string>
  body: string
  size: number
  elapsed_ms: number
}

interface FuzzRow {
  index: number
  payload: string
  status: number
  size: number
  elapsed_ms: number
  error?: string
}

const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']
const MARKER = '§FUZZ§'

// ── Helpers ───────────────────────────────────────────────────────────────────

function parseHeaders(raw: string): Record<string, string> {
  const out: Record<string, string> = {}
  raw.split('\n').forEach(line => {
    const idx = line.indexOf(':')
    if (idx > 0) {
      const k = line.slice(0, idx).trim()
      const v = line.slice(idx + 1).trim()
      if (k) out[k] = v
    }
  })
  return out
}

function statusColor(status: number): string {
  if (status === 0) return 'var(--fg-4)'
  if (status < 300) return 'var(--low)'
  if (status < 400) return 'var(--accent)'
  if (status < 500) return 'var(--high)'
  return 'var(--crit)'
}

const inputStyle: React.CSSProperties = {
  background: 'var(--bg)', border: '1px solid var(--rule)', color: 'var(--fg)',
  fontFamily: 'var(--font-mono)', fontSize: 12, padding: '7px 10px', borderRadius: 3,
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function RequestWorkbench() {
  const { selectedProject } = useAppStore()
  const { show: showToast } = useToast()
  const api = getApiBase()

  const [tab, setTab] = useState<'repeater' | 'intruder'>('repeater')
  const [method, setMethod] = useState('GET')
  const [url, setUrl] = useState('')
  const [headersRaw, setHeadersRaw] = useState('')
  const [body, setBody] = useState('')

  const [resp, setResp] = useState<SendResponse | null>(null)
  const [sending, setSending] = useState(false)
  const [error, setError] = useState('')

  const [saved, setSaved] = useState<SavedRequest[]>([])

  // Fuzz state
  const [payloadsRaw, setPayloadsRaw] = useState('')
  const [fuzzRows, setFuzzRows] = useState<FuzzRow[]>([])
  const [fuzzing, setFuzzing] = useState(false)
  const [fuzzTotal, setFuzzTotal] = useState(0)
  const [sortKey, setSortKey] = useState<'index' | 'status' | 'size' | 'elapsed_ms'>('index')
  const wsRef = useRef<WebSocket | null>(null)

  function loadSaved() {
    if (!selectedProject) return
    fetch(`${api}/http/requests?project_id=${selectedProject.id}`)
      .then(r => r.json()).then(setSaved).catch(() => {})
  }

  useEffect(() => {
    setResp(null); setFuzzRows([]); loadSaved()
    return () => { wsRef.current?.close() }
  }, [selectedProject])

  async function send() {
    if (!selectedProject || !url.trim()) return
    setSending(true); setError(''); setResp(null)
    try {
      const r = await fetch(`${api}/http/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_id: selectedProject.id, method, url, headers: parseHeaders(headersRaw), body }),
      })
      const data = await r.json()
      if (!r.ok) throw new Error(data.detail || 'Request failed')
      setResp(data)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Request failed')
    } finally {
      setSending(false)
    }
  }

  async function saveCurrent() {
    if (!selectedProject || !url.trim()) return
    await fetch(`${api}/http/requests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project_id: selectedProject.id, name: url, method, url, headers: parseHeaders(headersRaw), body }),
    })
    showToast('Request saved', 'success')
    loadSaved()
  }

  function loadRequest(s: SavedRequest) {
    setMethod(s.method); setUrl(s.url); setBody(s.body)
    setHeadersRaw(Object.entries(s.headers).map(([k, v]) => `${k}: ${v}`).join('\n'))
    setResp(null)
  }

  async function deleteSaved(id: string) {
    await fetch(`${api}/http/requests/${id}`, { method: 'DELETE' })
    setSaved(prev => prev.filter(s => s.id !== id))
  }

  async function startFuzz() {
    if (!selectedProject) return
    const payloads = payloadsRaw.split('\n').map(p => p.trim()).filter(Boolean)
    if (payloads.length === 0) { showToast('Add payloads (one per line)', 'error'); return }
    const headers = parseHeaders(headersRaw)
    if (![url, body, ...Object.values(headers)].some(s => s.includes(MARKER))) {
      showToast(`Place the ${MARKER} marker in the URL, a header, or the body first`, 'error'); return
    }

    setFuzzing(true); setFuzzRows([]); setError('')
    try {
      const r = await fetch(`${api}/http/fuzz`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_id: selectedProject.id, method, url, headers, body, payloads }),
      })
      const data = await r.json()
      if (!r.ok) throw new Error(data.detail || 'Fuzz failed to start')

      const ws = new WebSocket(wsUrl(`/ws/httpfuzz/${data.run_id}`))
      wsRef.current = ws
      ws.onmessage = ev => {
        const msg = JSON.parse(ev.data)
        if (msg.type === 'start') setFuzzTotal(msg.total)
        else if (msg.type === 'result') setFuzzRows(prev => [...prev, msg as FuzzRow])
        else if (msg.type === 'exit') { setFuzzing(false); ws.close() }
        else if (msg.type === 'error') { showToast(msg.data, 'error'); setFuzzing(false); ws.close() }
      }
      ws.onerror = () => { setFuzzing(false); showToast('WebSocket error', 'error') }
      ws.onclose = () => setFuzzing(false)
    } catch (e) {
      setFuzzing(false)
      showToast(e instanceof Error ? e.message : 'Fuzz failed', 'error')
    }
  }

  function insertMarker() {
    setUrl(u => u + MARKER)
  }

  const sortedRows = [...fuzzRows].sort((a, b) => {
    if (sortKey === 'index') return a.index - b.index
    return (b[sortKey] as number) - (a[sortKey] as number)
  })

  if (!selectedProject) {
    return (
      <div style={{ padding: '24px 28px' }}>
        <h1 className="sec-h" style={{ margin: '0 0 16px' }}>Request Workbench</h1>
        <EmptyState icon="send" title="No project selected" hint="Pick an engagement to send and fuzz HTTP requests." />
      </div>
    )
  }

  return (
    <div style={{ padding: '20px 24px', display: 'flex', gap: 16, height: '100%', boxSizing: 'border-box' }}>

      {/* Saved requests rail */}
      <div style={{ width: 200, flexShrink: 0, borderRight: '1px solid var(--rule)', paddingRight: 14, overflowY: 'auto' }}>
        <div className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)', marginBottom: 8 }}>Saved ({saved.length})</div>
        {saved.length === 0 ? (
          <div style={{ fontSize: 11, color: 'var(--fg-4)' }}>No saved requests.</div>
        ) : saved.map(s => (
          <div key={s.id} style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 4 }}>
            <button onClick={() => loadRequest(s)} style={{ flex: 1, minWidth: 0, textAlign: 'left', background: 'transparent', border: '1px solid var(--rule)', borderRadius: 3, padding: '5px 7px', cursor: 'pointer' }}>
              <div className="mono" style={{ fontSize: 9, color: 'var(--accent)' }}>{s.method}</div>
              <div style={{ fontSize: 10.5, color: 'var(--fg-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.url}</div>
            </button>
            <button onClick={() => deleteSaved(s.id)} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', display: 'flex' }}>
              <Icon name="trash" size={11} />
            </button>
          </div>
        ))}
      </div>

      {/* Main column */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
        {/* Header + tabs */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
          <h1 className="sec-h" style={{ margin: 0 }}>Request Workbench</h1>
          <div style={{ display: 'flex', border: '1px solid var(--rule)', borderRadius: 3, overflow: 'hidden' }}>
            {(['repeater', 'intruder'] as const).map(t => (
              <button key={t} onClick={() => setTab(t)} style={{
                padding: '5px 14px', fontSize: 11, textTransform: 'capitalize', cursor: 'pointer',
                background: tab === t ? 'var(--accent-2)' : 'transparent',
                color: tab === t ? 'var(--accent)' : 'var(--fg-3)', border: 'none',
                fontFamily: 'var(--font-mono)',
              }}>{t}</button>
            ))}
          </div>
        </div>

        {/* Request line */}
        <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
          <select value={method} onChange={e => setMethod(e.target.value)} style={{ ...inputStyle, width: 100 }}>
            {METHODS.map(m => <option key={m} value={m}>{m}</option>)}
          </select>
          <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://app.corp.local/api/users" style={{ ...inputStyle, flex: 1 }} />
          {tab === 'repeater' ? (
            <>
              <button className="btn btn-primary" onClick={send} disabled={sending} style={{ height: 34, padding: '0 16px', fontSize: 12 }}>
                <Icon name={sending ? 'refresh' : 'send'} size={12} style={{ marginRight: 6 }} />{sending ? 'Sending…' : 'Send'}
              </button>
              <button className="btn" onClick={saveCurrent} title="Save request" style={{ height: 34, padding: '0 12px', fontSize: 12 }}>
                <Icon name="download" size={12} />
              </button>
            </>
          ) : (
            <button className="btn" onClick={insertMarker} title="Insert fuzz marker" style={{ height: 34, padding: '0 12px', fontSize: 11 }}>
              + {MARKER}
            </button>
          )}
        </div>

        {error && <div style={{ fontSize: 12, color: 'var(--crit)', marginBottom: 10 }}>{error}</div>}

        {/* Body split */}
        <div style={{ flex: 1, display: 'flex', gap: 14, minHeight: 0 }}>
          {/* Left: editor */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8, minWidth: 0 }}>
            <div className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)' }}>Headers (one per line)</div>
            <textarea value={headersRaw} onChange={e => setHeadersRaw(e.target.value)} placeholder="Authorization: Bearer …&#10;Content-Type: application/json"
              style={{ ...inputStyle, height: 90, resize: 'vertical' }} />
            <div className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)' }}>Body</div>
            <textarea value={body} onChange={e => setBody(e.target.value)} placeholder='{"key": "value"}'
              style={{ ...inputStyle, flex: 1, minHeight: 80, resize: 'vertical' }} />

            {tab === 'intruder' && (
              <>
                <div className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)' }}>Payloads (one per line)</div>
                <textarea value={payloadsRaw} onChange={e => setPayloadsRaw(e.target.value)} placeholder="admin&#10;root&#10;../../etc/passwd"
                  style={{ ...inputStyle, height: 90, resize: 'vertical' }} />
                <button className="btn btn-primary" onClick={startFuzz} disabled={fuzzing} style={{ height: 32, fontSize: 12 }}>
                  <Icon name={fuzzing ? 'refresh' : 'zap'} size={12} style={{ marginRight: 6 }} />
                  {fuzzing ? `Fuzzing ${fuzzRows.length}/${fuzzTotal}…` : 'Start fuzz'}
                </button>
              </>
            )}
          </div>

          {/* Right: response / results */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, border: '1px solid var(--rule)', borderRadius: 3 }}>
            {tab === 'repeater' ? (
              !resp ? (
                <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--fg-4)', fontSize: 12 }}>
                  Response appears here.
                </div>
              ) : (
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
                  <div style={{ padding: '8px 12px', borderBottom: '1px solid var(--rule)', display: 'flex', gap: 14, alignItems: 'center', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                    <span style={{ color: statusColor(resp.status), fontWeight: 700 }}>{resp.status} {resp.reason}</span>
                    <span style={{ color: 'var(--fg-3)' }}>{resp.size} B</span>
                    <span style={{ color: 'var(--fg-3)' }}>{resp.elapsed_ms} ms</span>
                  </div>
                  <pre style={{ margin: 0, padding: 12, overflow: 'auto', flex: 1, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg-2)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                    {Object.entries(resp.headers).map(([k, v]) => `${k}: ${v}`).join('\n')}
                    {'\n\n'}
                    {resp.body}
                  </pre>
                </div>
              )
            ) : (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 70px 70px 70px', padding: '7px 12px', borderBottom: '1px solid var(--rule)', background: 'var(--bg-2)' }}>
                  {([['payload', 'index'], ['status', 'status'], ['size', 'size'], ['time', 'elapsed_ms']] as const).map(([label, key]) => (
                    <button key={key} onClick={() => setSortKey(key)} style={{ background: 'transparent', border: 'none', textAlign: key === 'index' ? 'left' : 'right', cursor: 'pointer', fontFamily: 'var(--font-mono)', fontSize: 9.5, textTransform: 'uppercase', letterSpacing: '0.08em', color: sortKey === key ? 'var(--accent)' : 'var(--fg-3)' }}>
                      {label}
                    </button>
                  ))}
                </div>
                <div style={{ flex: 1, overflowY: 'auto' }}>
                  {sortedRows.length === 0 ? (
                    <div style={{ padding: 16, color: 'var(--fg-4)', fontSize: 12 }}>Fuzz results stream here.</div>
                  ) : sortedRows.map(row => (
                    <div key={row.index} style={{ display: 'grid', gridTemplateColumns: '1fr 70px 70px 70px', padding: '5px 12px', borderBottom: '1px solid var(--rule)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                      <span style={{ color: 'var(--fg-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={row.payload}>{row.payload}</span>
                      <span style={{ textAlign: 'right', color: statusColor(row.status), fontWeight: 700 }}>{row.error ? 'ERR' : row.status}</span>
                      <span style={{ textAlign: 'right', color: 'var(--fg-3)' }}>{row.size}</span>
                      <span style={{ textAlign: 'right', color: 'var(--fg-3)' }}>{row.elapsed_ms}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
