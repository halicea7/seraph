import { useState, useEffect, useRef } from 'react'
import { useAppStore } from '@/stores/appStore'
import { getApiBase, wsUrl, authedUrl } from '@/lib/config'
import Icon from '@/components/Icon'
import EmptyState from '@/components/EmptyState'
import { useToast } from '@/contexts/ToastContext'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Shot {
  id: string
  url: string
  title: string
  status_code: string | null
  captured_at: string | null
  finding_id?: string | null
}

interface FindingOpt { id: string; title: string; severity: string }

interface Target {
  id: string
  hostname_or_ip: string
  target_type: string
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ScreenshotGallery() {
  const { selectedProject } = useAppStore()
  const { show: showToast } = useToast()
  const api = getApiBase()

  const [shots, setShots] = useState<Shot[]>([])
  const [targets, setTargets] = useState<Target[]>([])
  const [findings, setFindings] = useState<FindingOpt[]>([])
  const [urlText, setUrlText] = useState('')
  const [running, setRunning] = useState(false)
  const [log, setLog] = useState<string[]>([])
  const [lightbox, setLightbox] = useState<Shot | null>(null)
  const wsRef = useRef<WebSocket | null>(null)

  function loadShots() {
    if (!selectedProject) return
    fetch(`${api}/screenshots?project_id=${selectedProject.id}`)
      .then(r => r.json())
      .then(setShots)
      .catch(() => {})
  }

  useEffect(() => {
    setShots([]); setUrlText(''); setLog([])
    loadShots()
    if (selectedProject) {
      fetch(`${api}/projects/${selectedProject.id}/targets`)
        .then(r => r.json()).then(setTargets).catch(() => {})
      fetch(`${api}/findings?project_id=${selectedProject.id}`)
        .then(r => r.ok ? r.json() : []).then(setFindings).catch(() => {})
    }
    return () => { wsRef.current?.close() }
  }, [selectedProject])

  async function linkShot(shotId: string, findingId: string | null) {
    const r = await fetch(`${api}/screenshots/${shotId}/link`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding_id: findingId }),
    })
    if (r.ok) {
      setShots(prev => prev.map(s => s.id === shotId ? { ...s, finding_id: findingId } : s))
      showToast(findingId ? 'Attached as evidence' : 'Detached', 'success')
    } else showToast('Link failed', 'error')
  }

  function loadWebTargets() {
    const urls = targets
      .map(t => t.hostname_or_ip)
      .filter(Boolean)
      .map(h => (h.startsWith('http') ? h : `http://${h}`))
    setUrlText(urls.join('\n'))
  }

  async function startCapture() {
    if (!selectedProject) return
    const urls = urlText.split('\n').map(u => u.trim()).filter(Boolean)
    if (urls.length === 0) { showToast('Add at least one URL', 'error'); return }

    setRunning(true)
    setLog([])
    try {
      const r = await fetch(`${api}/screenshots/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_id: selectedProject.id, urls }),
      })
      if (!r.ok) {
        const d = await r.json().catch(() => ({}))
        throw new Error(d.detail || 'Capture failed to start')
      }
      const { job_id, skipped } = await r.json()
      if (skipped?.length) showToast(`${skipped.length} URL(s) skipped (out of scope)`, 'info')

      const ws = new WebSocket(wsUrl(`/ws/screenshots/${job_id}`))
      wsRef.current = ws
      ws.onmessage = ev => {
        const msg = JSON.parse(ev.data)
        if (msg.type === 'stdout' || msg.type === 'stderr') {
          setLog(prev => [...prev.slice(-200), msg.data])
        } else if (msg.type === 'results') {
          showToast(`Captured ${msg.captured} screenshot(s)`, 'success')
          loadShots()
        } else if (msg.type === 'exit') {
          setRunning(false)
          ws.close()
        } else if (msg.type === 'error') {
          showToast(msg.data, 'error')
          setRunning(false)
          ws.close()
        }
      }
      ws.onerror = () => { setRunning(false); showToast('WebSocket error', 'error') }
      ws.onclose = () => setRunning(false)
    } catch (e) {
      setRunning(false)
      showToast(e instanceof Error ? e.message : 'Capture failed', 'error')
    }
  }

  async function remove(id: string) {
    await fetch(`${api}/screenshots/${id}`, { method: 'DELETE' })
    setShots(prev => prev.filter(s => s.id !== id))
    if (lightbox?.id === id) setLightbox(null)
  }

  return (
    <div style={{ padding: '24px 28px', maxWidth: 1100, margin: '0 auto', width: '100%' }}>

      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <div className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)', marginBottom: 4 }}>Recon</div>
        <h1 className="sec-h" style={{ margin: 0 }}>Screenshot Gallery</h1>
        <p style={{ fontSize: 12, color: 'var(--fg-3)', marginTop: 4 }}>
          Capture web hosts with gowitness and triage them visually. Out-of-scope URLs are dropped automatically.
        </p>
      </div>

      <div style={{ height: 1, background: 'var(--rule)', marginBottom: 20 }} />

      {!selectedProject ? (
        <EmptyState icon="eye" title="No project selected" hint="Pick an engagement to capture and review screenshots." />
      ) : (
        <>
          {/* Capture panel */}
          <div style={{ border: '1px solid var(--rule)', borderRadius: 3, padding: 14, marginBottom: 24 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)' }}>URLs (one per line)</span>
              <button className="btn btn-sm" onClick={loadWebTargets} disabled={targets.length === 0}>
                <Icon name="target" size={11} style={{ marginRight: 5 }} />Load project targets
              </button>
            </div>
            <textarea
              value={urlText}
              onChange={e => setUrlText(e.target.value)}
              placeholder="http://10.0.0.5&#10;https://app.corp.local"
              rows={4}
              style={{
                width: '100%', background: 'var(--bg)', border: '1px solid var(--rule)',
                color: 'var(--fg)', fontFamily: 'var(--font-mono)', fontSize: 12,
                padding: '8px 10px', borderRadius: 3, resize: 'vertical',
              }}
            />
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 10 }}>
              <button className="btn btn-primary" onClick={startCapture} disabled={running} style={{ height: 32, padding: '0 16px', fontSize: 12 }}>
                <Icon name={running ? 'refresh' : 'eye'} size={12} style={{ marginRight: 6 }} />
                {running ? 'Capturing…' : 'Capture'}
              </button>
              {log.length > 0 && (
                <span className="mono" style={{ fontSize: 11, color: 'var(--fg-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                  {log[log.length - 1]}
                </span>
              )}
            </div>
          </div>

          {/* Gallery */}
          {shots.length === 0 ? (
            <EmptyState icon="eye" title="No screenshots yet" hint="Run a capture above to populate the gallery." />
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 14 }}>
              {shots.map(s => (
                <div key={s.id} style={{ border: '1px solid var(--rule)', borderRadius: 3, overflow: 'hidden', background: 'var(--bg-2)' }}>
                  <div
                    onClick={() => setLightbox(s)}
                    style={{ cursor: 'pointer', aspectRatio: '16 / 10', overflow: 'hidden', background: 'var(--bg)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                  >
                    <img
                      src={authedUrl(`/screenshots/${s.id}/image`)}
                      alt={s.url}
                      style={{ width: '100%', height: '100%', objectFit: 'cover', objectPosition: 'top' }}
                      loading="lazy"
                    />
                  </div>
                  <div style={{ padding: '8px 10px', display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className="mono" style={{ flex: 1, fontSize: 11, color: 'var(--fg-2)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={s.url}>
                      {s.url}
                    </span>
                    <button onClick={() => remove(s.id)} title="Delete" style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', display: 'flex' }}>
                      <Icon name="trash" size={12} />
                    </button>
                  </div>
                  {/* Attach as finding evidence */}
                  <div style={{ padding: '0 10px 8px', display: 'flex', alignItems: 'center', gap: 6 }}>
                    {s.finding_id ? (
                      <>
                        <Icon name="flag" size={11} color="var(--accent)" />
                        <span className="mono" style={{ flex: 1, fontSize: 10, color: 'var(--accent)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={findings.find(f => f.id === s.finding_id)?.title}>
                          {findings.find(f => f.id === s.finding_id)?.title ?? 'evidence'}
                        </span>
                        <button onClick={() => linkShot(s.id, null)} title="Detach" style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--fg-4)', fontSize: 10 }}>unlink</button>
                      </>
                    ) : (
                      <select
                        value=""
                        onChange={e => e.target.value && linkShot(s.id, e.target.value)}
                        disabled={findings.length === 0}
                        style={{ width: '100%', background: 'var(--bg)', border: '1px solid var(--rule)', color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', fontSize: 10, padding: '3px 6px', borderRadius: 2 }}
                      >
                        <option value="">{findings.length ? 'Attach to finding…' : 'no findings yet'}</option>
                        {findings.map(f => <option key={f.id} value={f.id}>[{f.severity}] {f.title.slice(0, 50)}</option>)}
                      </select>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {/* Lightbox */}
      {lightbox && (
        <div
          onClick={() => setLightbox(null)}
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.85)', zIndex: 100, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: 32 }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12, maxWidth: '90vw' }}>
            <span className="mono" style={{ fontSize: 12, color: 'var(--fg)' }}>{lightbox.url}</span>
            {lightbox.status_code && <span className="mono" style={{ fontSize: 11, color: 'var(--accent)' }}>{lightbox.status_code}</span>}
            <button onClick={() => setLightbox(null)} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--fg-2)', display: 'flex' }}>
              <Icon name="x" size={16} />
            </button>
          </div>
          <img
            src={authedUrl(`/screenshots/${lightbox.id}/image`)}
            alt={lightbox.url}
            onClick={e => e.stopPropagation()}
            style={{ maxWidth: '90vw', maxHeight: '80vh', objectFit: 'contain', border: '1px solid var(--rule-strong)' }}
          />
        </div>
      )}
    </div>
  )
}
