import { useState, useEffect, useRef } from 'react'
import { useAppStore } from '@/stores/appStore'
import { getApiBase } from '@/lib/config'
import Icon from '@/components/Icon'
import EmptyState from '@/components/EmptyState'
import { useToast } from '@/contexts/ToastContext'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Collection {
  id: string
  name: string
  domain: string
  source: string
  stats: Record<string, number>
  quick_win_count: number
  imported_at: string | null
}

interface QuickWin {
  kind: string
  title: string
  severity: string
  description: string
  count: number
  items: string[]
  command: string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--crit)',
  high: 'var(--high)',
  medium: 'var(--med)',
  low: 'var(--low)',
  info: 'var(--fg-3)',
}

const KIND_ICON: Record<string, string> = {
  kerberoast: 'key',
  asrep: 'lock',
  unconstrained: 'skull',
  high_value: 'flag',
}

// ── Quick-win card ────────────────────────────────────────────────────────────

function QuickWinCard({ win, onCopy }: { win: QuickWin; onCopy: (cmd: string) => void }) {
  const [open, setOpen] = useState(false)
  const color = SEV_COLOR[win.severity] ?? 'var(--fg-3)'
  return (
    <div style={{ border: '1px solid var(--rule)', borderLeft: `3px solid ${color}`, borderRadius: 3, marginBottom: 12 }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 10, padding: '11px 14px', background: 'var(--bg-2)', border: 'none', cursor: 'pointer', textAlign: 'left' }}
      >
        <Icon name={KIND_ICON[win.kind] ?? 'flag'} size={14} color={color} />
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--fg)' }}>{win.title}</span>
        <span className="mono" style={{ fontSize: 10, color, border: `1px solid ${color}`, background: `${color}18`, padding: '1px 6px', borderRadius: 2 }}>{win.severity}</span>
        <span className="mono" style={{ fontSize: 11, color: 'var(--fg-3)', background: 'var(--bg)', padding: '1px 7px', borderRadius: 10 }}>{win.count}</span>
        <Icon name={open ? 'chev_u' : 'chev_d'} size={11} color="var(--fg-3)" style={{ marginLeft: 'auto' }} />
      </button>
      {open && (
        <div style={{ padding: '12px 14px', borderTop: '1px solid var(--rule)' }}>
          <p style={{ fontSize: 12, color: 'var(--fg-2)', margin: '0 0 10px', lineHeight: 1.6 }}>{win.description}</p>

          {/* Command */}
          <div style={{ display: 'flex', alignItems: 'stretch', gap: 6, marginBottom: 12 }}>
            <code className="mono" style={{ flex: 1, fontSize: 11, color: 'var(--accent)', background: 'var(--bg)', padding: '8px 10px', borderRadius: 3, wordBreak: 'break-all', lineHeight: 1.5 }}>
              {win.command}
            </code>
            <button className="btn btn-sm" onClick={() => onCopy(win.command)} title="Copy command" style={{ flexShrink: 0 }}>
              <Icon name="copy" size={12} />
            </button>
          </div>

          {/* Affected principals */}
          <div className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)', marginBottom: 6 }}>Affected ({win.count})</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
            {win.items.map(p => (
              <span key={p} className="mono" style={{ fontSize: 10.5, color: 'var(--fg-2)', background: 'var(--bg)', border: '1px solid var(--rule)', padding: '2px 7px', borderRadius: 2 }}>{p}</span>
            ))}
            {win.count > win.items.length && (
              <span className="mono" style={{ fontSize: 10.5, color: 'var(--fg-4)', padding: '2px 7px' }}>+{win.count - win.items.length} more</span>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ADAttack() {
  const { selectedProject } = useAppStore()
  const { show: showToast } = useToast()
  const api = getApiBase()
  const fileRef = useRef<HTMLInputElement>(null)

  const [collections, setCollections] = useState<Collection[]>([])
  const [activeId, setActiveId] = useState('')
  const [wins, setWins] = useState<QuickWin[]>([])
  const [domain, setDomain] = useState('')
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')

  function loadCollections() {
    if (!selectedProject) return
    fetch(`${api}/ad/collections?project_id=${selectedProject.id}`)
      .then(r => r.json())
      .then((data: Collection[]) => {
        setCollections(data)
        if (data.length && !data.find(c => c.id === activeId)) setActiveId(data[0].id)
      })
      .catch(() => setError('Failed to load collections.'))
  }

  useEffect(() => { setCollections([]); setActiveId(''); setWins([]); loadCollections() }, [selectedProject])

  useEffect(() => {
    if (!activeId) { setWins([]); return }
    fetch(`${api}/ad/collections/${activeId}/quick-wins`)
      .then(r => r.json())
      .then(d => { setWins(d.quick_wins || []); setDomain(d.domain || '') })
      .catch(() => {})
  }, [activeId])

  async function handleUpload(file: File) {
    if (!selectedProject) return
    setUploading(true)
    setError('')
    try {
      const fd = new FormData()
      fd.append('project_id', selectedProject.id)
      fd.append('name', file.name)
      fd.append('file', file)
      const r = await fetch(`${api}/ad/collections/import`, { method: 'POST', body: fd })
      if (!r.ok) {
        const d = await r.json().catch(() => ({}))
        throw new Error(d.detail || 'Import failed')
      }
      const created: Collection = await r.json()
      showToast(`Imported ${created.name} — ${created.quick_win_count} quick-wins`, 'success')
      loadCollections()
      setActiveId(created.id)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Import failed')
    } finally {
      setUploading(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  async function copyCmd(cmd: string) {
    try { await navigator.clipboard.writeText(cmd); showToast('Command copied', 'success') } catch { /* ignore */ }
  }

  async function removeCollection(id: string) {
    await fetch(`${api}/ad/collections/${id}`, { method: 'DELETE' })
    if (activeId === id) setActiveId('')
    loadCollections()
  }

  const active = collections.find(c => c.id === activeId)

  return (
    <div style={{ padding: '24px 28px', maxWidth: 1000, margin: '0 auto', width: '100%' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 24, gap: 16 }}>
        <div>
          <div className="smcap" style={{ fontSize: 10, color: 'var(--fg-3)', marginBottom: 4 }}>Offense</div>
          <h1 className="sec-h" style={{ margin: 0 }}>AD Attack Suite</h1>
          <p style={{ fontSize: 12, color: 'var(--fg-3)', marginTop: 4 }}>
            Import a BloodHound/SharpHound collection to surface kerberoasting, AS-REP, delegation, and privileged-principal attack opportunities.
          </p>
        </div>
        <div style={{ flexShrink: 0 }}>
          <input
            ref={fileRef} type="file" accept=".zip,.json" style={{ display: 'none' }}
            onChange={e => { const f = e.target.files?.[0]; if (f) handleUpload(f) }}
          />
          <button className="btn btn-primary" onClick={() => fileRef.current?.click()} disabled={uploading || !selectedProject} style={{ height: 32, padding: '0 14px', fontSize: 12 }}>
            <Icon name="upload" size={12} style={{ marginRight: 6 }} />{uploading ? 'Importing…' : 'Import collection'}
          </button>
        </div>
      </div>

      <div style={{ height: 1, background: 'var(--rule)', marginBottom: 24 }} />

      {error && <div style={{ fontSize: 12, color: 'var(--crit)', marginBottom: 16 }}>{error}</div>}

      {!selectedProject ? (
        <EmptyState icon="cpu" title="No project selected" hint="Pick an engagement to import and analyze AD collections." />
      ) : collections.length === 0 ? (
        <EmptyState
          icon="cpu"
          title="No AD collections yet"
          hint="Run SharpHound or bloodhound-python against the domain, then import the .zip here."
          action={{ label: 'Import collection', onClick: () => fileRef.current?.click() }}
        />
      ) : (
        <>
          {/* Collection selector */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 20, flexWrap: 'wrap', alignItems: 'center' }}>
            {collections.map(c => (
              <button
                key={c.id}
                onClick={() => setActiveId(c.id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer',
                  background: activeId === c.id ? 'var(--accent-2)' : 'var(--bg-2)',
                  border: `1px solid ${activeId === c.id ? 'var(--accent)' : 'var(--rule)'}`,
                  borderRadius: 3, padding: '6px 10px',
                }}
              >
                <Icon name="cpu" size={12} color={activeId === c.id ? 'var(--accent)' : 'var(--fg-3)'} />
                <span style={{ fontSize: 12, color: 'var(--fg)' }}>{c.domain || c.name}</span>
                <span className="mono" style={{ fontSize: 10, color: 'var(--fg-4)' }}>{c.quick_win_count} wins</span>
                <span onClick={e => { e.stopPropagation(); removeCollection(c.id) }} title="Delete" style={{ display: 'flex', color: 'var(--fg-4)' }}>
                  <Icon name="trash" size={11} />
                </span>
              </button>
            ))}
          </div>

          {/* Stats */}
          {active && (
            <div style={{ display: 'flex', gap: 16, marginBottom: 20, fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--fg-2)', flexWrap: 'wrap' }}>
              {domain && <span>domain <span style={{ color: 'var(--accent)' }}>{domain}</span></span>}
              {Object.entries(active.stats).map(([k, v]) => (
                <span key={k}>{k} <span style={{ color: 'var(--accent)', fontWeight: 700 }}>{v}</span></span>
              ))}
            </div>
          )}

          {/* Quick wins */}
          {wins.length === 0 ? (
            <EmptyState icon="flag" title="No quick-wins found" hint="This collection had no kerberoastable, AS-REP, delegation, or privileged-principal hits." />
          ) : (
            wins.map(w => <QuickWinCard key={w.kind} win={w} onCopy={copyCmd} />)
          )}
        </>
      )}
    </div>
  )
}
