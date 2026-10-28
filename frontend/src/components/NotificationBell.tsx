import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import { Bell, Check, Trash2, X } from 'lucide-react'
import { getApiBase, wsUrl } from '@/lib/config'

interface Notification {
  id: string
  title: string
  body: string
  type: 'info' | 'warning' | 'critical'
  read: boolean
  created_at: string | null
  scan_id: string | null
}

const TYPE_COLOR: Record<string, string> = {
  info:     'var(--fg-2)',
  warning:  'var(--warn)',
  critical: 'var(--crit)',
}

const TYPE_DOT_COLOR: Record<string, string> = {
  info:     'var(--fg-3)',
  warning:  'var(--warn)',
  critical: 'var(--crit)',
}

function timeAgo(iso: string | null): string {
  if (!iso) return ''
  const diff = Date.now() - new Date(iso).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export default function NotificationBell() {
  const [notifications, setNotifications] = useState<Notification[]>([])
  const [open, setOpen] = useState(false)
  const [popupPos, setPopupPos] = useState({ top: 0, left: 0 })
  const ref = useRef<HTMLDivElement>(null)
  const buttonRef = useRef<HTMLButtonElement>(null)
  const navigate = useNavigate()

  function load() {
    fetch(`${getApiBase()}/notifications`)
      .then(r => r.ok ? r.json() : [])
      .then(setNotifications)
      .catch(() => {})
  }

  useEffect(() => {
    load()

    let delay = 1000
    let ws: WebSocket
    let reconnectTimer: ReturnType<typeof setTimeout>

    function connect() {
      ws = new WebSocket(wsUrl(`/ws/events`))
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data)
          if (msg.type === 'scan_update') { load(); delay = 1000 }
        } catch { /* ignore */ }
      }
      ws.onclose = () => {
        delay = Math.min(delay * 2, 30000)
        reconnectTimer = setTimeout(connect, delay)
      }
    }

    connect()
    return () => { clearTimeout(reconnectTimer); ws?.close() }
  }, [])

  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const unread = notifications.filter(n => !n.read).length

  function markRead(id: string) {
    fetch(`${getApiBase()}/notifications/${id}/read`, { method: 'PATCH' }).then(load)
  }

  function handleClick(n: Notification) {
    if (!n.read) markRead(n.id)
    if (n.scan_id) {
      setOpen(false)
      navigate(`/scans?open=${n.scan_id}`)
    }
  }

  function markAllRead() {
    fetch(`${getApiBase()}/notifications/read-all`, { method: 'PATCH' }).then(load)
  }

  function clearRead() {
    fetch(`${getApiBase()}/notifications/read`, { method: 'DELETE' }).then(load)
  }

  return (
    <div className="relative" ref={ref}>
      <button
        ref={buttonRef}
        onClick={() => {
          if (!open && buttonRef.current) {
            const r = buttonRef.current.getBoundingClientRect()
            setPopupPos({ top: Math.max(8, r.top - 320), left: r.right + 8 })
          }
          setOpen(o => !o)
        }}
        style={{
          position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'center',
          width: 28, height: 28, background: 'transparent', border: 'none', cursor: 'pointer',
          color: 'var(--fg-3)',
        }}
        onMouseEnter={e => (e.currentTarget.style.color = 'var(--fg)')}
        onMouseLeave={e => (e.currentTarget.style.color = 'var(--fg-3)')}
        title="Notifications"
      >
        <Bell size={15} />
        {unread > 0 && (
          <span style={{
            position: 'absolute', top: -2, right: -2,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            width: 14, height: 14, borderRadius: '50%', background: 'var(--crit)',
            fontSize: 8, fontWeight: 700, color: '#fff', fontFamily: 'var(--font-mono)',
          }}>
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </button>

      {open && createPortal(
        <div style={{
          position: 'fixed', top: popupPos.top, left: popupPos.left,
          width: 300, background: 'var(--bg-2)', border: '1px solid var(--rule-strong)',
          boxShadow: '0 16px 48px rgba(0,0,0,0.5)', zIndex: 9999, overflow: 'hidden',
        }}>
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', borderBottom: '1px solid var(--rule)' }}>
            <span style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.14em', color: 'var(--fg-2)', fontFamily: 'var(--font-mono)' }}>Notifications</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {unread > 0 && (
                <button onClick={markAllRead} title="Mark all read" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', display: 'flex' }}>
                  <Check size={12} />
                </button>
              )}
              <button onClick={clearRead} title="Clear read" style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', display: 'flex' }}>
                <Trash2 size={12} />
              </button>
              <button onClick={() => setOpen(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', display: 'flex' }}>
                <X size={12} />
              </button>
            </div>
          </div>

          {/* List */}
          <div style={{ overflowY: 'auto', maxHeight: 300 }}>
            {notifications.length === 0 ? (
              <div style={{ padding: '32px 16px', textAlign: 'center' }}>
                <Bell size={22} style={{ margin: '0 auto 8px', display: 'block', color: 'var(--fg-4)' }} />
                <p style={{ fontSize: 11, color: 'var(--fg-4)' }}>No notifications</p>
              </div>
            ) : (
              notifications.map(n => (
                <div
                  key={n.id}
                  onClick={() => handleClick(n)}
                  style={{
                    display: 'flex', gap: 10, padding: '10px 14px',
                    borderBottom: '1px solid var(--rule-2)', cursor: 'pointer',
                    opacity: n.read ? 0.5 : 1,
                    background: 'transparent',
                  }}
                  onMouseEnter={e => { if (!n.read) e.currentTarget.style.background = 'var(--bg-3)' }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'transparent' }}
                  title={n.scan_id ? 'Click to view scan' : undefined}
                >
                  <span style={{
                    marginTop: 5, width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                    background: n.read ? 'var(--fg-4)' : (TYPE_DOT_COLOR[n.type] ?? 'var(--fg-3)'),
                  }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <p style={{ fontSize: 11, fontWeight: 500, color: n.read ? 'var(--fg-3)' : (TYPE_COLOR[n.type] ?? 'var(--fg)'), marginBottom: 2 }}>
                      {n.title}
                    </p>
                    {n.body && <p style={{ fontSize: 10, color: 'var(--fg-3)', lineHeight: 1.4 }}>{n.body}</p>}
                    <p style={{ fontSize: 9, color: 'var(--fg-4)', marginTop: 3, fontFamily: 'var(--font-mono)' }}>{timeAgo(n.created_at)}</p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>,
        document.body
      )}
    </div>
  )
}
