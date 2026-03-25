import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Bell, Check, Trash2, X } from 'lucide-react'

interface Notification {
  id: string
  title: string
  body: string
  type: 'info' | 'warning' | 'critical'
  read: boolean
  created_at: string | null
  scan_id: string | null
}

const TYPE_STYLES: Record<string, string> = {
  info:     'text-blue-400',
  warning:  'text-amber-400',
  critical: 'text-red-400',
}

const TYPE_DOT: Record<string, string> = {
  info:     'bg-blue-400',
  warning:  'bg-amber-400',
  critical: 'bg-red-400',
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
  const ref = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()

  function load() {
    fetch('/api/v1/notifications')
      .then(r => r.ok ? r.json() : [])
      .then(setNotifications)
      .catch(() => {})
  }

  useEffect(() => {
    load()
    const interval = setInterval(load, 30000)
    return () => clearInterval(interval)
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
    fetch(`/api/v1/notifications/${id}/read`, { method: 'PATCH' }).then(load)
  }

  function handleClick(n: Notification) {
    if (!n.read) markRead(n.id)
    if (n.scan_id) {
      setOpen(false)
      navigate(`/scans?open=${n.scan_id}`)
    }
  }

  function markAllRead() {
    fetch('/api/v1/notifications/read-all', { method: 'PATCH' }).then(load)
  }

  function clearRead() {
    fetch('/api/v1/notifications/read', { method: 'DELETE' }).then(load)
  }

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(o => !o)}
        className="relative flex items-center justify-center w-8 h-8 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-[#0d1520] transition-colors"
        title="Notifications"
      >
        <Bell size={16} />
        {unread > 0 && (
          <span className="absolute -top-0.5 -right-0.5 flex items-center justify-center w-4 h-4 rounded-full bg-red-500 text-[9px] font-bold text-white">
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute left-0 bottom-full mb-2 w-80 glass border border-cyan-900/30 rounded-xl shadow-2xl z-30 overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-cyan-900/15">
            <span className="text-xs font-semibold text-white uppercase tracking-wider">Notifications</span>
            <div className="flex items-center gap-2">
              {unread > 0 && (
                <button onClick={markAllRead} title="Mark all read" className="text-slate-500 hover:text-slate-300 transition-colors">
                  <Check size={13} />
                </button>
              )}
              <button onClick={clearRead} title="Clear read" className="text-slate-500 hover:text-slate-300 transition-colors">
                <Trash2 size={13} />
              </button>
              <button onClick={() => setOpen(false)} className="text-slate-500 hover:text-slate-300 transition-colors">
                <X size={13} />
              </button>
            </div>
          </div>

          {/* List */}
          <div className="overflow-y-auto" style={{ maxHeight: '320px' }}>
            {notifications.length === 0 ? (
              <div className="py-10 text-center">
                <Bell size={24} className="mx-auto mb-2 text-slate-700" />
                <p className="text-xs text-slate-600">No notifications</p>
              </div>
            ) : (
              notifications.map(n => (
                <div
                  key={n.id}
                  onClick={() => handleClick(n)}
                  className={`flex gap-3 px-4 py-3 border-b border-cyan-900/10 transition-colors cursor-pointer ${
                    n.read ? 'opacity-50' : 'hover:bg-cyan-950/20'
                  }`}
                  title={n.scan_id ? 'Click to view scan' : undefined}
                >
                  <span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${n.read ? 'bg-slate-700' : TYPE_DOT[n.type] ?? 'bg-slate-500'}`} />
                  <div className="flex-1 min-w-0">
                    <p className={`text-xs font-medium ${n.read ? 'text-slate-500' : TYPE_STYLES[n.type] ?? 'text-slate-300'}`}>
                      {n.title}
                    </p>
                    {n.body && <p className="text-[11px] text-slate-500 mt-0.5 leading-snug">{n.body}</p>}
                    <p className="text-[10px] text-slate-700 mt-1">{timeAgo(n.created_at)}</p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
