/**
 * ActiveUsers — real-time presence indicator.
 *
 * Connects to /ws/presence/{projectId} and shows avatars of other users
 * currently viewing the same project. Announces the current user's page
 * via "page" messages whenever the route changes.
 *
 * Usage: <ActiveUsers projectId="..." page="dashboard" />
 */
import { useEffect, useRef, useState } from 'react'
import { useAuth } from '@/contexts/AuthContext'
import { Users } from 'lucide-react'

interface PresenceUser {
  id: string
  user: string
  page: string
}

function initials(name: string): string {
  return name
    .split(/[\s_-]+/)
    .slice(0, 2)
    .map(w => w[0]?.toUpperCase() ?? '')
    .join('')
    || name.slice(0, 2).toUpperCase()
}

// Deterministic colour from username
const AVATAR_COLORS = [
  '#06b6d4', '#8b5cf6', '#ec4899', '#f97316',
  '#22c55e', '#3b82f6', '#ef4444', '#f59e0b',
]
function avatarColor(name: string): string {
  let h = 0
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0
  return AVATAR_COLORS[h % AVATAR_COLORS.length]
}

interface ActiveUsersProps {
  projectId: string
  page?: string
}

export default function ActiveUsers({ projectId, page = '' }: ActiveUsersProps) {
  const { user } = useAuth()
  const [others, setOthers] = useState<PresenceUser[]>([])
  const [tooltip, setTooltip] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!projectId) return
    const displayName = user?.full_name || user?.username || 'anonymous'
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const url = `${proto}://${window.location.host}/ws/presence/${projectId}?user=${encodeURIComponent(displayName)}`

    let ws: WebSocket
    let reconnectTimer: ReturnType<typeof setTimeout>
    let alive = true

    function connect() {
      if (!alive) return
      ws = new WebSocket(url)
      wsRef.current = ws

      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data)
          if (msg.type === 'presence_snapshot') {
            setOthers(msg.users as PresenceUser[])
          } else if (msg.type === 'presence_join') {
            setOthers(prev => [...prev.filter(u => u.id !== msg.id), { id: msg.id, user: msg.user, page: msg.page }])
          } else if (msg.type === 'presence_leave') {
            setOthers(prev => prev.filter(u => u.id !== msg.id))
          } else if (msg.type === 'presence_update') {
            setOthers(prev => prev.map(u => u.id === msg.id ? { ...u, page: msg.page } : u))
          }
        } catch {
          // ignore parse errors
        }
      }

      ws.onclose = () => {
        if (alive) reconnectTimer = setTimeout(connect, 3000)
      }

      ws.onerror = () => ws.close()
    }

    connect()

    return () => {
      alive = false
      clearTimeout(reconnectTimer)
      ws?.close()
    }
  }, [projectId, user])

  // Announce page changes
  useEffect(() => {
    const ws = wsRef.current
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'page', page }))
    }
  }, [page])

  if (others.length === 0) return null

  const MAX_SHOWN = 4
  const shown = others.slice(0, MAX_SHOWN)
  const overflow = others.length - MAX_SHOWN

  return (
    <div className="flex items-center gap-2">
      <Users size={13} className="text-slate-500" />
      <div className="flex items-center -space-x-1.5">
        {shown.map(u => (
          <div
            key={u.id}
            className="relative"
            onMouseEnter={() => setTooltip(u.id)}
            onMouseLeave={() => setTooltip(null)}
          >
            <div
              className="w-6 h-6 rounded-full flex items-center justify-center text-[9px] font-bold text-white border-2 cursor-default select-none"
              style={{ background: avatarColor(u.user), borderColor: '#05080d' }}
              title={u.page ? `${u.user} — ${u.page}` : u.user}
            >
              {initials(u.user)}
            </div>
            {tooltip === u.id && (
              <div
                className="absolute top-8 left-1/2 -translate-x-1/2 z-50 whitespace-nowrap rounded-md px-2 py-1 text-[10px] text-slate-200 border border-slate-700 pointer-events-none"
                style={{ background: '#0b1120' }}
              >
                {u.user}{u.page ? ` · ${u.page}` : ''}
              </div>
            )}
          </div>
        ))}
        {overflow > 0 && (
          <div
            className="w-6 h-6 rounded-full flex items-center justify-center text-[9px] font-semibold text-slate-400 border-2"
            style={{ background: '#1e293b', borderColor: '#05080d' }}
            title={`+${overflow} more`}
          >
            +{overflow}
          </div>
        )}
      </div>
    </div>
  )
}
