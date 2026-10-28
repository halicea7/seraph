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
import { wsUrl } from '@/lib/config'

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
  '#f0a83a', '#b794f6', '#ec4899', '#f97316',
  '#22c55e', '#8ad26b', '#ef4444', '#d4c45a',
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
    const url = wsUrl(`/ws/presence/${projectId}?user=${encodeURIComponent(displayName)}`)

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
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <Users size={13} style={{ color: 'var(--fg-4)' }} />
      <div style={{ display: 'flex', alignItems: 'center' }}>
        {shown.map(u => (
          <div
            key={u.id}
            style={{ position: 'relative', marginLeft: -6 }}
            onMouseEnter={() => setTooltip(u.id)}
            onMouseLeave={() => setTooltip(null)}
          >
            <div
              style={{ width: 22, height: 22, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 8, fontWeight: 700, color: '#fff', border: '2px solid var(--bg)', background: avatarColor(u.user), cursor: 'default', userSelect: 'none' }}
              title={u.page ? `${u.user} — ${u.page}` : u.user}
            >
              {initials(u.user)}
            </div>
            {tooltip === u.id && (
              <div
                style={{ position: 'absolute', top: 28, left: '50%', transform: 'translateX(-50%)', zIndex: 50, whiteSpace: 'nowrap', padding: '3px 8px', fontSize: 10, color: 'var(--fg)', border: '1px solid var(--rule-strong)', background: 'var(--bg-3)', pointerEvents: 'none', fontFamily: 'var(--font-mono)' }}
              >
                {u.user}{u.page ? ` · ${u.page}` : ''}
              </div>
            )}
          </div>
        ))}
        {overflow > 0 && (
          <div
            style={{ width: 22, height: 22, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 8, fontWeight: 600, color: 'var(--fg-3)', border: '2px solid var(--bg)', background: 'var(--bg-3)', marginLeft: -6 }}
            title={`+${overflow} more`}
          >
            +{overflow}
          </div>
        )}
      </div>
    </div>
  )
}
