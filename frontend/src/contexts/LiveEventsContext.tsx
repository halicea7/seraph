import { createContext, useContext, useEffect, useRef } from 'react'
import type React from 'react'
import { wsUrl } from '@/lib/config'

// ══════════════════════════════════════════════════════════════════════════════
// One shared WebSocket to /ws/events. Components subscribe to backend pushes
// (scan_update, finding_created, session_established, …) without each opening
// their own socket. Reconnects with exponential backoff. Mounted only inside the
// authenticated tree (App.tsx ProtectedRoutes), so it connects after login.
// ══════════════════════════════════════════════════════════════════════════════

export interface LiveEventMsg { type: string; [k: string]: unknown }
type Listener = (msg: LiveEventMsg) => void

interface LiveEventsApi {
  subscribe: (cb: Listener) => () => void
}

const LiveEventsContext = createContext<LiveEventsApi | null>(null)

export function LiveEventsProvider({ children }: { children: React.ReactNode }) {
  const listeners = useRef<Set<Listener>>(new Set())
  // Stable API object so consumer effects don't re-subscribe every render.
  const apiRef = useRef<LiveEventsApi>({
    subscribe: (cb) => {
      listeners.current.add(cb)
      return () => { listeners.current.delete(cb) }
    },
  })

  useEffect(() => {
    let ws: WebSocket | null = null
    let delay = 1000
    let reconnectTimer: ReturnType<typeof setTimeout>
    let closed = false

    function scheduleReconnect() {
      delay = Math.min(delay * 2, 30000)
      reconnectTimer = setTimeout(connect, delay)
    }

    function connect() {
      try {
        ws = new WebSocket(wsUrl(`/ws/events`))
      } catch {
        scheduleReconnect()
        return
      }
      ws.onopen = () => { delay = 1000 }
      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data) as LiveEventMsg
          if (msg && msg.type && msg.type !== 'ping') {
            listeners.current.forEach((l) => { try { l(msg) } catch { /* ignore */ } })
          }
        } catch { /* ignore malformed */ }
      }
      ws.onerror = () => { ws?.close() }
      ws.onclose = () => { if (!closed) scheduleReconnect() }
    }

    connect()
    return () => { closed = true; clearTimeout(reconnectTimer); ws?.close() }
  }, [])

  return <LiveEventsContext.Provider value={apiRef.current}>{children}</LiveEventsContext.Provider>
}

export function useLiveEvents(): LiveEventsApi {
  return useContext(LiveEventsContext) || { subscribe: () => () => {} }
}
