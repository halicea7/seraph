import { createContext, useCallback, useContext, useRef, useState } from 'react'
import type React from 'react'
import Icon from '@/components/Icon'

// ══════════════════════════════════════════════════════════════════════════════
// Global toast queue. Replaces alert() and silent `.catch(() => {})` with
// stacking, auto-dismissing feedback. Usage:
//   const toast = useToast()
//   toast.error('Could not connect to Nessus')
//   toast.success('Project created')
// ══════════════════════════════════════════════════════════════════════════════

type ToastType = 'success' | 'error' | 'info'

interface ToastItem {
  id: number
  type: ToastType
  message: string
}

interface ToastApi {
  show: (message: string, type?: ToastType) => void
  success: (message: string) => void
  error: (message: string) => void
  info: (message: string) => void
}

const ToastContext = createContext<ToastApi | null>(null)

const TYPE_META: Record<ToastType, { icon: string; color: string; border: string }> = {
  success: { icon: 'check', color: 'var(--ok)',   border: 'rgba(107,138,114,0.45)' },
  error:   { icon: 'x',     color: 'var(--crit)', border: 'rgba(232,92,78,0.45)' },
  info:    { icon: 'bell',  color: 'var(--accent)', border: 'var(--accent-border)' },
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const nextId = useRef(1)

  const remove = useCallback((id: number) => {
    setToasts((list) => list.filter((t) => t.id !== id))
  }, [])

  const show = useCallback((message: string, type: ToastType = 'info') => {
    const id = nextId.current++
    setToasts((list) => [...list, { id, type, message }])
    setTimeout(() => remove(id), 4200)
  }, [remove])

  const api: ToastApi = {
    show,
    success: (m) => show(m, 'success'),
    error: (m) => show(m, 'error'),
    info: (m) => show(m, 'info'),
  }

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div style={{
        position: 'fixed', top: 40, left: '50%', transform: 'translateX(-50%)',
        zIndex: 200, display: 'flex', flexDirection: 'column', gap: 8,
        alignItems: 'center', pointerEvents: 'none',
      }}>
        {toasts.map((t) => {
          const meta = TYPE_META[t.type]
          return (
            <div
              key={t.id}
              onClick={() => remove(t.id)}
              style={{
                pointerEvents: 'auto', cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: 9,
                minWidth: 260, maxWidth: 460,
                background: 'var(--bg-2)', border: `1px solid ${meta.border}`,
                borderLeft: `2px solid ${meta.color}`,
                padding: '9px 14px', boxShadow: '0 8px 28px rgba(0,0,0,0.45)',
                animation: 'toast-in .22s cubic-bezier(0.16,1,0.3,1)',
              }}
            >
              <Icon name={meta.icon} size={13} color={meta.color} />
              <span style={{ fontSize: 12, color: 'var(--fg)', fontFamily: 'var(--font-mono)', lineHeight: 1.4 }}>
                {t.message}
              </span>
            </div>
          )
        })}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext)
  if (!ctx) {
    // Fail soft — never crash a page because a provider is missing.
    return { show: () => {}, success: () => {}, error: () => {}, info: () => {} }
  }
  return ctx
}
