import { createContext, useCallback, useContext, useRef, useState } from 'react'
import type React from 'react'
import Modal from '@/components/Modal'

// ══════════════════════════════════════════════════════════════════════════════
// Promise-based confirmation dialog. Replaces unguarded destructive actions and
// native window.confirm(). Usage:
//   const confirm = useConfirm()
//   if (!(await confirm({ title: 'Delete finding?', message: '…', danger: true }))) return
// ══════════════════════════════════════════════════════════════════════════════

interface ConfirmOptions {
  title: string
  message?: React.ReactNode
  confirmLabel?: string
  cancelLabel?: string
  danger?: boolean
}

type ConfirmFn = (opts: ConfirmOptions) => Promise<boolean>

const ConfirmContext = createContext<ConfirmFn | null>(null)

export function ConfirmProvider({ children }: { children: React.ReactNode }) {
  const [opts, setOpts] = useState<ConfirmOptions | null>(null)
  const resolver = useRef<((v: boolean) => void) | null>(null)

  const confirm = useCallback<ConfirmFn>((options) => {
    setOpts(options)
    return new Promise<boolean>((resolve) => { resolver.current = resolve })
  }, [])

  const close = useCallback((result: boolean) => {
    resolver.current?.(result)
    resolver.current = null
    setOpts(null)
  }, [])

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      {opts && (
        <Modal
          onClose={() => close(false)}
          title={opts.title}
          width={440}
          footer={
            <>
              <button className="btn" onClick={() => close(false)}>
                {opts.cancelLabel || 'Cancel'}
              </button>
              <button
                className={opts.danger ? 'btn btn-danger' : 'btn btn-primary'}
                onClick={() => close(true)}
                autoFocus
              >
                {opts.confirmLabel || 'Confirm'}
              </button>
            </>
          }
        >
          <div style={{ padding: 'var(--pad)', fontSize: 12.5, color: 'var(--fg-2)', lineHeight: 1.6 }}>
            {opts.message || 'This action cannot be undone.'}
          </div>
        </Modal>
      )}
    </ConfirmContext.Provider>
  )
}

export function useConfirm(): ConfirmFn {
  const ctx = useContext(ConfirmContext)
  // Fail soft to native confirm if the provider is missing.
  return ctx || (async (o) => window.confirm(o.title))
}
