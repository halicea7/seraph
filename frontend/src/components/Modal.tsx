import { useEffect, useRef } from 'react'
import type React from 'react'
import Icon from './Icon'

// ══════════════════════════════════════════════════════════════════════════════
// Shared modal shell — one canonical backdrop, Escape-to-close, backdrop-click,
// focus capture + return, role="dialog". Replaces the 7+ hand-rolled modal
// backdrops that drifted in opacity/structure across the pages.
// ══════════════════════════════════════════════════════════════════════════════

interface ModalProps {
  onClose: () => void
  title?: React.ReactNode
  children: React.ReactNode
  footer?: React.ReactNode
  /** Panel max width in px (or any CSS width string). Default 560. */
  width?: number | string
  /** Close when the backdrop is clicked. Default true. */
  closeOnBackdrop?: boolean
  /** Hide the default header (title + X). Default false. */
  hideHeader?: boolean
}

export default function Modal({
  onClose,
  title,
  children,
  footer,
  width = 560,
  closeOnBackdrop = true,
  hideHeader = false,
}: ModalProps) {
  const panelRef = useRef<HTMLDivElement>(null)
  const prevFocus = useRef<HTMLElement | null>(null)

  // Escape to close + capture/return focus
  useEffect(() => {
    prevFocus.current = document.activeElement as HTMLElement | null
    panelRef.current?.focus()
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') { e.stopPropagation(); onClose() }
    }
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('keydown', onKey)
      prevFocus.current?.focus?.()
    }
  }, [onClose])

  return (
    <div
      onMouseDown={closeOnBackdrop ? (e) => { if (e.target === e.currentTarget) onClose() } : undefined}
      style={{
        position: 'fixed', inset: 0, zIndex: 100,
        background: 'rgba(0,0,0,0.7)',
        backdropFilter: 'blur(2px)', WebkitBackdropFilter: 'blur(2px)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        padding: 24, animation: 'fadein .14s ease-out',
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === 'string' ? title : 'Dialog'}
        tabIndex={-1}
        style={{
          width: '100%', maxWidth: width, maxHeight: 'calc(100vh - 48px)',
          background: 'var(--bg-2)', border: '1px solid var(--rule-strong)',
          boxShadow: '0 16px 48px rgba(0,0,0,0.5)', outline: 'none',
          display: 'flex', flexDirection: 'column',
          animation: 'modal-pop .16s cubic-bezier(0.16,1,0.3,1)',
        }}
      >
        {!hideHeader && (
          <div className="sec-h" style={{ flexShrink: 0 }}>
            <span className="title">{title}</span>
            <button
              onClick={onClose}
              aria-label="Close dialog"
              style={{
                background: 'transparent', border: 'none', cursor: 'pointer',
                color: 'var(--fg-3)', display: 'flex', padding: 2,
              }}
              onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--fg)')}
              onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--fg-3)')}
            >
              <Icon name="x" size={14} />
            </button>
          </div>
        )}

        <div style={{ overflowY: 'auto', flex: 1, minHeight: 0 }}>
          {children}
        </div>

        {footer && (
          <div style={{
            flexShrink: 0, borderTop: '1px solid var(--rule)', padding: '12px var(--pad)',
            display: 'flex', justifyContent: 'flex-end', gap: 8,
          }}>
            {footer}
          </div>
        )}
      </div>
    </div>
  )
}
