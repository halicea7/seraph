import type React from 'react'
import Icon from './Icon'

// ══════════════════════════════════════════════════════════════════════════════
// Shared empty-state: icon + title + optional hint + optional CTA.
// Replaces bare "No X yet." monospace text scattered across pages.
// ══════════════════════════════════════════════════════════════════════════════

interface EmptyStateProps {
  /** Icon name (see components/Icon.tsx) or a custom node. */
  icon?: string | React.ReactNode
  title: string
  hint?: string
  /** Optional call-to-action. */
  action?: { label: string; onClick: () => void }
  /** Vertical padding. Default 48. */
  pad?: number
}

export default function EmptyState({ icon = 'folder', title, hint, action, pad = 48 }: EmptyStateProps) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      textAlign: 'center', padding: `${pad}px 24px`, gap: 10, color: 'var(--fg-3)',
    }}>
      <div style={{
        width: 44, height: 44, display: 'flex', alignItems: 'center', justifyContent: 'center',
        border: '1px solid var(--rule-strong)', borderRadius: '50%', color: 'var(--fg-4)',
        marginBottom: 2,
      }}>
        {typeof icon === 'string' ? <Icon name={icon} size={18} color="var(--fg-3)" /> : icon}
      </div>
      <div style={{
        fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--fg-2)', letterSpacing: '0.02em',
      }}>
        {title}
      </div>
      {hint && (
        <div style={{ fontSize: 11.5, color: 'var(--fg-4)', maxWidth: 360, lineHeight: 1.5 }}>
          {hint}
        </div>
      )}
      {action && (
        <button className="btn btn-primary btn-sm" style={{ marginTop: 6 }} onClick={action.onClick}>
          <Icon name="plus" size={11} color="#1a1408" />
          {action.label}
        </button>
      )}
    </div>
  )
}
