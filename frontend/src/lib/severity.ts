import type React from 'react'

// ══════════════════════════════════════════════════════════════════════════════
// Single source of truth for severity + finding-status styling.
// Derived from the design tokens in index.css (--crit/--high/--med/--low/--info)
// and the .badge-* classes. Replaces the drifting per-page maps that previously
// lived in FindingsTable.tsx, AllFindings.tsx, Playbooks.tsx, VulnTracker.tsx.
// ══════════════════════════════════════════════════════════════════════════════

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

/** Normalize arbitrary backend strings to a known severity bucket. */
export function normSev(s: string | null | undefined): Severity {
  const v = (s || '').toLowerCase().trim()
  if (v === 'critical' || v === 'crit') return 'critical'
  if (v === 'high') return 'high'
  if (v === 'medium' || v === 'med' || v === 'moderate') return 'medium'
  if (v === 'low') return 'low'
  return 'info'
}

/** Token-based foreground color for a severity. */
export const SEV_COLOR: Record<Severity, string> = {
  critical: 'var(--crit)',
  high:     'var(--high)',
  medium:   'var(--med)',
  low:      'var(--low)',
  info:     'var(--info)',
}

/** RGBA channels for each severity, so backgrounds/borders stay in sync with the color. */
const SEV_RGB: Record<Severity, string> = {
  critical: '232,92,78',
  high:     '240,168,58',
  medium:   '212,196,90',
  low:      '107,138,114',
  info:     '122,116,104',
}

/** Pill / badge inline style for a severity (color + translucent bg + border). */
export function sevPill(s: string | null | undefined): React.CSSProperties {
  const sev = normSev(s)
  const rgb = SEV_RGB[sev]
  return {
    color: SEV_COLOR[sev],
    background: `rgba(${rgb},0.08)`,
    border: `1px solid rgba(${rgb},0.4)`,
  }
}

/** The matching .badge-* class name, for callers that prefer CSS classes. */
export function sevBadgeClass(s: string | null | undefined): string {
  const map: Record<Severity, string> = {
    critical: 'badge badge-crit',
    high:     'badge badge-high',
    medium:   'badge badge-med',
    low:      'badge badge-low',
    info:     'badge badge-info',
  }
  return map[normSev(s)]
}

// ── Finding / vuln status ──────────────────────────────────────────────────────

export type FindingStatus =
  | 'open' | 'in-review' | 'in_progress' | 'remediated' | 'mitigated' | 'accepted' | 'false_positive'

export const STATUS_STYLES: Record<string, { color: string; bg: string; border: string }> = {
  'open':           { color: 'var(--crit)',   bg: 'rgba(232,92,78,0.08)',   border: 'rgba(232,92,78,0.25)' },
  'in-review':      { color: 'var(--accent)', bg: 'var(--accent-2)',        border: 'var(--accent-border)' },
  'in_progress':    { color: 'var(--accent)', bg: 'var(--accent-2)',        border: 'var(--accent-border)' },
  'remediated':     { color: 'var(--ok)',     bg: 'rgba(107,138,114,0.08)', border: 'rgba(107,138,114,0.25)' },
  'mitigated':      { color: 'var(--ok)',     bg: 'rgba(107,138,114,0.08)', border: 'rgba(107,138,114,0.25)' },
  'accepted':       { color: 'var(--fg-3)',   bg: 'rgba(122,116,104,0.08)', border: 'rgba(122,116,104,0.2)' },
  'false_positive': { color: '#a78bfa',       bg: 'rgba(167,139,250,0.08)', border: 'rgba(167,139,250,0.25)' },
}

export function statusStyle(s: string | null | undefined): { color: string; bg: string; border: string } {
  return STATUS_STYLES[(s || '').toLowerCase()] || STATUS_STYLES['accepted']
}
