import type React from 'react'
import type { AiModelOption } from '@/lib/ai'

// Shared model picker for every AI feature — lists [Local] (this computer) and
// [Server] (backend host) Ollama models.
export default function AiModelSelect({
  value, onChange, options, style,
}: {
  value: string
  onChange: (key: string) => void
  options: AiModelOption[]
  style?: React.CSSProperties
}) {
  if (options.length === 0) {
    return <span className="mono" style={{ fontSize: 10, color: 'var(--crit)' }}>no models — start Ollama / set Settings → AI</span>
  }
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      title="AI model — [Local] runs on this computer, [Server] on the backend host"
      style={{
        background: 'var(--bg)', border: '1px solid var(--rule)', color: 'var(--fg)',
        fontFamily: 'var(--font-mono)', fontSize: 10.5, padding: '3px 6px', borderRadius: 2,
        maxWidth: 240, ...style,
      }}
    >
      {options.map(o => <option key={o.key} value={o.key}>{o.label}</option>)}
    </select>
  )
}
