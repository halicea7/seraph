import { useEffect, useRef, useState } from 'react'
import type React from 'react'
import { useNavigate } from 'react-router-dom'
import {
  LayoutDashboard, Search, Network, Swords, Terminal, BookOpen,
  KeyRound, Lock, ShieldCheck, ShieldAlert, FileSearch,
  FileText, Settings, HelpCircle, Command, GitBranch, Cpu, Radio,
} from 'lucide-react'

interface Route {
  label: string
  to: string
  icon: React.ReactNode
  group: string
}

const ROUTES: Route[] = [
  { label: 'Dashboard',          to: '/',          icon: <LayoutDashboard size={15} />, group: 'Core' },
  { label: 'OSINT',              to: '/osint',      icon: <Search size={15} />,         group: 'Recon' },
  { label: 'Network Map',        to: '/network',    icon: <Network size={15} />,        group: 'Recon' },
  { label: 'Pentest Workbench',  to: '/pentest',    icon: <Swords size={15} />,         group: 'Offense' },
  { label: 'C2 Console',         to: '/c2',         icon: <Terminal size={15} />,       group: 'Offense' },
  { label: 'Playbooks',          to: '/playbooks',  icon: <BookOpen size={15} />,       group: 'Offense' },
  { label: 'Attack Paths',       to: '/attack-paths', icon: <GitBranch size={15} />,    group: 'Offense' },
  { label: 'Credential Vault',   to: '/vault',      icon: <KeyRound size={15} />,       group: 'Credentials' },
  { label: 'Password Auditing',  to: '/cracking',   icon: <Lock size={15} />,           group: 'Credentials' },
  { label: 'Audit Builder',      to: '/audit',      icon: <ShieldCheck size={15} />,    group: 'Defense' },
  { label: 'Agents',             to: '/agents',     icon: <Cpu size={15} />,            group: 'Defense' },
  { label: 'Listeners',          to: '/listeners',  icon: <Radio size={15} />,          group: 'Defense' },
  { label: 'Vuln Tracker',       to: '/vulns',      icon: <ShieldAlert size={15} />,    group: 'Defense' },
  { label: 'CVE Watch',          to: '/cve-watch',  icon: <ShieldAlert size={15} />,    group: 'Defense' },
  { label: 'Log Analysis',       to: '/logs',       icon: <FileSearch size={15} />,     group: 'Defense' },
  { label: 'Reports',            to: '/reports',    icon: <FileText size={15} />,       group: 'Core' },
  { label: 'Settings',           to: '/settings',   icon: <Settings size={15} />,       group: 'Core' },
  { label: 'Guide',              to: '/guide',      icon: <HelpCircle size={15} />,     group: 'Core' },
  { label: 'All Findings',       to: '/findings',   icon: <ShieldAlert size={15} />,    group: 'Core' },
  { label: 'All Scans',          to: '/scans',      icon: <FileSearch size={15} />,     group: 'Core' },
]

const GROUP_COLOR_STYLES: Record<string, React.CSSProperties> = {
  Core:        { color: 'var(--fg-3)' },
  Recon:       { color: 'var(--accent)' },
  Offense:     { color: 'var(--crit)' },
  Credentials: { color: 'var(--warn)' },
  Defense:     { color: 'var(--ok)' },
}

interface Props {
  onClose: () => void
}

export default function CommandPalette({ onClose }: Props) {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [cursor, setCursor] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  const filtered = query.trim()
    ? ROUTES.filter(r => r.label.toLowerCase().includes(query.toLowerCase()))
    : ROUTES

  useEffect(() => { inputRef.current?.focus() }, [])
  useEffect(() => { setCursor(0) }, [query])

  // Scroll active item into view
  useEffect(() => {
    const el = listRef.current?.querySelector(`[data-idx="${cursor}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [cursor])

  function select(route: Route) {
    navigate(route.to)
    onClose()
  }

  function onKey(e: React.KeyboardEvent) {
    if (e.key === 'ArrowDown') { e.preventDefault(); setCursor(c => Math.min(c + 1, filtered.length - 1)) }
    if (e.key === 'ArrowUp')   { e.preventDefault(); setCursor(c => Math.max(c - 1, 0)) }
    if (e.key === 'Enter' && filtered[cursor]) select(filtered[cursor])
    if (e.key === 'Escape') onClose()
  }

  // Group results
  const groups: Record<string, Array<Route & { idx: number }>> = {}
  filtered.forEach((r, i) => {
    if (!groups[r.group]) groups[r.group] = []
    groups[r.group].push({ ...r, idx: i })
  })

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]"
      style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(4px)' }}
      onMouseDown={e => { if (e.target === e.currentTarget) onClose() }}
    >
      <div style={{
        width: '100%', maxWidth: 460,
        background: 'var(--bg-2)', border: '1px solid var(--rule-strong)',
        boxShadow: '0 20px 60px rgba(0,0,0,0.6)', overflow: 'hidden',
      }}>
        {/* Search input */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px', borderBottom: '1px solid var(--rule)' }}>
          <Command size={14} style={{ color: 'var(--accent)', flexShrink: 0 }} />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={onKey}
            placeholder="Go to…"
            style={{ flex: 1, background: 'transparent', border: 'none', outline: 'none', fontSize: 13, color: 'var(--fg)', fontFamily: 'var(--font-sans)' }}
          />
          <kbd style={{ fontSize: 10, color: 'var(--fg-4)', border: '1px solid var(--rule-strong)', padding: '1px 5px', fontFamily: 'var(--font-mono)' }}>ESC</kbd>
        </div>

        {/* Results */}
        <div ref={listRef} style={{ overflowY: 'auto', maxHeight: 340 }}>
          {filtered.length === 0 ? (
            <p style={{ padding: '24px 16px', textAlign: 'center', fontSize: 13, color: 'var(--fg-3)' }}>No results</p>
          ) : (
            Object.entries(groups).map(([group, items]) => (
              <div key={group}>
                <p style={{ padding: '10px 14px 4px', fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.14em', fontFamily: 'var(--font-mono)', ...GROUP_COLOR_STYLES[group] }}>
                  {group}
                </p>
                {items.map(item => (
                  <button
                    key={item.to}
                    data-idx={item.idx}
                    onClick={() => select(item)}
                    onMouseEnter={() => setCursor(item.idx)}
                    style={{
                      width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                      padding: '8px 14px', fontSize: 13, textAlign: 'left', border: 'none', cursor: 'pointer',
                      background: cursor === item.idx ? 'var(--accent-2)' : 'transparent',
                      color: cursor === item.idx ? 'var(--fg)' : 'var(--fg-2)',
                      fontFamily: 'var(--font-sans)',
                    }}
                  >
                    <span style={{ color: cursor === item.idx ? 'var(--accent)' : 'var(--fg-4)' }}>
                      {item.icon}
                    </span>
                    {item.label}
                    {cursor === item.idx && (
                      <kbd style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--fg-4)', border: '1px solid var(--rule-strong)', padding: '1px 4px', fontFamily: 'var(--font-mono)' }}>↵</kbd>
                    )}
                  </button>
                ))}
              </div>
            ))
          )}
        </div>

        <div style={{ padding: '6px 14px', borderTop: '1px solid var(--rule)', display: 'flex', alignItems: 'center', gap: 16, fontSize: 10, color: 'var(--fg-4)', fontFamily: 'var(--font-mono)' }}>
          <span><kbd style={{ border: '1px solid var(--rule-strong)', padding: '0 3px' }}>↑↓</kbd> navigate</span>
          <span><kbd style={{ border: '1px solid var(--rule-strong)', padding: '0 3px' }}>↵</kbd> open</span>
          <span><kbd style={{ border: '1px solid var(--rule-strong)', padding: '0 3px' }}>?</kbd> toggle</span>
        </div>
      </div>
    </div>
  )
}
