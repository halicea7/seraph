import { useEffect, useRef, useState } from 'react'
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

const GROUP_COLORS: Record<string, string> = {
  Core:        'text-slate-400',
  Recon:       'text-blue-400',
  Offense:     'text-red-400',
  Credentials: 'text-amber-400',
  Defense:     'text-green-400',
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
      <div className="w-full max-w-md glass border border-cyan-900/40 rounded-xl shadow-2xl overflow-hidden">
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-cyan-900/20">
          <Command size={15} className="text-cyan-500 shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={onKey}
            placeholder="Go to…"
            className="flex-1 bg-transparent text-sm text-slate-200 placeholder-slate-500 outline-none"
          />
          <kbd className="text-[10px] text-slate-500 border border-slate-700 rounded px-1.5 py-0.5">ESC</kbd>
        </div>

        {/* Results */}
        <div ref={listRef} className="overflow-y-auto" style={{ maxHeight: '340px' }}>
          {filtered.length === 0 ? (
            <p className="px-4 py-6 text-center text-sm text-slate-500">No results</p>
          ) : (
            Object.entries(groups).map(([group, items]) => (
              <div key={group}>
                <p className={`px-4 pt-3 pb-1 text-[10px] font-bold uppercase tracking-widest ${GROUP_COLORS[group] ?? 'text-slate-500'}`}>
                  {group}
                </p>
                {items.map(item => (
                  <button
                    key={item.to}
                    data-idx={item.idx}
                    onClick={() => select(item)}
                    onMouseEnter={() => setCursor(item.idx)}
                    className={`w-full flex items-center gap-3 px-4 py-2.5 text-sm transition-colors text-left ${
                      cursor === item.idx
                        ? 'bg-cyan-950/40 text-white'
                        : 'text-slate-300 hover:bg-cyan-950/20'
                    }`}
                  >
                    <span className={cursor === item.idx ? 'text-cyan-400' : 'text-slate-500'}>
                      {item.icon}
                    </span>
                    {item.label}
                    {cursor === item.idx && (
                      <kbd className="ml-auto text-[10px] text-slate-500 border border-slate-700 rounded px-1.5 py-0.5">↵</kbd>
                    )}
                  </button>
                ))}
              </div>
            ))
          )}
        </div>

        <div className="px-4 py-2 border-t border-cyan-900/20 flex items-center gap-4 text-[10px] text-slate-600">
          <span><kbd className="border border-slate-700 rounded px-1">↑↓</kbd> navigate</span>
          <span><kbd className="border border-slate-700 rounded px-1">↵</kbd> open</span>
          <span><kbd className="border border-slate-700 rounded px-1">?</kbd> toggle</span>
        </div>
      </div>
    </div>
  )
}
