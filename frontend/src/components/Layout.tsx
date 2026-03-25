import { NavLink, Outlet, useNavigate, useLocation } from 'react-router-dom'
import { useEffect, useState } from 'react'
import CommandPalette from './CommandPalette'
import NotificationBell from './NotificationBell'
import {
  LayoutDashboard,
  ShieldCheck,
  Swords,
  FileText,
  Settings,
  Shield,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  Terminal,
  KeyRound,
  Search,
  Network,
  Lock,
  LogOut,
  User,
  BookOpen,
  HelpCircle,
  ShieldAlert,
  FileSearch,
  Radio,
  Cpu,
} from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'

interface NavItem {
  to: string
  label: string
  icon: React.ReactNode
}

interface NavGroup {
  id: string
  label: string
  color: string        // Tailwind text color class for the section label
  icon: React.ReactNode
  items: NavItem[]
}

// ── Standalone items (always visible, not grouped) ────────────────────────────

const TOP_ITEM: NavItem = {
  to: '/',
  label: 'Dashboard',
  icon: <LayoutDashboard size={18} />,
}

const BOTTOM_ITEMS: NavItem[] = [
  { to: '/reports',  label: 'Reports',  icon: <FileText size={18} /> },
  { to: '/settings', label: 'Settings', icon: <Settings size={18} /> },
  { to: '/guide',    label: 'Guide',    icon: <HelpCircle size={18} /> },
]

// ── Grouped items ─────────────────────────────────────────────────────────────

const NAV_GROUPS: NavGroup[] = [
  {
    id: 'recon',
    label: 'Recon',
    color: 'text-blue-400',
    icon: <Search size={13} />,
    items: [
      { to: '/osint',   label: 'OSINT',      icon: <Search size={18} /> },
      { to: '/network', label: 'Network Map', icon: <Network size={18} /> },
    ],
  },
  {
    id: 'offense',
    label: 'Offense',
    color: 'text-red-400',
    icon: <Swords size={13} />,
    items: [
      { to: '/pentest',   label: 'Pentest Workbench', icon: <Swords size={18} /> },
      { to: '/c2',        label: 'C2 Console',        icon: <Terminal size={18} /> },
      { to: '/playbooks', label: 'Playbooks',         icon: <BookOpen size={18} /> },
    ],
  },
  {
    id: 'credentials',
    label: 'Credentials',
    color: 'text-amber-400',
    icon: <KeyRound size={13} />,
    items: [
      { to: '/vault',    label: 'Credential Vault',  icon: <KeyRound size={18} /> },
      { to: '/cracking', label: 'Password Auditing', icon: <Lock size={18} /> },
    ],
  },
  {
    id: 'defense',
    label: 'Defense',
    color: 'text-green-400',
    icon: <ShieldCheck size={13} />,
    items: [
      { to: '/audit',     label: 'Audit Builder', icon: <ShieldCheck size={18} /> },
      { to: '/agents',    label: 'Agents',        icon: <Cpu size={18} /> },
      { to: '/listeners', label: 'Listeners',     icon: <Radio size={18} /> },
      { to: '/vulns',     label: 'Vuln Tracker',  icon: <ShieldAlert size={18} /> },
      { to: '/logs',      label: 'Log Analysis',  icon: <FileSearch size={18} /> },
    ],
  },
]

// ── NavLink helper ────────────────────────────────────────────────────────────

function NavItem({ item, collapsed }: { item: NavItem; collapsed: boolean }) {
  return (
    <NavLink
      to={item.to}
      end={item.to === '/'}
      title={collapsed ? item.label : undefined}
      className={({ isActive }) =>
        [
          'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-150',
          collapsed ? 'justify-center' : '',
          isActive
            ? 'nav-active text-cyan-300'
            : 'text-slate-400 hover:text-slate-200 hover:bg-[#0d1520]',
        ].join(' ')
      }
    >
      {({ isActive }) => (
        <>
          <span className={isActive ? 'text-cyan-400' : ''}>{item.icon}</span>
          {!collapsed && (
            <>
              <span className="flex-1">{item.label}</span>
              {isActive && <ChevronRight size={12} className="text-cyan-500 opacity-70" />}
            </>
          )}
        </>
      )}
    </NavLink>
  )
}

// ── Layout ────────────────────────────────────────────────────────────────────

export default function Layout() {
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null)
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('seraph_nav_collapsed') === 'true')
  const [paletteOpen, setPaletteOpen] = useState(false)
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()

  // Group open/closed state — persisted to localStorage, auto-opens the active group
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>(() => {
    const defaults: Record<string, boolean> = { recon: false, offense: false, credentials: false, defense: false }
    try {
      const saved = localStorage.getItem('seraph_nav_groups')
      const base = saved ? { ...defaults, ...JSON.parse(saved) } : defaults
      // Open the group containing the current route
      for (const group of NAV_GROUPS) {
        if (group.items.some(item => location.pathname === item.to || location.pathname.startsWith(item.to + '/'))) {
          base[group.id] = true
        }
      }
      return base
    } catch {
      return defaults
    }
  })

  function toggleGroup(id: string) {
    setOpenGroups(prev => {
      const next = { ...prev, [id]: !prev[id] }
      localStorage.setItem('seraph_nav_groups', JSON.stringify(next))
      return next
    })
  }

  function handleLogout() {
    logout()
    navigate('/login')
  }

  // Global keyboard shortcuts
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement).tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA') return
      if (e.key === '?') { e.preventDefault(); setPaletteOpen(o => !o) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  useEffect(() => {
    fetch('/api/v1/projects')
      .then(r => setBackendOnline(r.ok))
      .catch(() => setBackendOnline(false))
  }, [])

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: 'var(--bg-base)', color: '#e2e8f0' }}>
      {/* Sidebar */}
      <aside
        className="flex flex-col shrink-0 border-r border-cyan-900/20 relative transition-all duration-300"
        style={{ width: collapsed ? '64px' : '220px', background: 'var(--sidebar-bg)' }}
        aria-label="Main navigation"
      >
        {/* Gradient overlay */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{ background: 'linear-gradient(180deg, var(--accent-dim) 0%, transparent 40%)' }}
        />

        {/* Brand */}
        <div className={`flex items-center gap-3 border-b border-cyan-900/20 relative z-10 ${collapsed ? 'px-4 py-5 justify-center' : 'px-5 py-5'}`}>
          <div
            className="flex items-center justify-center w-9 h-9 rounded-lg shrink-0 relative"
            style={{ background: 'var(--accent-soft)', border: '1px solid var(--accent-border)' }}
          >
            <Shield size={18} className="text-cyan-400" />
            {backendOnline !== null && (
              <span className="absolute -top-1 -right-1 flex h-3 w-3">
                {backendOnline ? (
                  <>
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-60" />
                    <span className="relative inline-flex rounded-full h-3 w-3 bg-green-400" />
                  </>
                ) : (
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500" />
                )}
              </span>
            )}
          </div>
          {!collapsed && (
            <div>
              <span className="font-bold text-base tracking-widest gradient-text">SERAPH</span>
              <p className="text-[10px] text-slate-500 font-mono tracking-wide">Security Platform</p>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav className="flex-1 px-2 py-3 overflow-y-auto relative z-10 space-y-0.5">

          {/* Dashboard — standalone top */}
          <NavItem item={TOP_ITEM} collapsed={collapsed} />

          {/* Grouped sections */}
          {NAV_GROUPS.map(group => {
            const isOpen = openGroups[group.id] ?? true
            return (
              <div key={group.id}>
                {/* Section header */}
                {!collapsed ? (
                  <button
                    onClick={() => toggleGroup(group.id)}
                    className="w-full flex items-center gap-2 px-3 py-1.5 mt-2 rounded-lg hover:bg-[#0d1520] transition-colors"
                  >
                    <span className={group.color}>{group.icon}</span>
                    <span className={`flex-1 text-left text-[10px] font-bold uppercase tracking-widest ${group.color}`}>
                      {group.label}
                    </span>
                    <ChevronDown
                      size={11}
                      className="text-slate-600 transition-transform duration-200"
                      style={{ transform: isOpen ? 'rotate(0deg)' : 'rotate(-90deg)' }}
                    />
                  </button>
                ) : (
                  /* Collapsed: show thin divider between groups */
                  <div className="my-2 mx-3 border-t border-cyan-900/15" />
                )}

                {/* Group items */}
                {(isOpen || collapsed) && (
                  <div className={!collapsed ? 'ml-1' : ''}>
                    {group.items.map(item => (
                      <NavItem key={item.to} item={item} collapsed={collapsed} />
                    ))}
                  </div>
                )}
              </div>
            )
          })}

          {/* Divider before bottom standalones */}
          <div className="my-2 mx-1 border-t border-cyan-900/15" />

          {/* Reports */}
          <NavItem item={BOTTOM_ITEMS[0]} collapsed={collapsed} />
        </nav>

        {/* Footer */}
        <div className="px-2 py-3 border-t border-cyan-900/20 relative z-10 space-y-1.5">
          {/* Notification bell */}
          <div className={`flex px-1 pb-1 ${collapsed ? 'justify-center' : 'justify-end'}`}>
            <NotificationBell />
          </div>
          {/* Settings + Guide */}
          {BOTTOM_ITEMS.slice(1).map(item => (
            <NavItem key={item.to} item={item} collapsed={collapsed} />
          ))}

          <div className="pt-1 space-y-1.5">
            {!collapsed && user && (
              <div className="glass rounded-lg px-3 py-2 flex items-center gap-2">
                <div
                  className="w-6 h-6 rounded-full flex items-center justify-center shrink-0"
                  style={{ background: 'var(--accent-mid)', border: '1px solid var(--accent-border)' }}
                >
                  <User size={11} className="text-cyan-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-[11px] font-semibold text-slate-300 truncate">{user.username}</div>
                  <div className="text-[9px] text-slate-500 capitalize">{user.role}</div>
                </div>
                <button
                  onClick={handleLogout}
                  title="Sign out"
                  className="text-slate-500 hover:text-red-400 transition-colors flex-shrink-0"
                >
                  <LogOut size={13} />
                </button>
              </div>
            )}

            {collapsed && (
              <button
                onClick={handleLogout}
                title="Sign out"
                className="w-full flex items-center justify-center py-2 text-slate-500 hover:text-red-400 transition-colors"
              >
                <LogOut size={14} />
              </button>
            )}

            {!collapsed && (
              <div className="glass rounded-lg px-3 py-1.5 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-400" style={{ boxShadow: '0 0 6px rgba(34,197,94,0.8)' }} />
                  <span className="text-[10px] text-slate-400 font-mono">
                    {backendOnline === null ? 'connecting' : backendOnline ? 'online' : 'offline'}
                  </span>
                </div>
                <span className="text-[10px] text-slate-500 font-mono">v0.1.0</span>
              </div>
            )}
          </div>
        </div>

        {/* Collapse toggle */}
        <button
          onClick={() => setCollapsed(c => { const next = !c; localStorage.setItem('seraph_nav_collapsed', String(next)); return next })}
          className="absolute -right-3 top-1/2 -translate-y-1/2 z-20 flex items-center justify-center w-6 h-6 rounded-full border border-cyan-900/40 text-slate-400 hover:text-cyan-400 hover:border-cyan-500/50 transition-colors"
          style={{ background: 'var(--bg-surface)' }}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? <ChevronRight size={12} /> : <ChevronLeft size={12} />}
        </button>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto dot-grid page-enter" style={{ background: 'var(--bg-base)' }}>
        <Outlet />
      </main>

      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} />}
    </div>
  )
}
