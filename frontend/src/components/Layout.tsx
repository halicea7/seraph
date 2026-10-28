import { NavLink, Outlet, useNavigate, useLocation } from 'react-router-dom'
import { useEffect, useRef, useState } from 'react'
import CommandPalette from './CommandPalette'
import Ticker from './Ticker'
import NotificationBell from './NotificationBell'
import ActiveUsers from './ActiveUsers'
import ProjectModal from './ProjectModal'
import Icon from './Icon'
import { useAppStore } from '@/stores/appStore'
import { useAINarrative } from '../contexts/AINarrativeContext'
import { useAuth } from '../contexts/AuthContext'
import { getApiBase } from '@/lib/config'
import { SeraphMark } from './SeraphMark'

// ── Nav structure (mirrors handoff shell.jsx) ─────────────────────────────────

const NAV_TOP = [
  { to: '/', label: 'Dashboard', icon: 'grid', end: true },
]

const NAV_GROUPS = [
  {
    id: 'recon', label: 'Recon',
    items: [
      { to: '/osint',   label: 'OSINT',       icon: 'search' },
      { to: '/network', label: 'Network Map', icon: 'network' },
      { to: '/screenshots', label: 'Screenshots', icon: 'eye' },
      { to: '/scans',   label: 'Scans',       icon: 'target' },
    ],
  },
  {
    id: 'offense', label: 'Offense',
    items: [
      { to: '/pentest',         label: 'Pentest Workbench', icon: 'swords' },
      { to: '/c2',              label: 'C2 Console',        icon: 'terminal' },
      { to: '/ad',              label: 'AD Attack Suite',   icon: 'cpu' },
      { to: '/playbooks',       label: 'Playbooks',         icon: 'book' },
      { to: '/attack-paths',    label: 'Attack Paths',      icon: 'activity' },
      { to: '/attack-nav',      label: 'ATT&CK Navigator',  icon: 'grid' },
      { to: '/operator',        label: 'AI Operator',       icon: 'cube' },
      { to: '/hermes',          label: 'Hermes Operator',   icon: 'zap' },
      { to: '/command-library', label: 'Command Library',   icon: 'fingerprint' },
      { to: '/http',            label: 'Request Workbench', icon: 'send' },
    ],
  },
  {
    id: 'infra', label: 'Infrastructure',
    items: [
      { to: '/listeners', label: 'Listeners', icon: 'radio' },
      { to: '/agents',    label: 'Agents',    icon: 'cpu' },
    ],
  },
  {
    id: 'credentials', label: 'Credentials',
    items: [
      { to: '/vault',    label: 'Credential Vault',  icon: 'key' },
      { to: '/cracking', label: 'Password Auditing', icon: 'lock' },
    ],
  },
  {
    id: 'analysis', label: 'Findings & Analysis',
    items: [
      { to: '/findings',  label: 'Findings',     icon: 'flag' },
      { to: '/ask',       label: 'Ask Seraph',   icon: 'help' },
      { to: '/cve-watch', label: 'CVE Watch',    icon: 'eye' },
      { to: '/timeline',  label: 'Timeline',     icon: 'clock' },
      { to: '/posture',   label: 'Posture',      icon: 'activity' },
      { to: '/logs',      label: 'Log Analysis', icon: 'history' },
      { to: '/scan-diff', label: 'Scan Diff',    icon: 'layers' },
    ],
  },
  {
    id: 'defense', label: 'Defense',
    items: [
      { to: '/audit', label: 'Audit Builder', icon: 'shield' },
    ],
  },
]

const NAV_BOTTOM = [
  { to: '/scratchpad', label: 'Scratchpad', icon: 'edit' },
  { to: '/reports',    label: 'Reports',    icon: 'file' },
  { to: '/settings', label: 'Settings', icon: 'cog' },
  { to: '/guide',    label: 'Guide',    icon: 'help' },
]

// ── Logo ──────────────────────────────────────────────────────────────────────

function Logo({ size = 22 }: { size?: number }) {
  return <SeraphMark size={size} />
}

// ── NavRow ────────────────────────────────────────────────────────────────────

function NavRow({ to, label, icon, end = false, railed = false }: { to: string; label: string; icon: string; end?: boolean; railed?: boolean }) {
  return (
    <NavLink
      to={to}
      end={end}
      className="nav-row"
      title={railed ? label : undefined}
      style={({ isActive }) => ({
        display: 'flex',
        alignItems: 'center',
        gap: railed ? 0 : 9,
        justifyContent: railed ? 'center' : 'flex-start',
        width: '100%',
        padding: railed ? '8px 0' : '6px 10px',
        marginBottom: 1,
        background: isActive ? 'var(--accent-2)' : 'transparent',
        border: 'none',
        borderLeft: isActive ? '2px solid var(--accent)' : '2px solid transparent',
        color: isActive ? 'var(--fg)' : 'var(--fg-2)',
        cursor: 'pointer',
        fontFamily: 'var(--font-sans)',
        fontSize: 12.5,
        textDecoration: 'none',
        transition: 'color .12s, background .12s',
      })}
    >
      {({ isActive }) => (
        <>
          <Icon name={icon} size={railed ? 15 : 13} color={isActive ? 'var(--accent)' : 'currentColor'} />
          {!railed && <span style={{ flex: 1 }}>{label}</span>}
          {!railed && isActive && <Icon name="chev_r" size={10} color="var(--accent)" />}
        </>
      )}
    </NavLink>
  )
}

// ── Sidebar ───────────────────────────────────────────────────────────────────

function Sidebar({ backendOnline }: { backendOnline: boolean | null }) {
  const { user, logout, token } = useAuth()
  const navigate = useNavigate()
  const { projects, selectedProject, setProjects, setSelectedProject, addProject } = useAppStore()
  const [showPicker, setShowPicker] = useState(false)
  const [showNewProject, setShowNewProject] = useState(false)
  const pickerRef = useRef<HTMLDivElement>(null)
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(() => {
    try { return JSON.parse(localStorage.getItem('nav-collapsed') || '{}') } catch { return {} }
  })

  function toggleGroup(id: string) {
    setCollapsed(prev => {
      const next = { ...prev, [id]: !prev[id] }
      try { localStorage.setItem('nav-collapsed', JSON.stringify(next)) } catch { /* ignore */ }
      return next
    })
  }

  // Whole-sidebar collapse to an icon-only rail
  const [railed, setRailed] = useState<boolean>(() => {
    try { return localStorage.getItem('nav-railed') === '1' } catch { return false }
  })
  function toggleRail() {
    setRailed(prev => {
      const next = !prev
      try { localStorage.setItem('nav-railed', next ? '1' : '0') } catch { /* ignore */ }
      if (next) setShowPicker(false)
      return next
    })
  }

  // Flatten all nav items for the icon rail (group labels are hidden when railed)
  const railSections = [NAV_TOP, NAV_GROUPS.flatMap(g => g.items), NAV_BOTTOM]

  // Load projects once
  useEffect(() => {
    if (!token) return
    fetch(`${getApiBase()}/projects`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.ok ? r.json() : [])
      .then(data => {
        setProjects(data)
        // Auto-select first project if none selected
        if (!selectedProject && data.length > 0) setSelectedProject(data[0])
      })
      .catch(() => {})
  }, [token])

  // Close picker on outside click
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (pickerRef.current && !pickerRef.current.contains(e.target as Node)) setShowPicker(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const initials = user?.username
    ? user.username.slice(0, 2).toUpperCase()
    : '??'

  function handleLogout() {
    logout()
    navigate('/login')
  }

  async function handleCreateProject(
    proj: { name: string; description: string },
    targets: any[],
    scope: any,
    nessusData?: { scan_id: number; host_ids: number[] },
  ) {
    const res = await fetch(`${getApiBase()}/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ ...proj, scope }),
    })
    if (!res.ok) { const d = await res.json(); throw new Error(d.detail || 'Failed') }
    const newProject = await res.json()

    // Create manually-entered targets if any
    for (const t of targets) {
      if (!t.hostname_or_ip.trim()) continue
      await fetch(`${getApiBase()}/projects/${newProject.id}/targets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(t),
      })
    }

    // Import selected Nessus hosts if provided
    if (nessusData) {
      await fetch(`${getApiBase()}/nessus/scans/${nessusData.scan_id}/import`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_id: newProject.id, host_ids: nessusData.host_ids }),
      })
    }

    addProject(newProject)
    setSelectedProject(newProject)
    setShowNewProject(false)
  }

  return (
    <>
    <aside style={{
      width: railed ? 56 : 230,
      flexShrink: 0,
      borderRight: '1px solid var(--rule)',
      background: 'var(--bg)',
      display: 'flex',
      flexDirection: 'column',
      height: '100vh',
      position: 'sticky',
      top: 0,
      // Lift above the page-content stacking context (`.page-enter` gets one via
      // its transform animation) so the railed engagement dropdown — which opens
      // to the right, overflowing the narrow rail into the page area — paints on
      // top instead of behind the page. Stays below modals (z-index 100).
      zIndex: 30,
      transition: 'width .16s ease',
    }}>
      {/* Brand */}
      <div style={{ padding: railed ? '14px 0 12px' : '18px 18px 16px', borderBottom: '1px solid var(--rule)' }}>
        {railed ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
            <Logo size={28} />
            <button onClick={toggleRail} title="Expand sidebar" className="nav-row"
              style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', display: 'flex', padding: 4 }}>
              <Icon name="chev_r" size={13} />
            </button>
          </div>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Logo size={28} />
            <div>
              <div className="mono" style={{ fontSize: 13, letterSpacing: '0.22em', fontWeight: 600 }}>SERAPH</div>
              <div className="mono" style={{ fontSize: 8.5, letterSpacing: '0.18em', color: 'var(--fg-3)', textTransform: 'uppercase' }}>Ops Console · v2.0</div>
            </div>
            <button onClick={toggleRail} title="Collapse sidebar" className="nav-row"
              style={{ marginLeft: 'auto', background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--fg-3)', display: 'flex', padding: 4 }}>
              <Icon name="chev_l" size={14} />
            </button>
          </div>
        )}
      </div>

      {/* Engagement switcher */}
      <div style={{ padding: railed ? '10px 0' : '10px 14px', borderBottom: '1px solid var(--rule)', position: 'relative', display: railed ? 'flex' : 'block', justifyContent: 'center' }} ref={pickerRef}>
        {!railed && <div className="smcap smcap-2" style={{ marginBottom: 6 }}>Engagement</div>}
        {railed ? (
          <button
            onClick={() => setShowPicker(v => !v)}
            title={selectedProject ? selectedProject.name : 'Select engagement'}
            className="nav-row"
            style={{
              width: 34, height: 34, display: 'flex', alignItems: 'center', justifyContent: 'center',
              background: 'transparent', border: `1px solid ${showPicker ? 'var(--accent)' : 'var(--rule)'}`,
              color: selectedProject ? 'var(--accent)' : 'var(--fg-3)', cursor: 'pointer',
            }}
          >
            <Icon name="folder" size={15} color="currentColor" />
          </button>
        ) : (
          <button
            onClick={() => setShowPicker(v => !v)}
            style={{
              width: '100%', textAlign: 'left', background: 'transparent',
              border: `1px solid ${showPicker ? 'var(--accent)' : 'var(--rule)'}`,
              padding: '8px 10px', display: 'flex', alignItems: 'center',
              justifyContent: 'space-between', color: 'var(--fg)', cursor: 'pointer',
            }}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              <span className="mono" style={{ fontSize: 11, color: 'var(--fg)' }}>
                {selectedProject ? selectedProject.name : 'No project'}
              </span>
              <span style={{ fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>
                {selectedProject ? `${selectedProject.target_count ?? 0} targets` : 'Select a project'}
              </span>
            </div>
            <Icon name={showPicker ? 'chev_u' : 'chev_d'} size={11} color="var(--fg-3)" />
          </button>
        )}

        {/* Dropdown */}
        {showPicker && (
          <div style={{
            position: 'absolute', top: railed ? 8 : '100%',
            left: railed ? '100%' : 0, right: railed ? 'auto' : 0, marginLeft: railed ? 6 : 0,
            width: railed ? 220 : 'auto', zIndex: 40,
            background: 'var(--bg-2)', border: '1px solid var(--rule-strong)',
            borderTop: railed ? '1px solid var(--rule-strong)' : 'none', boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
            maxHeight: 260, overflowY: 'auto',
            animation: 'modal-pop .13s cubic-bezier(0.16,1,0.3,1)', transformOrigin: 'top',
          }}>
            {projects.length === 0 ? (
              <div style={{ padding: '12px 14px', fontSize: 11, color: 'var(--fg-4)', fontFamily: 'var(--font-mono)' }}>No projects yet</div>
            ) : (
              projects.map(p => (
                <button
                  key={p.id}
                  onClick={() => { setSelectedProject(p); setShowPicker(false) }}
                  style={{
                    width: '100%', textAlign: 'left', padding: '9px 14px',
                    background: selectedProject?.id === p.id ? 'var(--accent-2)' : 'transparent',
                    borderLeft: `2px solid ${selectedProject?.id === p.id ? 'var(--accent)' : 'transparent'}`,
                    border: 'none', borderBottom: '1px solid var(--rule-2)', cursor: 'pointer',
                    display: 'flex', flexDirection: 'column', gap: 2,
                  }}
                  onMouseEnter={e => { if (selectedProject?.id !== p.id) e.currentTarget.style.background = 'var(--bg-3)' }}
                  onMouseLeave={e => { if (selectedProject?.id !== p.id) e.currentTarget.style.background = 'transparent' }}
                >
                  <span style={{ fontSize: 11, color: selectedProject?.id === p.id ? 'var(--accent)' : 'var(--fg)', fontFamily: 'var(--font-sans)' }}>{p.name}</span>
                  {p.description && <span style={{ fontSize: 10, color: 'var(--fg-4)', fontFamily: 'var(--font-sans)' }}>{p.description.slice(0, 40)}</span>}
                </button>
              ))
            )}
            <button
              onClick={() => { setShowPicker(false); setShowNewProject(true) }}
              style={{
                width: '100%', textAlign: 'left', padding: '9px 14px',
                background: 'transparent', border: 'none', borderTop: '1px solid var(--rule)',
                display: 'flex', alignItems: 'center', gap: 6,
                color: 'var(--accent)', fontSize: 11, cursor: 'pointer', fontFamily: 'var(--font-mono)',
              }}
            >
              <Icon name="plus" size={11} color="var(--accent)" />
              New Project
            </button>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, overflowY: 'auto', padding: railed ? '8px 4px' : '8px 8px' }}>
        {railed ? (
          railSections.map((items, si) => (
            <div key={si} style={si > 0 ? { borderTop: '1px solid var(--rule)', marginTop: 8, paddingTop: 8 } : undefined}>
              {items.map(item => (
                <NavRow key={item.to} to={item.to} label={item.label} icon={item.icon} end={(item as any).end} railed />
              ))}
            </div>
          ))
        ) : (
        <>
        {NAV_TOP.map(item => (
          <NavRow key={item.to} to={item.to} label={item.label} icon={item.icon} end={item.end} />
        ))}

        {NAV_GROUPS.map(group => {
          const isCol = collapsed[group.id]
          return (
            <div key={group.id} style={{ marginTop: 14 }}>
              <button
                onClick={() => toggleGroup(group.id)}
                className="smcap smcap-2 nav-row"
                aria-expanded={!isCol}
                style={{
                  width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '0 10px 4px', background: 'transparent', border: 'none', cursor: 'pointer',
                }}
              >
                <span>{group.label}</span>
                <Icon name={isCol ? 'chev_r' : 'chev_d'} size={9} color="var(--fg-4)" />
              </button>
              {!isCol && group.items.map(item => (
                <NavRow key={item.to} to={item.to} label={item.label} icon={item.icon} />
              ))}
            </div>
          )
        })}

        <div style={{ borderTop: '1px solid var(--rule)', margin: '14px 8px 8px' }} />
        <div className="smcap smcap-2" style={{ padding: '0 10px 4px' }}>Workspace</div>
        {NAV_BOTTOM.map(item => (
          <NavRow key={item.to} to={item.to} label={item.label} icon={item.icon} />
        ))}
        </>
        )}
      </nav>

      {/* Footer */}
      <div style={{ borderTop: '1px solid var(--rule)', padding: railed ? '10px 0' : 10 }}>
        {railed ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, padding: '4px 0' }}>
            <span
              className={`dot ${backendOnline ? 'dot-live' : backendOnline === false ? 'dot-crit' : 'dot-idle'}`}
              title={backendOnline === null ? 'connecting' : backendOnline ? 'backend online' : 'backend offline'}
            />
            <NotificationBell />
            <div title={`${user?.username ?? '—'} · ${user?.role ?? ''}`} style={{ width: 24, height: 24, border: '1px solid var(--rule-strong)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--fg-2)' }}>
              {initials}
            </div>
            <button
              onClick={handleLogout}
              title="Sign out"
              style={{ background: 'transparent', border: 'none', padding: 4, display: 'flex', color: 'var(--fg-3)', cursor: 'pointer' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--crit)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--fg-3)')}
            >
              <Icon name="logout" size={13} />
            </button>
          </div>
        ) : (
        <>
        {/* Status row */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '4px 4px 8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className={`dot ${backendOnline ? 'dot-live' : backendOnline === false ? 'dot-crit' : 'dot-idle'}`} />
            <span className="mono" style={{ fontSize: 10, color: 'var(--fg-2)' }}>
              {backendOnline === null ? 'connecting' : backendOnline ? 'backend online' : 'backend offline'}
            </span>
          </div>
          <NotificationBell />
        </div>

        {/* User row */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 4px', borderTop: '1px dashed var(--rule-strong)' }}>
          <div style={{
            width: 22,
            height: 22,
            border: '1px solid var(--rule-strong)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontFamily: 'var(--font-mono)',
            fontSize: 9,
            color: 'var(--fg-2)',
            flexShrink: 0,
          }}>
            {initials}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="mono" style={{ fontSize: 11, color: 'var(--fg)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {user?.username ?? '—'}
            </div>
            <div className="mono" style={{ fontSize: 9, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              {user?.role ?? '—'}
            </div>
          </div>
          <button
            onClick={handleLogout}
            title="Sign out"
            style={{
              background: 'transparent',
              border: 'none',
              padding: 4,
              height: 22,
              width: 22,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--fg-3)',
              cursor: 'pointer',
              flexShrink: 0,
            }}
            onMouseEnter={e => (e.currentTarget.style.color = 'var(--crit)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--fg-3)')}
          >
            <Icon name="logout" size={11} />
          </button>
        </div>
        </>
        )}
      </div>
    </aside>

    {showNewProject && (
      <ProjectModal
        onClose={() => setShowNewProject(false)}
        onSave={handleCreateProject}
      />
    )}
    </>
  )
}

// ── Layout ────────────────────────────────────────────────────────────────────

export default function Layout() {
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null)
  const { generating, progress, done, dismissDone } = useAINarrative()
  const location = useLocation()
  const isOnReports = location.pathname === '/reports'
  const [paletteOpen, setPaletteOpen] = useState(false)
  const { selectedProject } = useAppStore()
  const currentPage = location.pathname.replace(/^\//, '') || 'dashboard'

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
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: 'var(--bg)', color: 'var(--fg)' }}>
      <Sidebar backendOnline={backendOnline} />

      {/* Right column: ticker + page content */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>
        <Ticker backendOnline={backendOnline} />

        <main style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: 'var(--bg)', position: 'relative' }}>
          {selectedProject && (
            <div style={{ position: 'absolute', top: 12, right: 16, zIndex: 10 }}>
              <ActiveUsers projectId={selectedProject.id} page={currentPage} />
            </div>
          )}
          <div key={location.pathname} className="page-enter" style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
            <Outlet />
          </div>
        </main>
      </div>

      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} />}

      {/* AI narrative orb */}
      {(generating || done) && !isOnReports && (
        <NavLink
          to="/reports"
          onClick={done ? dismissDone : undefined}
          title={done ? 'Narrative ready — click to view' : 'AI Narrative generating…'}
          style={{
            position: 'fixed',
            bottom: 24,
            right: 24,
            zIndex: 50,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            borderRadius: '50%',
            width: 44,
            height: 44,
            background: 'rgba(10,5,20,0.92)',
            border: `1px solid ${done ? 'rgba(168,85,247,0.6)' : 'rgba(168,85,247,0.35)'}`,
            boxShadow: done
              ? '0 0 18px rgba(168,85,247,0.7), 0 0 36px rgba(168,85,247,0.3)'
              : '0 0 18px rgba(168,85,247,0.5)',
            animation: done ? 'seraph-orb-pulse 1.8s ease-in-out infinite' : undefined,
            textDecoration: 'none',
          }}
        >
          <svg width="44" height="44" viewBox="0 0 44 44" style={{ position: 'absolute', inset: 0 }}>
            <circle cx="22" cy="22" r="18" fill="none" stroke="rgba(168,85,247,0.15)" strokeWidth="3" />
            {done ? (
              <circle cx="22" cy="22" r="18" fill="none" stroke="#a855f7" strokeWidth="3" strokeLinecap="round"
                style={{ filter: 'drop-shadow(0 0 5px rgba(168,85,247,0.9))' }} />
            ) : progress !== null && progress >= 0 ? (
              <circle cx="22" cy="22" r="18" fill="none" stroke="#a855f7" strokeWidth="3" strokeLinecap="round"
                strokeDasharray={`${2 * Math.PI * 18}`}
                strokeDashoffset={`${2 * Math.PI * 18 * (1 - progress / 100)}`}
                transform="rotate(-90 22 22)"
                style={{ filter: 'drop-shadow(0 0 4px rgba(168,85,247,0.8))' }} />
            ) : (
              <circle cx="22" cy="22" r="18" fill="none" stroke="#a855f7" strokeWidth="3" strokeLinecap="round"
                strokeDasharray={`${2 * Math.PI * 18 * 0.3} ${2 * Math.PI * 18 * 0.7}`}
                style={{ filter: 'drop-shadow(0 0 4px rgba(168,85,247,0.8))', transformOrigin: '22px 22px', animation: 'spin 1s linear infinite' }} />
            )}
          </svg>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
            stroke={done ? '#e9d5ff' : '#c084fc'} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
            style={{ position: 'relative', zIndex: 1 }}>
            <path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.44-3.14Z"/>
            <path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.44-3.14Z"/>
          </svg>
        </NavLink>
      )}
    </div>
  )
}
