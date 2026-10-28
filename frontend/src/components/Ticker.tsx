import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAppStore } from '@/stores/appStore'
import Icon from './Icon'
import { useCountUp } from '@/lib/useCountUp'
import { SEV_COLOR, normSev } from '@/lib/severity'
import { useLiveTelemetry, type ThreatLevel, type TickerEvent } from '@/lib/useLiveTelemetry'

// ── Threat-level chip metadata ──────────────────────────────────────────────────

const THREAT: Record<ThreatLevel, { label: string; dot: string; bg: string; fg: string }> = {
  nominal:  { label: 'NOMINAL',  dot: 'dot-live', bg: 'rgba(107,138,114,0.16)', fg: 'var(--ok)' },
  elevated: { label: 'ELEVATED', dot: 'dot-warn', bg: 'rgba(240,168,58,0.16)',  fg: 'var(--accent)' },
  critical: { label: 'CRITICAL', dot: 'dot-crit', bg: 'rgba(232,92,78,0.20)',   fg: 'var(--crit)' },
}

function usePrefersReducedMotion(): boolean {
  const [reduce, setReduce] = useState(
    () => typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches,
  )
  useEffect(() => {
    const mq = window.matchMedia?.('(prefers-reduced-motion: reduce)')
    if (!mq) return
    const handler = () => setReduce(mq.matches)
    mq.addEventListener?.('change', handler)
    return () => mq.removeEventListener?.('change', handler)
  }, [])
  return !!reduce
}

// ── Glanceable counter ──────────────────────────────────────────────────────────

function Stat({ icon, value, color, title, onClick, spin, glow }: {
  icon: string
  value: number
  color: string
  title: string
  onClick: () => void
  spin?: boolean
  glow?: boolean
}) {
  const display = useCountUp(value)
  return (
    <button
      onClick={onClick}
      title={title}
      className="mono tnum"
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 5, background: 'transparent',
        border: 'none', cursor: 'pointer', padding: '0 2px', height: '100%',
        fontSize: 10.5, letterSpacing: '0.04em', color,
        textShadow: glow ? `0 0 8px ${color}` : undefined,
      }}
    >
      <Icon name={icon} size={11} color={color} style={spin ? { animation: 'spin 1.4s linear infinite' } : undefined} />
      <span>{display}</span>
    </button>
  )
}

// ── Marquee event item ──────────────────────────────────────────────────────────

function EventItem({ ev, onClick }: { ev: TickerEvent; onClick: () => void }) {
  const color = ev.kind === 'finding' ? SEV_COLOR[normSev(ev.severity)] : 'var(--fg-3)'
  return (
    <button
      onClick={onClick}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 8, background: 'transparent',
        border: 'none', cursor: 'pointer', padding: 0, whiteSpace: 'nowrap',
        fontFamily: 'var(--font-mono)', fontSize: 10.5, letterSpacing: '0.06em', color: 'var(--fg-2)',
      }}
    >
      <span style={{ color, fontWeight: 600 }}>
        {ev.kind === 'finding' ? normSev(ev.severity).slice(0, 4).toUpperCase() : 'SCAN'}
      </span>
      <span style={{ color: 'var(--fg-2)' }}>{ev.label}</span>
      {ev.detail && <span style={{ color: 'var(--fg-4)' }}>· {ev.detail}</span>}
    </button>
  )
}

// ── Ticker ────────────────────────────────────────────────────────────────────

export default function Ticker({ backendOnline }: { backendOnline: boolean | null }) {
  const navigate = useNavigate()
  const { selectedProject } = useAppStore()
  const engagement = selectedProject?.name ?? null
  const tel = useLiveTelemetry()
  const reduce = usePrefersReducedMotion()

  const [time, setTime] = useState(() => new Date().toLocaleTimeString('en-GB'))
  useEffect(() => {
    const id = setInterval(() => setTime(new Date().toLocaleTimeString('en-GB')), 1000)
    return () => clearInterval(id)
  }, [])

  // Bar glow flash on a new critical/high pulse.
  const [flash, setFlash] = useState<'crit' | 'high' | null>(null)
  useEffect(() => {
    if (!tel.pulse) return
    setFlash(tel.pulse.level)
    // Reduced motion shows a static colored border; give it a longer dwell.
    const t = setTimeout(() => setFlash(null), reduce ? 6000 : 2800)
    return () => clearTimeout(t)
  }, [tel.pulse?.ts, reduce])

  // Reduced-motion: rotate the latest events in place instead of scrolling.
  const [rotIdx, setRotIdx] = useState(0)
  useEffect(() => {
    if (!reduce || tel.events.length === 0) return
    const id = setInterval(() => setRotIdx(i => (i + 1) % tel.events.length), 4000)
    return () => clearInterval(id)
  }, [reduce, tel.events.length])

  const offline = backendOnline === false || tel.online === false
  const meta = offline
    ? { label: 'OFFLINE', dot: 'dot-idle', bg: 'rgba(122,116,104,0.14)', fg: 'var(--fg-3)' }
    : THREAT[tel.threat]

  const doubled = tel.events.length > 0 ? [...tel.events, ...tel.events] : []

  return (
    <div
      className={`ticker-bar${flash ? ` alert-${flash}` : ''}`}
      style={{
        height: 28, borderBottom: '1px solid var(--rule)', background: 'var(--bg-2)',
        overflow: 'hidden', display: 'flex', alignItems: 'center', flexShrink: 0,
      }}
    >
      {/* Threat chip */}
      <div style={{
        flexShrink: 0, padding: '0 12px', height: '100%', display: 'flex', alignItems: 'center', gap: 7,
        borderRight: '1px solid var(--rule)', background: meta.bg,
      }}>
        <span className={`dot ${meta.dot}`} />
        <span className="mono" style={{ fontSize: 9, fontWeight: 700, letterSpacing: '0.16em', color: meta.fg }}>
          {meta.label}
        </span>
      </div>

      {/* Stat cluster */}
      <div style={{
        flexShrink: 0, display: 'flex', alignItems: 'center', gap: 12, padding: '0 14px', height: '100%',
        borderRight: '1px solid var(--rule)',
      }}>
        <Stat icon="target" value={tel.activeScans} color={tel.activeScans > 0 ? 'var(--accent)' : 'var(--fg-3)'}
          title="Active scans" spin={tel.activeScans > 0} onClick={() => navigate('/scans')} />
        {selectedProject && (
          <Stat icon="terminal" value={tel.sessions} color={tel.sessions > 0 ? 'var(--ok)' : 'var(--fg-3)'}
            title="Active C2 sessions" onClick={() => navigate('/c2')} />
        )}
        {selectedProject && (
          <Stat icon="cpu" value={tel.agents} color={tel.agents > 0 ? 'var(--ok)' : 'var(--fg-3)'}
            title="Online agents" onClick={() => navigate('/agents')} />
        )}
        <span style={{ width: 1, height: 12, background: 'var(--rule-strong)' }} />
        <Stat icon="flag" value={tel.sev.critical} color={SEV_COLOR.critical}
          title="Critical findings" glow={tel.sev.critical > 0} onClick={() => navigate('/findings')} />
        <Stat icon="bolt" value={tel.sev.high} color={SEV_COLOR.high}
          title="High findings" onClick={() => navigate('/findings')} />
      </div>

      {/* Event marquee (or static rotation under reduced motion) */}
      <div style={{ overflow: 'hidden', flex: 1, minWidth: 0, height: '100%', display: 'flex', alignItems: 'center' }}>
        {tel.events.length === 0 ? (
          <span className="mono" style={{ fontSize: 10.5, color: 'var(--fg-4)', padding: '0 16px', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
            {offline ? 'Awaiting backend…' : 'All quiet · no recent events'}
          </span>
        ) : reduce ? (
          <div style={{ padding: '0 16px' }}>
            <EventItem ev={tel.events[rotIdx % tel.events.length]} onClick={() => navigate(tel.events[rotIdx % tel.events.length].to)} />
          </div>
        ) : (
          <div className="ticker-track" style={{ animationDuration: '90s', paddingLeft: 16 }}>
            {doubled.map((ev, i) => (
              <span key={`${ev.id}-${i}`} style={{ display: 'inline-flex', alignItems: 'center', gap: 16 }}>
                <span style={{ color: 'var(--fg-4)' }}>◆</span>
                <EventItem ev={ev} onClick={() => navigate(ev.to)} />
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Engagement + clock */}
      <div style={{ flexShrink: 0, padding: '0 14px', borderLeft: '1px solid var(--rule)', display: 'flex', alignItems: 'center', gap: 12 }}>
        {engagement && (
          <span className="mono" style={{ fontSize: 10, color: 'var(--fg-2)', display: 'flex', alignItems: 'center', gap: 6, maxWidth: 200, overflow: 'hidden' }}>
            <span style={{ color: 'var(--fg-4)', textTransform: 'uppercase', letterSpacing: '0.12em', fontSize: 9 }}>Eng</span>
            <span style={{ color: 'var(--accent)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{engagement}</span>
          </span>
        )}
        <span className="mono tnum" style={{ fontSize: 10, color: 'var(--fg-3)' }}>{time}</span>
      </div>
    </div>
  )
}
