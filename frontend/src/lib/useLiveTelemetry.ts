import { useEffect, useRef, useState } from 'react'
import { getApiBase } from '@/lib/config'
import { useAppStore } from '@/stores/appStore'
import { useLiveEvents } from '@/contexts/LiveEventsContext'

// ══════════════════════════════════════════════════════════════════════════════
// Data layer for the live ops Ticker. Polls /stats (+ project-scoped C2 sessions
// and agents), nudged to refetch instantly on WebSocket events. Detects new
// critical/high findings by diffing severity counts between polls.
// ══════════════════════════════════════════════════════════════════════════════

export type ThreatLevel = 'nominal' | 'elevated' | 'critical'

export interface TickerEvent {
  id: string
  kind: 'finding' | 'scan'
  severity?: string
  label: string
  detail?: string
  to: string
}

export interface AlertPulse { level: 'crit' | 'high'; text: string; ts: number }

interface Sev { critical: number; high: number; medium: number; low: number }

export interface Telemetry {
  online: boolean | null
  threat: ThreatLevel
  sev: Sev
  activeScans: number
  sessions: number
  agents: number
  events: TickerEvent[]
  pulse: AlertPulse | null
}

const EMPTY: Telemetry = {
  online: null, threat: 'nominal',
  sev: { critical: 0, high: 0, medium: 0, low: 0 },
  activeScans: 0, sessions: 0, agents: 0, events: [], pulse: null,
}

export function useLiveTelemetry(): Telemetry {
  const { selectedProject } = useAppStore()
  const projectId = selectedProject?.id ?? null
  const { subscribe } = useLiveEvents()

  const [tel, setTel] = useState<Telemetry>(EMPTY)
  const prevSev = useRef<Sev | null>(null)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  useEffect(() => {
    let cancelled = false

    async function fetchStats() {
      try {
        const r = await fetch(`${getApiBase()}/stats`, { cache: 'no-store' })
        if (!r.ok) { if (!cancelled) setTel(t => ({ ...t, online: false })); return }
        const d = await r.json()
        if (cancelled) return

        const sc = d.severity_counts || {}
        const sev: Sev = {
          critical: sc.critical || 0, high: sc.high || 0,
          medium: sc.medium || 0, low: sc.low || 0,
        }
        const recentScans: any[] = d.recent_scans || []
        const recentFindings: any[] = d.recent_findings || []
        const activeScans = recentScans.filter(s => s.status === 'running').length

        const fEvents: TickerEvent[] = recentFindings.map((f: any) => ({
          id: `f-${f.id}`, kind: 'finding', severity: f.severity,
          label: f.title, detail: f.target, to: '/findings',
        }))
        const sEvents: TickerEvent[] = recentScans
          .filter(s => s.status === 'completed')
          .map((s: any) => ({
            id: `s-${s.id}`, kind: 'scan',
            label: `${s.scan_type} scan`, detail: s.target, to: `/scans?open=${s.id}`,
          }))
        const events = [...fEvents, ...sEvents].slice(0, 12)

        // New critical/high since last poll → pulse (skip on first load).
        let pulse: AlertPulse | null = null
        const prev = prevSev.current
        if (prev) {
          if (sev.critical > prev.critical) pulse = { level: 'crit', text: recentFindings[0]?.title || 'New critical finding', ts: Date.now() }
          else if (sev.high > prev.high)    pulse = { level: 'high', text: recentFindings[0]?.title || 'New high finding', ts: Date.now() }
        }
        prevSev.current = sev

        const threat: ThreatLevel = sev.critical > 0 ? 'critical' : sev.high > 0 ? 'elevated' : 'nominal'
        setTel(t => ({ ...t, online: true, threat, sev, activeScans, events, pulse: pulse ?? t.pulse }))
      } catch {
        if (!cancelled) setTel(t => ({ ...t, online: false }))
      }
    }

    async function fetchProjectScoped(pid: string) {
      try {
        const [sRes, aRes] = await Promise.all([
          fetch(`${getApiBase()}/c2/sessions?project_id=${pid}`, { cache: 'no-store' }),
          fetch(`${getApiBase()}/agents?project_id=${pid}`, { cache: 'no-store' }),
        ])
        if (cancelled) return
        const sessionsArr = sRes.ok ? await sRes.json() : []
        const agentsArr = aRes.ok ? await aRes.json() : []
        const sessions = Array.isArray(sessionsArr) ? sessionsArr.filter((s: any) => s.status === 'active' && s.live).length : 0
        const agents = Array.isArray(agentsArr) ? agentsArr.filter((a: any) => a.status === 'online').length : 0
        if (!cancelled) setTel(t => ({ ...t, sessions, agents }))
      } catch { /* ignore */ }
    }

    function refresh() {
      fetchStats()
      if (projectId) fetchProjectScoped(projectId)
      else setTel(t => ({ ...t, sessions: 0, agents: 0 }))
    }

    refresh()
    const id = setInterval(refresh, 10000)

    const unsub = subscribe((msg) => {
      if (debounceRef.current) clearTimeout(debounceRef.current)
      debounceRef.current = setTimeout(() => {
        refresh()
        if (msg.type === 'finding_created') {
          setTel(t => ({ ...t, pulse: { level: 'crit', text: 'New finding reported', ts: Date.now() } }))
        }
      }, 400)
    })

    return () => {
      cancelled = true
      clearInterval(id)
      unsub()
      if (debounceRef.current) clearTimeout(debounceRef.current)
    }
  }, [projectId, subscribe])

  return tel
}
