import { createContext, useContext, useRef, useState, useCallback } from 'react'

// ── Timing helpers ────────────────────────────────────────────────────────────

const AI_TIME_KEY = (model: string) => `seraph_ai_time_${model}`

function getStoredDuration(model: string): number | null {
  const v = localStorage.getItem(AI_TIME_KEY(model))
  return v ? Number(v) : null
}

function storeDuration(model: string, ms: number) {
  localStorage.setItem(AI_TIME_KEY(model), String(ms))
}

// ── Context types ─────────────────────────────────────────────────────────────

export interface NarrativeResult {
  narrative: string
  savedAt: string
}

interface AINarrativeContextType {
  generating: boolean
  /** null = idle, -1 = indeterminate, 0–100 = percent */
  progress: number | null
  /** true after generation finishes, until the user dismisses the orb */
  done: boolean
  dismissDone: () => void
  generate: (projectId: string, style: string) => Promise<NarrativeResult | null>
}

const AINarrativeContext = createContext<AINarrativeContextType>({
  generating: false,
  progress: null,
  done: false,
  dismissDone: () => {},
  generate: async () => null,
})

export function useAINarrative() {
  return useContext(AINarrativeContext)
}

// ── Provider ──────────────────────────────────────────────────────────────────

export function AINarrativeProvider({ children }: { children: React.ReactNode }) {
  const [generating, setGenerating] = useState(false)
  const [progress, setProgress] = useState<number | null>(null)
  const [done, setDone] = useState(false)

  const startMs = useRef<number>(0)
  const timer = useRef<ReturnType<typeof setInterval> | null>(null)

  const stopTimer = useCallback(() => {
    if (timer.current) { clearInterval(timer.current); timer.current = null }
  }, [])

  const dismissDone = useCallback(() => setDone(false), [])

  const generate = useCallback(async (projectId: string, style: string): Promise<NarrativeResult | null> => {
    // Fetch current model for timing key
    let model = ''
    try {
      const cfg = await fetch('/api/v1/ai/config').then(r => r.json())
      model = cfg.model || ''
    } catch { /* ignore */ }

    setDone(false)
    setGenerating(true)
    startMs.current = Date.now()
    const stored = model ? getStoredDuration(model) : null

    if (!stored) {
      setProgress(-1)
    } else {
      setProgress(0)
      stopTimer()
      timer.current = setInterval(() => {
        const elapsed = Date.now() - startMs.current
        setProgress(Math.min(95, (elapsed / stored) * 100))
      }, 150)
    }

    try {
      const res = await fetch('/api/v1/ai/narrate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_id: projectId, style }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Narrative generation failed')

      const elapsed = Date.now() - startMs.current
      if (model) storeDuration(model, elapsed)

      stopTimer()
      setProgress(null)
      setGenerating(false)
      setDone(true)

      return { narrative: data.narrative || '', savedAt: new Date().toISOString() }
    } catch (err) {
      stopTimer()
      setProgress(null)
      setGenerating(false)
      throw err
    }
  }, [stopTimer])

  return (
    <AINarrativeContext.Provider value={{ generating, progress, done, dismissDone, generate }}>
      {children}
    </AINarrativeContext.Provider>
  )
}
