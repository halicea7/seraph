import { useEffect, useRef } from 'react'

const CHARS = ' .,-~:;=!*#'
const CW = 8
const CH = 14
const SPEED = 1
const FREQ = 0.3
const THR = 0.15
const ORB = 0.3

export default function LoginBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const cv = canvas
    const ctx = cv.getContext('2d')!

    let t = 0
    let animId: number
    let COLS = 0
    let ROWS = 0

    function resize() {
      cv.width = cv.offsetWidth
      cv.height = cv.offsetHeight
      COLS = Math.floor(cv.width / CW)
      ROWS = Math.floor(cv.height / CH)
      ctx.font = CW + 'px monospace'
      ctx.textBaseline = 'top'
    }

    function draw() {
      t += 0.016 * SPEED

      ctx.fillStyle = '#0a0a0f'
      ctx.fillRect(0, 0, cv.width, cv.height)

      const cols = COLS
      const rows = ROWS

      // Three orbiting wave centers
      const nx = cols * 0.5 + Math.cos(t * 0.3) * cols * ORB
      const ny = rows * 0.5 + Math.sin(t * 0.4) * rows * ORB
      const ix = cols * 0.5 + Math.cos(t * 0.37 + 2) * cols * (ORB * 0.83)
      const iy = rows * 0.5 + Math.sin(t * 0.29 + 2) * rows * (ORB * 1.17)
      const sx = cols * 0.5 + Math.sin(t * 0.23 + 4) * cols * (ORB * 1.17)
      const sy = rows * 0.5 + Math.cos(t * 0.31 + 4) * rows * (ORB * 0.83)

      // Slightly detuned frequencies — the mismatch creates the interference bands
      const f1 = FREQ
      const f2 = FREQ * 1.033
      const f3 = FREQ * 0.967

      for (let row = 0; row < rows; row++) {
        for (let col = 0; col < cols; col++) {
          // 0.55 aspect correction
          const fx = col * 0.55

          const pb = fx - nx * 0.55, hb = row - ny
          const gb = fx - ix * 0.55, ib = row - iy
          const vb = fx - sx * 0.55, yb = row - sy

          const dist1 = Math.sqrt(pb * pb + hb * hb)
          const dist2 = Math.sqrt(gb * gb + ib * ib)
          const dist3 = Math.sqrt(vb * vb + yb * yb)

          let C = Math.sin(dist1 * f1 + t)
                + Math.sin(dist2 * f2 - t * 0.7)
                + Math.sin(dist3 * f3 + t * 0.5)

          C = (C + 3) / 6 // normalise 0..1

          // Hard threshold — only render the interference bands
          if (C < THR || C > (1 - THR)) continue

          // Brightness peaks at C = 0.5
          let w = Math.abs(C - 0.5) * 2
          w = 1 - w

          const charIdx = Math.min(CHARS.length - 1, (w * CHARS.length) | 0)
          const ch = CHARS[charIdx]
          if (ch === ' ') continue

          // Cyan palette: rgb(0-10, 80-220, 100-255) — teal at dim, bright cyan at peak
          const r = (w * 10) | 0
          const g = (80 + w * 140) | 0
          const b = (100 + w * 155) | 0
          ctx.fillStyle = `rgba(${r},${g},${b},${0.3 + w * 0.7})`
          ctx.fillText(ch, col * CW, row * CH)
        }
      }

      animId = requestAnimationFrame(draw)
    }

    const ro = new ResizeObserver(resize)
    ro.observe(cv)
    resize()
    draw()

    return () => {
      cancelAnimationFrame(animId)
      ro.disconnect()
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', display: 'block' }}
    />
  )
}
