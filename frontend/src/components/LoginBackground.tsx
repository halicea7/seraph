import type React from 'react'
import { useEffect, useRef } from 'react'

const CHARS = ' .,-~:;=!*#'
const CW = 8
const CH = 14
const SPEED = 1
const FREQ = 0.3
const THR = 0.15
const ORB = 0.3

interface Props {
  style?: React.CSSProperties
}

export default function LoginBackground({ style }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')!

    function readAccent(): [number, number, number] {
      const raw = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()
      const m = raw.match(/^#?([0-9a-f]{6})$/i)
      if (m) return [parseInt(m[1].slice(0, 2), 16), parseInt(m[1].slice(2, 4), 16), parseInt(m[1].slice(4, 6), 16)]
      return [240, 168, 58]
    }
    function readBg(): string {
      const raw = getComputedStyle(document.documentElement).getPropertyValue('--bg').trim()
      const m = raw.match(/^#?([0-9a-f]{6})$/i)
      if (m) return `#${m[1]}`
      return '#0d0c0a'
    }

    let accentRGB = readAccent()
    let bgColor = readBg()
    let t = 0
    let animId: number
    let COLS = 0
    let ROWS = 0

    function resize() {
      const dpr = window.devicePixelRatio || 1
      canvas!.width = canvas!.offsetWidth * dpr
      canvas!.height = canvas!.offsetHeight * dpr
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      COLS = Math.floor(canvas!.offsetWidth / CW)
      ROWS = Math.floor(canvas!.offsetHeight / CH)
      ctx.font = CW + 'px ui-monospace, IBM Plex Mono, monospace'
      ctx.textBaseline = 'top'
      accentRGB = readAccent()
      bgColor = readBg()
    }

    function draw() {
      t += 0.016 * SPEED

      ctx.fillStyle = bgColor
      ctx.fillRect(0, 0, canvas!.offsetWidth, canvas!.offsetHeight)

      const cols = COLS
      const rows = ROWS

      const nx = cols * 0.5 + Math.cos(t * 0.30) * cols * ORB
      const ny = rows * 0.5 + Math.sin(t * 0.40) * rows * ORB
      const ix = cols * 0.5 + Math.cos(t * 0.37 + 2) * cols * (ORB * 0.83)
      const iy = rows * 0.5 + Math.sin(t * 0.29 + 2) * rows * (ORB * 1.17)
      const sx = cols * 0.5 + Math.sin(t * 0.23 + 4) * cols * (ORB * 1.17)
      const sy = rows * 0.5 + Math.cos(t * 0.31 + 4) * rows * (ORB * 0.83)

      const f1 = FREQ
      const f2 = FREQ * 1.033
      const f3 = FREQ * 0.967

      const [ar, ag, ab] = accentRGB

      for (let row = 0; row < rows; row++) {
        for (let col = 0; col < cols; col++) {
          const fx = col * 0.55
          const pb = fx - nx * 0.55, hb = row - ny
          const gb = fx - ix * 0.55, ib = row - iy
          const vb = fx - sx * 0.55, yb = row - sy

          const d1 = Math.sqrt(pb * pb + hb * hb)
          const d2 = Math.sqrt(gb * gb + ib * ib)
          const d3 = Math.sqrt(vb * vb + yb * yb)

          let C = Math.sin(d1 * f1 + t)
                + Math.sin(d2 * f2 - t * 0.7)
                + Math.sin(d3 * f3 + t * 0.5)
          C = (C + 3) / 6

          if (C < THR || C > (1 - THR)) continue

          let w = Math.abs(C - 0.5) * 2
          w = 1 - w

          const charIdx = Math.min(CHARS.length - 1, (w * CHARS.length) | 0)
          const ch = CHARS[charIdx]
          if (ch === ' ') continue

          const r = Math.round(ar * (0.20 + w * 0.80))
          const g = Math.round(ag * (0.20 + w * 0.80))
          const b = Math.round(ab * (0.20 + w * 0.80))
          ctx.fillStyle = `rgba(${r},${g},${b},${0.28 + w * 0.62})`
          ctx.fillText(ch, col * CW, row * CH)
        }
      }

      animId = requestAnimationFrame(draw)
    }

    const ro = new ResizeObserver(resize)
    ro.observe(canvas)
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
      style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', display: 'block', ...style }}
    />
  )
}
