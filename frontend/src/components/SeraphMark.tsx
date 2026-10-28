import type { CSSProperties } from 'react'
import seraphMark from '@/assets/seraph-mark.svg'

// The Seraph emblem (monochrome SVG) rendered as a CSS mask so it takes on any
// theme colour and stays crisp on dark backgrounds.
export function SeraphMark({
  size = 22,
  color = 'var(--accent)',
  style,
}: {
  size?: number
  color?: string
  style?: CSSProperties
}) {
  return (
    <div
      role="img"
      aria-label="Seraph"
      style={{
        width: size,
        height: size,
        flexShrink: 0,
        backgroundColor: color,
        WebkitMaskImage: `url(${seraphMark})`,
        maskImage: `url(${seraphMark})`,
        WebkitMaskRepeat: 'no-repeat',
        maskRepeat: 'no-repeat',
        WebkitMaskPosition: 'center',
        maskPosition: 'center',
        WebkitMaskSize: 'contain',
        maskSize: 'contain',
        ...style,
      }}
    />
  )
}
