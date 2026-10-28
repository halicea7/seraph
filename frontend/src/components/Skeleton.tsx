import type React from 'react'

// ══════════════════════════════════════════════════════════════════════════════
// Loading skeletons built on the existing `.shimmer` keyframe (index.css).
// Use instead of flashing empty→populated when a list/table is loading.
// ══════════════════════════════════════════════════════════════════════════════

export function Skeleton({ width = '100%', height = 12, style }: {
  width?: number | string
  height?: number | string
  style?: React.CSSProperties
}) {
  return (
    <div
      className="shimmer"
      style={{ width, height, background: 'var(--bg-3)', borderRadius: 0, ...style }}
    />
  )
}

/** Placeholder rows for a data table. Renders `rows` × `cols` shimmer cells. */
export function SkeletonRows({ rows = 6, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, r) => (
        <div
          key={r}
          style={{
            display: 'grid', gridTemplateColumns: `repeat(${cols}, 1fr)`, gap: 16,
            padding: '10px 12px', borderBottom: '1px solid var(--rule)',
          }}
        >
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton key={c} height={11} width={c === 0 ? '60%' : '85%'} />
          ))}
        </div>
      ))}
    </>
  )
}

/** Stacked text lines, e.g. for a card body. */
export function SkeletonText({ lines = 3 }: { lines?: number }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} height={11} width={i === lines - 1 ? '55%' : '100%'} />
      ))}
    </div>
  )
}

export default Skeleton
