interface Props {
  values: number[]
  color: string
  width?: number
  height?: number
}

export default function SparkLine({ values, color, width = 120, height = 36 }: Props) {
  if (values.length < 2) return null

  const max = Math.max(...values, 1)
  const pad = 2
  const w = width - pad * 2
  const h = height - pad * 2

  const points = values.map((v, i) => {
    const x = pad + (i / (values.length - 1)) * w
    const y = pad + h - (v / max) * h
    return `${x},${y}`
  })

  const last = points[points.length - 1].split(',')

  return (
    <svg width={width} height={height} style={{ overflow: 'visible' }}>
      <polyline
        points={points.join(' ')}
        fill="none"
        stroke={color}
        strokeWidth={1.5}
        strokeLinejoin="round"
        strokeLinecap="round"
        opacity={0.8}
      />
      <circle cx={last[0]} cy={last[1]} r={2.5} fill={color} opacity={0.9} />
    </svg>
  )
}
