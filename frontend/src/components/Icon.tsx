interface IconProps {
  name: string
  size?: number
  color?: string
  className?: string
  style?: React.CSSProperties
}

const PATHS: Record<string, string> = {
  shield:      'M12 2 L4 5 v6 c0 5 3.5 9 8 11 4.5-2 8-6 8-11 V5 z',
  terminal:    'M4 6 L8 10 L4 14 M10 14 L16 14',
  swords:      'M14 3 L21 10 L17 14 L10 7 M3 21 L7 17 M5 19 L8 22 M8 16 L14 22',
  lock:        'M6 10 V7 a6 6 0 0 1 12 0 V10 M5 10 H19 V20 H5 Z',
  key:         'M14 8 a4 4 0 1 1 -4 4 L4 18 L4 22 L8 22 L8 19 L11 19 L11 16',
  search:      'M11 11 m-6 0 a6 6 0 1 0 12 0 a6 6 0 1 0 -12 0 M16 16 L21 21',
  network:     'M4 6 H10 V12 H4 Z M14 14 H20 V20 H14 Z M14 6 H20 V12 H14 Z M4 14 H10 V20 H4 Z M10 9 H14 M17 12 V14 M7 12 V14 M10 17 H14',
  book:        'M4 4 H11 V20 H4 Z M13 4 H20 V20 H13 Z',
  file:        'M5 3 H14 L19 8 V21 H5 Z M14 3 V8 H19',
  cog:         'M12 8 a4 4 0 1 1 0 8 a4 4 0 1 1 0 -8 M12 2 V5 M12 19 V22 M2 12 H5 M19 12 H22 M5 5 L7 7 M17 17 L19 19 M5 19 L7 17 M17 7 L19 5',
  help:        'M12 22 a10 10 0 1 1 0 -20 a10 10 0 1 1 0 20 M9 10 a3 3 0 1 1 4.5 2.6 c-1 0.5 -1.5 1.4 -1.5 2.4 M12 18 v0.1',
  grid:        'M3 3 H10 V10 H3 Z M14 3 H21 V10 H14 Z M3 14 H10 V21 H3 Z M14 14 H21 V21 H14 Z',
  chev_r:      'M9 5 L15 12 L9 19',
  chev_d:      'M5 9 L12 15 L19 9',
  chev_l:      'M15 5 L9 12 L15 19',
  chev_u:      'M5 15 L12 9 L19 15',
  plus:        'M5 12 H19 M12 5 V19',
  minus:       'M5 12 H19',
  x:           'M5 5 L19 19 M5 19 L19 5',
  check:       'M5 12 L10 17 L19 7',
  bolt:        'M13 2 L4 14 H11 L10 22 L20 9 H13 Z',
  skull:       'M12 2 a8 8 0 0 1 8 8 v5 l-2 2 v3 H6 v-3 l-2 -2 V10 a8 8 0 0 1 8 -8 M9 11 v2 M15 11 v2 M10 18 H14',
  radio:       'M5 8 a10 10 0 0 1 14 0 M8 11 a6 6 0 0 1 8 0 M12 14 v0.1 M2 5 a14 14 0 0 1 20 0',
  eye:         'M2 12 s4 -8 10 -8 s10 8 10 8 s -4 8 -10 8 s -10 -8 -10 -8 M12 9 a3 3 0 1 1 0 6 a3 3 0 1 1 0 -6',
  eye_off:     'M2 2 L22 22 M6 6 c-2 2 -4 6 -4 6 s4 8 10 8 c2 0 4 -1 5 -1 M9 4 a10 10 0 0 1 3 -0.5 c6 0 10 8 10 8 s -1 2 -3 4',
  download:    'M12 4 V16 M6 12 L12 18 L18 12 M4 20 H20',
  upload:      'M12 4 L6 10 M12 4 L18 10 M12 4 V16 M4 20 H20',
  refresh:     'M3 12 a9 9 0 0 1 16 -5 V3 M19 12 a9 9 0 0 1 -16 5 V21 M16 3 H19 V6 M5 18 H8 V21',
  pause:       'M7 5 V19 M17 5 V19',
  play:        'M6 4 L20 12 L6 20 Z',
  stop:        'M5 5 H19 V19 H5 Z',
  arrow_r:     'M5 12 H19 M13 6 L19 12 L13 18',
  arrow_l:     'M19 12 H5 M11 18 L5 12 L11 6',
  flag:        'M5 3 V21 M5 4 L18 4 L15 9 L18 14 H5',
  clock:       'M12 4 a8 8 0 1 1 0 16 a8 8 0 1 1 0 -16 M12 8 V12 L15 14',
  activity:    'M3 12 H7 L10 4 L14 20 L17 12 H21',
  cpu:         'M5 5 H19 V19 H5 Z M9 9 H15 V15 H9 Z M3 9 H5 M3 15 H5 M19 9 H21 M19 15 H21 M9 3 V5 M15 3 V5 M9 19 V21 M15 19 V21',
  layers:      'M12 3 L3 8 L12 13 L21 8 Z M3 13 L12 18 L21 13 M3 18 L12 23 L21 18',
  sun:         'M12 5 V2 M12 22 V19 M5 12 H2 M22 12 H19 M5 5 L7 7 M17 17 L19 19 M5 19 L7 17 M17 7 L19 5 M12 8 a4 4 0 1 1 0 8 a4 4 0 1 1 0 -8',
  bell:        'M5 18 H19 L17 16 V11 a5 5 0 1 0 -10 0 V16 Z M10 21 a2 2 0 0 0 4 0',
  logout:      'M14 4 H20 V20 H14 M16 12 H4 M8 8 L4 12 L8 16',
  user:        'M12 4 a4 4 0 1 1 0 8 a4 4 0 1 1 0 -8 M4 22 a8 8 0 0 1 16 0',
  folder:      'M3 6 a2 2 0 0 1 2 -2 H10 L12 6 H19 a2 2 0 0 1 2 2 V18 a2 2 0 0 1 -2 2 H5 a2 2 0 0 1 -2 -2 Z',
  cube:        'M12 3 L3 8 V16 L12 21 L21 16 V8 Z M3 8 L12 13 L21 8 M12 13 V21',
  history:     'M3 12 a9 9 0 1 1 18 0 a9 9 0 1 1 -18 0 M3 12 H6 M12 7 V12 L16 14 M3 3 L5 5',
  target:      'M12 2 a10 10 0 1 1 0 20 a10 10 0 1 1 0 -20 M12 7 a5 5 0 1 1 0 10 a5 5 0 1 1 0 -10 M11 12 H13',
  fingerprint: 'M12 4 c-4 0 -8 3 -8 8 v3 M16 20 c-2 0 -4 -1 -4 -4 V8 c0 -2 -2 -4 -4 -4 M8 14 v4 M20 14 a8 8 0 0 0 -8 -8 M12 10 v6',
  wifi:        'M12 20 v0.1 M2 8.8 a14 14 0 0 1 20 0 M5 12.4 a10 10 0 0 1 14 0 M8.5 15.9 a6 6 0 0 1 7 0',
  copy:        'M8 4 H5 a1 1 0 0 0 -1 1 V19 a1 1 0 0 0 1 1 H14 a1 1 0 0 0 1 -1 V16 M8 4 a1 1 0 0 1 1 -1 H19 a1 1 0 0 1 1 1 V15 a1 1 0 0 1 -1 1 H9 a1 1 0 0 1 -1 -1 Z',
  trash:       'M3 6 H21 M8 6 V4 H16 V6 M19 6 L18 20 H6 L5 6',
  edit:        'M11 4 H4 a2 2 0 0 0 -2 2 V18 a2 2 0 0 0 2 2 H16 a2 2 0 0 0 2 -2 V11 M18 2 a2.8 2.8 0 1 1 4 4 L12 16 L8 17 L9 13 Z',
  link:        'M10 13 a5 5 0 0 0 7.5 0.6 L19 12 a5 5 0 0 0 -7 -7 L10.5 6.5 M14 11 a5 5 0 0 0 -7.5 -0.6 L5 12 a5 5 0 0 0 7 7 L13.5 17.5',
  more:        'M12 5 v0.1 M12 12 v0.1 M12 19 v0.1',
  filter:      'M22 3 H2 L10 12.5 V19 L14 21 V12.5 Z',
  send:        'M22 2 L11 13 M22 2 L15 22 L11 13 L2 9 Z',
  zap:         'M13 2 L4 14 H11 L10 22 L20 9 H13 Z',
}

export default function Icon({ name, size = 14, color = 'currentColor', className, style }: IconProps) {
  const d = PATHS[name]
  if (!d) {
    return (
      <span
        style={{ width: size, height: size, display: 'inline-block', background: 'var(--rule-strong)', flexShrink: 0, ...style }}
        className={className}
      />
    )
  }
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      style={{ display: 'block', flexShrink: 0, ...style }}
    >
      <path d={d} />
    </svg>
  )
}
