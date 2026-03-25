import { useEffect, useRef, forwardRef, useImperativeHandle } from 'react'
import { Terminal as XTerm } from 'xterm'
import { FitAddon } from 'xterm-addon-fit'
import 'xterm/css/xterm.css'
import { useTheme } from '../contexts/ThemeContext'

function getXtermTheme(mono: boolean) {
  return {
    background:       mono ? '#050505' : '#05080d',
    foreground:       '#e2e8f0',
    cursor:           mono ? '#d4d4d8' : '#06b6d4',
    cursorAccent:     mono ? '#050505' : '#05080d',
    selectionBackground: mono ? 'rgba(255,255,255,0.15)' : '#06b6d440',
    black:            mono ? '#050505' : '#05080d',
    brightBlack:      mono ? '#2a2a2a' : '#1a2540',
    red:              '#ef4444',
    brightRed:        '#f87171',
    green:            '#22c55e',
    brightGreen:      '#4ade80',
    yellow:           '#f59e0b',
    brightYellow:     '#fbbf24',
    blue:             mono ? '#a1a1aa' : '#3b82f6',
    brightBlue:       mono ? '#d4d4d8' : '#60a5fa',
    magenta:          '#a855f7',
    brightMagenta:    '#c084fc',
    cyan:             mono ? '#d4d4d8' : '#06b6d4',
    brightCyan:       mono ? '#f4f4f5' : '#22d3ee',
    white:            '#e2e8f0',
    brightWhite:      '#f8fafc',
  }
}

export interface TerminalHandle {
  write: (data: string) => void
  writeln: (data: string) => void
  clear: () => void
  connect: (scanId: string, script: string) => void
  disconnect: () => void
}

interface TerminalProps {
  className?: string
}

const Terminal = forwardRef<TerminalHandle, TerminalProps>(({ className }, ref) => {
  const containerRef = useRef<HTMLDivElement>(null)
  const xtermRef = useRef<XTerm | null>(null)
  const fitAddonRef = useRef<FitAddon | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const { theme } = useTheme()

  // Update xterm color theme when app theme changes
  useEffect(() => {
    if (xtermRef.current) {
      xtermRef.current.options.theme = getXtermTheme(theme === 'mono')
    }
  }, [theme])

  useEffect(() => {
    if (!containerRef.current) return

    const term = new XTerm({
      theme: getXtermTheme(theme === 'mono'),
      fontFamily: '"JetBrains Mono", "Fira Code", monospace',
      fontSize: 13,
      lineHeight: 1.4,
      cursorBlink: true,
      scrollback: 5000,
      convertEol: true,
    })

    const fitAddon = new FitAddon()
    term.loadAddon(fitAddon)
    term.open(containerRef.current)
    fitAddon.fit()

    xtermRef.current = term
    fitAddonRef.current = fitAddon

    // Typewriter intro
    const lines = [
      '\x1b[36m╔══════════════════════════════════════════╗\x1b[0m',
      '\x1b[36m║  \x1b[32mSeraph\x1b[0m \x1b[90m//\x1b[0m \x1b[36mSecurity Terminal\x1b[0m          \x1b[36m║\x1b[0m',
      '\x1b[36m╚══════════════════════════════════════════╝\x1b[0m',
      '',
      '\x1b[90m  Ready. Awaiting command execution...\x1b[0m',
      '',
    ]

    let lineIdx = 0
    const printNextLine = () => {
      if (lineIdx < lines.length) {
        term.writeln(lines[lineIdx])
        lineIdx++
        setTimeout(printNextLine, 60)
      }
    }
    setTimeout(printNextLine, 200)

    const handleResize = () => fitAddon.fit()
    window.addEventListener('resize', handleResize)

    return () => {
      window.removeEventListener('resize', handleResize)
      wsRef.current?.close()
      term.dispose()
    }
  }, [])

  useImperativeHandle(ref, () => ({
    write: (data: string) => xtermRef.current?.write(data),
    writeln: (data: string) => xtermRef.current?.writeln(data),
    clear: () => xtermRef.current?.clear(),
    connect: (scanId: string, script: string) => {
      const term = xtermRef.current
      if (!term) return

      wsRef.current?.close()

      const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const wsUrl = `${wsProto}//${window.location.host}/ws/execute/${scanId}`
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws

      ws.onopen = () => {
        term.writeln('\x1b[33m[*] Connected — starting execution...\x1b[0m')
        ws.send(JSON.stringify({ action: 'run', script }))
      }

      ws.onmessage = (event) => {
        const msg = JSON.parse(event.data)
        if (msg.type === 'stdout') {
          term.write(msg.data)
        } else if (msg.type === 'stderr') {
          term.write('\x1b[33m' + msg.data + '\x1b[0m')
        } else if (msg.type === 'exit') {
          if (msg.code === 0) {
            term.writeln('\x1b[32m\r\n[+] Command completed successfully (exit 0)\x1b[0m')
          } else {
            term.writeln(`\x1b[31m\r\n[!] Command exited with code ${msg.code}\x1b[0m`)
          }
        } else if (msg.type === 'error') {
          term.writeln(`\x1b[31m[ERROR] ${msg.data}\x1b[0m`)
        }
      }

      ws.onerror = () => {
        term.writeln('\x1b[31m[ERROR] WebSocket connection failed\x1b[0m')
      }

      ws.onclose = () => {
        term.writeln('\x1b[90m[disconnected]\x1b[0m')
      }
    },
    disconnect: () => {
      wsRef.current?.close()
      wsRef.current = null
    },
  }))

  return (
    <div
      ref={containerRef}
      className={className}
      style={{ backgroundColor: theme === 'mono' ? '#050505' : '#05080d' }}
    />
  )
})

Terminal.displayName = 'Terminal'
export default Terminal
