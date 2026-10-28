import { useEffect, useRef } from 'react'
import hljs from 'highlight.js/lib/core'
import bash from 'highlight.js/lib/languages/bash'
import 'highlight.js/styles/atom-one-dark.css'

hljs.registerLanguage('bash', bash)

interface ScriptPreviewProps {
  script: string
  className?: string
}

export default function ScriptPreview({ script, className = '' }: ScriptPreviewProps) {
  const codeRef = useRef<HTMLElement>(null)

  useEffect(() => {
    if (codeRef.current && script) {
      codeRef.current.removeAttribute('data-highlighted')
      codeRef.current.textContent = script
      hljs.highlightElement(codeRef.current)
    }
  }, [script])

  if (!script) {
    return (
      <div className={`flex items-center justify-center text-slate-400 font-mono text-sm ${className}`}>
        Script preview will appear here after generation
      </div>
    )
  }

  return (
    <div className={`overflow-auto on-term ${className}`} style={{ border: '1px solid var(--rule)', background: 'var(--bg-term)' }}>
      <pre style={{ margin: 0, padding: '12px 14px', fontSize: 11, lineHeight: 1.55, overflowX: 'auto', fontFamily: 'var(--font-mono)' }}>
        <code ref={codeRef} className="language-bash" />
      </pre>
    </div>
  )
}
