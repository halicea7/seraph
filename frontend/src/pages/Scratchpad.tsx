import { useState, useEffect, useRef, useCallback } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { useAppStore } from '@/stores/appStore'
import { getApiBase } from '@/lib/config'
import Icon from '@/components/Icon'

type SaveStatus = 'saved' | 'saving' | 'unsaved' | 'idle'

const DEBOUNCE_MS = 1000

export default function Scratchpad() {
  const { selectedProject } = useAppStore()
  const api = getApiBase()

  const [content,    setContent]    = useState('')
  const [mode,       setMode]       = useState<'edit' | 'preview'>('edit')
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [lastSaved,  setLastSaved]  = useState<Date | null>(null)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const projectId   = selectedProject?.id

  // Load on project change
  useEffect(() => {
    if (!projectId) { setContent(''); setSaveStatus('idle'); return }
    fetch(`${api}/projects/${projectId}/scratchpad`)
      .then(r => r.json())
      .then(d => { setContent(d.content ?? ''); setSaveStatus('saved') })
      .catch(() => setSaveStatus('idle'))
  }, [projectId])

  const save = useCallback(async (text: string) => {
    if (!projectId) return
    setSaveStatus('saving')
    try {
      await fetch(`${api}/projects/${projectId}/scratchpad`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: text }),
      })
      setSaveStatus('saved')
      setLastSaved(new Date())
    } catch {
      setSaveStatus('unsaved')
    }
  }, [projectId])

  function handleChange(e: React.ChangeEvent<HTMLTextAreaElement>) {
    const val = e.target.value
    setContent(val)
    setSaveStatus('unsaved')
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => save(val), DEBOUNCE_MS)
  }

  // Cleanup debounce on unmount
  useEffect(() => () => { if (debounceRef.current) clearTimeout(debounceRef.current) }, [])

  const statusColor: Record<SaveStatus, string> = {
    saved:   'var(--accent)',
    saving:  'var(--fg-3)',
    unsaved: '#e07b39',
    idle:    'var(--fg-4)',
  }
  const statusLabel: Record<SaveStatus, string> = {
    saved:   lastSaved ? `Saved ${lastSaved.toLocaleTimeString()}` : 'Saved',
    saving:  'Saving…',
    unsaved: 'Unsaved',
    idle:    '—',
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

      {/* Toolbar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12,
        padding: '10px 20px', borderBottom: '1px solid var(--rule)',
        background: 'var(--bg-2)', flexShrink: 0,
      }}>
        <Icon name="edit" size={13} color="var(--accent)" />
        <span className="smcap" style={{ fontSize: 10, color: 'var(--fg)', letterSpacing: '0.12em' }}>
          {selectedProject ? selectedProject.name : 'Scratchpad'}
        </span>

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
          {/* Mode toggle */}
          <div style={{ display: 'flex', border: '1px solid var(--rule)', borderRadius: 3, overflow: 'hidden' }}>
            {(['edit', 'preview'] as const).map(m => (
              <button
                key={m}
                onClick={() => setMode(m)}
                style={{
                  padding: '4px 12px', fontSize: 11, border: 'none', cursor: 'pointer',
                  fontFamily: 'var(--font-mono)', textTransform: 'uppercase', letterSpacing: '0.08em',
                  background: mode === m ? 'var(--accent)' : 'var(--bg)',
                  color:      mode === m ? '#1a1408'        : 'var(--fg-3)',
                  transition: 'background .12s, color .12s',
                }}
              >{m}</button>
            ))}
          </div>

          {/* Save status */}
          <span className="mono" style={{ fontSize: 10, color: statusColor[saveStatus] }}>
            {statusLabel[saveStatus]}
          </span>

          {/* Manual save */}
          <button
            className="btn"
            onClick={() => { if (debounceRef.current) clearTimeout(debounceRef.current); save(content) }}
            disabled={!projectId || saveStatus === 'saving'}
            style={{ fontSize: 11, padding: '4px 12px' }}
          >
            Save
          </button>
        </div>
      </div>

      {/* Body */}
      {!selectedProject ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <span style={{ fontSize: 13, color: 'var(--fg-3)' }}>Select a project to use the scratchpad.</span>
        </div>
      ) : mode === 'edit' ? (
        <textarea
          value={content}
          onChange={handleChange}
          placeholder={'# Notes\n\nStart typing. Markdown is supported. Auto-saves after 1 second.\n\n---\n\n- Targets of interest\n- Credentials found\n- Next steps'}
          style={{
            flex: 1, resize: 'none', border: 'none', outline: 'none',
            background: 'var(--bg)', color: 'var(--fg)',
            fontFamily: 'var(--font-mono)', fontSize: 13, lineHeight: 1.7,
            padding: '20px 28px',
          }}
        />
      ) : (
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px 28px' }}>
          {content.trim() ? (
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                h1: ({ children }) => <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--fg)', borderBottom: '1px solid var(--rule)', paddingBottom: 8, marginBottom: 16 }}>{children}</h1>,
                h2: ({ children }) => <h2 style={{ fontSize: 16, fontWeight: 600, color: 'var(--fg)', marginBottom: 12, marginTop: 24 }}>{children}</h2>,
                h3: ({ children }) => <h3 style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent)', marginBottom: 8, marginTop: 16 }}>{children}</h3>,
                p:  ({ children }) => <p  style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7, marginBottom: 12 }}>{children}</p>,
                ul: ({ children }) => <ul style={{ paddingLeft: 20, marginBottom: 12 }}>{children}</ul>,
                ol: ({ children }) => <ol style={{ paddingLeft: 20, marginBottom: 12 }}>{children}</ol>,
                li: ({ children }) => <li style={{ fontSize: 13, color: 'var(--fg-2)', lineHeight: 1.7, marginBottom: 4 }}>{children}</li>,
                code: ({ children, className }) => {
                  const block = className?.startsWith('language-')
                  return block
                    ? <pre style={{ background: 'var(--bg-2)', border: '1px solid var(--rule)', borderRadius: 3, padding: '12px 16px', overflowX: 'auto', marginBottom: 12 }}><code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--fg)' }}>{children}</code></pre>
                    : <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, background: 'var(--bg-2)', padding: '1px 5px', borderRadius: 2, color: 'var(--accent)' }}>{children}</code>
                },
                hr:     () => <hr style={{ border: 'none', borderTop: '1px solid var(--rule)', margin: '20px 0' }} />,
                strong: ({ children }) => <strong style={{ color: 'var(--fg)', fontWeight: 600 }}>{children}</strong>,
                blockquote: ({ children }) => <blockquote style={{ borderLeft: '3px solid var(--accent)', paddingLeft: 14, margin: '12px 0', color: 'var(--fg-3)' }}>{children}</blockquote>,
                table: ({ children }) => <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 16, fontSize: 12 }}>{children}</table>,
                th: ({ children }) => <th style={{ padding: '6px 10px', borderBottom: '1px solid var(--rule)', textAlign: 'left', color: 'var(--fg-3)', fontFamily: 'var(--font-mono)', fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{children}</th>,
                td: ({ children }) => <td style={{ padding: '6px 10px', borderBottom: '1px solid var(--rule)', color: 'var(--fg-2)', fontSize: 12 }}>{children}</td>,
              }}
            >
              {content}
            </ReactMarkdown>
          ) : (
            <span style={{ fontSize: 13, color: 'var(--fg-4)' }}>Nothing written yet. Switch to Edit to start.</span>
          )}
        </div>
      )}
    </div>
  )
}
