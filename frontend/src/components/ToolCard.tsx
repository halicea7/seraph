import { useState, useRef, useEffect } from 'react'
import {
  Play, Copy, Edit2, Check, X, Terminal as TerminalIcon,
  ChevronDown, ChevronUp, Circle, Loader, CheckCircle, XCircle,
  FileText,
} from 'lucide-react'

export type ToolStatus = 'idle' | 'running' | 'completed' | 'failed'

export interface ToolCardProps {
  tool: string
  description: string
  commandTemplate: string
  install: string
  renderedCommand: string
  status: ToolStatus
  output?: string
  scanId?: string | null
  isToolAvailable?: boolean
  onRun: (command: string) => void
  onCommandChange: (command: string) => void
  onViewOutput?: () => void
}

const statusBorderColor: Record<ToolStatus, string> = {
  idle: 'var(--rule-strong)',
  running: 'var(--accent)',
  completed: 'var(--ok)',
  failed: 'var(--crit)',
}

export default function ToolCard({
  tool,
  description,
  commandTemplate: _commandTemplate,
  install,
  renderedCommand,
  status,
  output,
  scanId,
  isToolAvailable = true,
  onRun,
  onCommandChange,
  onViewOutput,
}: ToolCardProps) {
  const [isEditing, setIsEditing] = useState(false)
  const [editedCommand, setEditedCommand] = useState(renderedCommand)
  const [copied, setCopied] = useState(false)
  const [showOutput, setShowOutput] = useState(false)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    setEditedCommand(renderedCommand)
  }, [renderedCommand])

  useEffect(() => {
    if (status === 'running' || status === 'completed' || status === 'failed') {
      setShowOutput(true)
    }
  }, [status])

  function handleCopy() {
    navigator.clipboard.writeText(isEditing ? editedCommand : renderedCommand)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  function handleEditSave() {
    onCommandChange(editedCommand)
    setIsEditing(false)
  }

  function handleEditCancel() {
    setEditedCommand(renderedCommand)
    setIsEditing(false)
  }

  const statusIcon = {
    idle: <Circle size={14} style={{ color: 'var(--fg-4)' }} />,
    running: <Loader size={14} style={{ color: 'var(--accent)', animation: 'spin 1s linear infinite' }} />,
    completed: <CheckCircle size={14} style={{ color: 'var(--ok)' }} />,
    failed: <XCircle size={14} style={{ color: 'var(--crit)' }} />,
  }[status]

  return (
    <div style={{ background: 'var(--bg-2)', border: '1px solid var(--rule-strong)', borderLeft: `3px solid ${statusBorderColor[status]}`, overflow: 'hidden' }}>
      {/* Header */}
      <div className="flex items-start gap-3 p-4">
        <div className="mt-0.5">{statusIcon}</div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 600, color: 'var(--accent)' }}>{tool}</span>
            {!isToolAvailable && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-amber-900/30 text-amber-400 border border-amber-700/30">
                not installed
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400">{description}</p>
        </div>
      </div>

      {/* Command */}
      <div className="px-4 pb-3">
        {isEditing ? (
          <div className="space-y-2">
            <textarea
              ref={textareaRef}
              className="on-term"
              value={editedCommand}
              onChange={e => setEditedCommand(e.target.value)}
              style={{ width: '100%', padding: '8px 10px', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg)', background: 'var(--bg-term)', border: '1px solid var(--accent-border)', outline: 'none', resize: 'none' }}
              rows={Math.max(2, editedCommand.split('\n').length)}
              autoFocus
            />
            <div className="flex gap-2">
              <button
                onClick={handleEditSave}
                style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '4px 10px', fontSize: 11, background: 'var(--accent)', color: '#1a1408', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}
              >
                <Check size={12} /> Save
              </button>
              <button
                onClick={handleEditCancel}
                style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '4px 10px', fontSize: 11, color: 'var(--fg-2)', background: 'var(--bg-2)', border: '1px solid var(--rule-strong)', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}
              >
                <X size={12} /> Cancel
              </button>
            </div>
          </div>
        ) : (
          <div>
            <div className="on-term" style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg-2)', wordBreak: 'break-all', border: '1px solid var(--rule)', background: 'var(--bg-term)' }}>
              {renderedCommand}
            </div>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 px-4 pb-3">
        <button
          onClick={() => onRun(renderedCommand)}
          disabled={status === 'running' || !isToolAvailable}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-green-600 hover:bg-green-500 disabled:opacity-40 text-xs text-white font-medium transition-all hover:shadow-glow-green"
        >
          <Play size={12} />
          {status === 'running' ? 'Running...' : 'Run'}
        </button>
        <button
          onClick={handleCopy}
          style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '4px 10px', fontSize: 11, color: copied ? 'var(--ok)' : 'var(--fg-2)', background: 'var(--bg)', border: '1px solid var(--rule)', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}
        >
          {copied ? <Check size={12} /> : <Copy size={12} />}
          {copied ? 'Copied!' : 'Copy'}
        </button>
        <button
          onClick={() => { setIsEditing(!isEditing); setEditedCommand(renderedCommand) }}
          style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '4px 10px', fontSize: 11, color: 'var(--fg-2)', background: 'var(--bg)', border: '1px solid var(--rule)', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}
        >
          <Edit2 size={12} /> Edit
        </button>
        {!isToolAvailable && (
          <span className="text-xs text-slate-500 ml-auto font-mono">{install}</span>
        )}
        <div className="ml-auto flex items-center gap-2">
          {scanId && onViewOutput && (
            <button
              onClick={onViewOutput}
              style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--accent)', background: 'none', border: 'none', cursor: 'pointer', fontFamily: 'var(--font-mono)' }}
              title="Load saved output into terminal"
            >
              <FileText size={12} />
              View Output
            </button>
          )}
          {(output || status !== 'idle') && (
            <button
              onClick={() => setShowOutput(!showOutput)}
              className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 transition-colors"
            >
              <TerminalIcon size={12} />
              Output
              {showOutput ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
            </button>
          )}
        </div>
      </div>

      {/* Output */}
      {showOutput && output && (
        <div className="on-term" style={{ borderTop: '1px solid var(--rule)', padding: '10px 14px', maxHeight: 192, overflowY: 'auto', background: 'var(--bg-term)' }}>
          <pre style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fg-2)', whiteSpace: 'pre-wrap', margin: 0 }}>{output}</pre>
        </div>
      )}
    </div>
  )
}
