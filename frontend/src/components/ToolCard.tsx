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

const statusBorder: Record<ToolStatus, string> = {
  idle: 'border-l-slate-800',
  running: 'border-l-blue-500',
  completed: 'border-l-green-500',
  failed: 'border-l-red-500',
}

const statusGlow: Record<ToolStatus, string> = {
  idle: '',
  running: 'shadow-glow-blue',
  completed: 'shadow-glow-green',
  failed: 'shadow-glow-red',
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
    idle: <Circle size={14} className="text-slate-600" />,
    running: <Loader size={14} className="text-blue-400 animate-spin" />,
    completed: <CheckCircle size={14} className="text-green-500" />,
    failed: <XCircle size={14} className="text-red-500" />,
  }[status]

  return (
    <div className={`glass glass-hover rounded-xl border-l-4 ${statusBorder[status]} ${statusGlow[status]} overflow-hidden transition-all`}>
      {/* Header */}
      <div className="flex items-start gap-3 p-4">
        <div className="mt-0.5">{statusIcon}</div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="font-mono text-sm font-semibold text-cyan-400">{tool}</span>
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
              value={editedCommand}
              onChange={e => setEditedCommand(e.target.value)}
              className="w-full rounded px-3 py-2 font-mono text-xs text-slate-200 focus:outline-none resize-none border border-cyan-500/40"
              style={{ background: '#05080d' }}
              rows={Math.max(2, editedCommand.split('\n').length)}
              autoFocus
            />
            <div className="flex gap-2">
              <button
                onClick={handleEditSave}
                className="flex items-center gap-1.5 px-3 py-1 rounded bg-blue-600 hover:bg-blue-500 text-xs text-white transition-colors"
              >
                <Check size={12} /> Save
              </button>
              <button
                onClick={handleEditCancel}
                className="flex items-center gap-1.5 px-3 py-1 rounded text-xs text-slate-300 transition-colors border border-cyan-900/30 hover:border-cyan-900/50"
                style={{ background: '#0d1520' }}
              >
                <X size={12} /> Cancel
              </button>
            </div>
          </div>
        ) : (
          <div className="group relative">
            <div className="rounded px-3 py-2 font-mono text-xs text-slate-300 break-all border border-cyan-900/20" style={{ background: '#05080d' }}>
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
          className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs text-slate-300 transition-colors border border-cyan-900/20 hover:border-cyan-900/40"
          style={{ background: '#0d1520' }}
        >
          {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
          {copied ? 'Copied!' : 'Copy'}
        </button>
        <button
          onClick={() => { setIsEditing(!isEditing); setEditedCommand(renderedCommand) }}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs text-slate-300 transition-colors border border-cyan-900/20 hover:border-cyan-900/40"
          style={{ background: '#0d1520' }}
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
              className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
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
        <div className="border-t border-cyan-900/20 px-4 py-3 max-h-48 overflow-y-auto" style={{ background: '#05080d' }}>
          <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap">{output}</pre>
        </div>
      )}
    </div>
  )
}
