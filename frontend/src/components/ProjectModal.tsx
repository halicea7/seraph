import { useState } from 'react'
import { X, Plus, Trash2 } from 'lucide-react'

interface TargetInput {
  hostname_or_ip: string
  target_type: string
  ports: string
  notes: string
}

interface ProjectModalProps {
  onClose: () => void
  onSave: (project: { name: string; description: string }, targets: TargetInput[]) => Promise<void>
}

const TARGET_TYPES = [
  { value: 'linux_host', label: 'Linux Host' },
  { value: 'windows_host', label: 'Windows Host' },
  { value: 'web_app', label: 'Web Application' },
  { value: 'cloud_aws', label: 'Cloud (AWS)' },
  { value: 'network', label: 'Network' },
]

const inputClass = "w-full rounded-lg px-3 py-2 text-sm text-white focus:outline-none border border-cyan-900/20 focus:border-cyan-500/40"

export default function ProjectModal({ onClose, onSave }: ProjectModalProps) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [targets, setTargets] = useState<TargetInput[]>([
    { hostname_or_ip: '', target_type: 'linux_host', ports: '', notes: '' }
  ])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  function addTarget() {
    setTargets(prev => [...prev, { hostname_or_ip: '', target_type: 'linux_host', ports: '', notes: '' }])
  }

  function removeTarget(idx: number) {
    setTargets(prev => prev.filter((_, i) => i !== idx))
  }

  function updateTarget(idx: number, field: keyof TargetInput, value: string) {
    setTargets(prev => prev.map((t, i) => i === idx ? { ...t, [field]: value } : t))
  }

  async function handleSave() {
    if (!name.trim()) { setError('Project name is required'); return }
    const validTargets = targets.filter(t => t.hostname_or_ip.trim())
    setSaving(true)
    setError('')
    try {
      await onSave({ name: name.trim(), description: description.trim() }, validTargets)
      onClose()
    } catch (e: any) {
      setError(e.message || 'Failed to save project')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md">
      <div className="glass rounded-2xl border border-cyan-900/30 w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-cyan-900/20">
          <h2 className="text-lg font-semibold text-white">New Project</h2>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition-colors">
            <X size={20} />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-5">
          {error && (
            <div className="rounded-lg px-4 py-2 text-sm text-red-400 border border-red-700/50" style={{ background: 'rgba(127,29,29,0.3)' }}>
              {error}
            </div>
          )}

          {/* Project Info */}
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-slate-400 mb-1">Project Name *</label>
              <input
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. ACME Corp Q2 Assessment"
                className={inputClass}
                style={{ background: '#05080d' }}
                autoFocus
              />
            </div>
            <div>
              <label className="block text-xs text-slate-400 mb-1">Description</label>
              <textarea
                value={description}
                onChange={e => setDescription(e.target.value)}
                placeholder="Engagement scope, objectives..."
                rows={2}
                className={`${inputClass} resize-none`}
                style={{ background: '#05080d' }}
              />
            </div>
          </div>

          {/* Targets */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Targets</label>
              <button
                onClick={addTarget}
                className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
              >
                <Plus size={14} /> Add Target
              </button>
            </div>
            <div className="space-y-3">
              {targets.map((target, idx) => (
                <div key={idx} className="glass rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-slate-400">Target {idx + 1}</span>
                    {targets.length > 1 && (
                      <button onClick={() => removeTarget(idx)} className="text-slate-600 hover:text-red-400 transition-colors">
                        <Trash2 size={14} />
                      </button>
                    )}
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">Hostname / IP</label>
                      <input
                        type="text"
                        value={target.hostname_or_ip}
                        onChange={e => updateTarget(idx, 'hostname_or_ip', e.target.value)}
                        placeholder="192.168.1.1 or target.example.com"
                        className={`${inputClass} font-mono`}
                        style={{ background: '#090d14' }}
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">Type</label>
                      <select
                        value={target.target_type}
                        onChange={e => updateTarget(idx, 'target_type', e.target.value)}
                        className={inputClass}
                        style={{ background: '#090d14' }}
                      >
                        {TARGET_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">Port Range (optional)</label>
                      <input
                        type="text"
                        value={target.ports}
                        onChange={e => updateTarget(idx, 'ports', e.target.value)}
                        placeholder="e.g. 1-1024"
                        className={`${inputClass} font-mono`}
                        style={{ background: '#090d14' }}
                      />
                    </div>
                    <div>
                      <label className="block text-xs text-slate-400 mb-1">Notes</label>
                      <input
                        type="text"
                        value={target.notes}
                        onChange={e => updateTarget(idx, 'notes', e.target.value)}
                        placeholder="Any context..."
                        className={inputClass}
                        style={{ background: '#090d14' }}
                      />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-cyan-900/20">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-sm text-slate-400 hover:text-slate-200 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="px-6 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-sm text-white font-semibold transition-all shadow-glow-blue"
          >
            {saving ? 'Creating...' : 'Create Project'}
          </button>
        </div>
      </div>
    </div>
  )
}
