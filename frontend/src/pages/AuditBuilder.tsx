import { useState, useEffect, useRef } from 'react'
import {
  Network, ShieldAlert, Globe, Server, ClipboardCheck,
  Cloud, Activity, ChevronDown, ChevronUp, Download,
  Play, RefreshCw, CheckSquare, Square, BookMarked, ChevronRight,
  Clock, X, Shield, CheckCircle, XCircle, AlertTriangle, Gauge, KeyRound,
} from 'lucide-react'
import ScriptPreview from '../components/ScriptPreview'
import Terminal, { TerminalHandle } from '../components/Terminal'
import { getProjects, getTargets } from '../api/client'
import type { Project, TargetSummary, ScanCategory } from '../types'

const BASE_URL = '/api/v1'

const CATEGORY_ICONS: Record<string, React.ReactNode> = {
  network_discovery: <Network size={20} />,
  vulnerability_scan: <ShieldAlert size={20} />,
  web_audit: <Globe size={20} />,
  host_hardening: <Server size={20} />,
  openscap: <ClipboardCheck size={20} />,
  cloud_aws: <Cloud size={20} />,
  log_monitoring: <Activity size={20} />,
}

interface Profile {
  id: string
  name: string
  description: string
  scan_categories: Array<{ category_id: string; config: Record<string, any> }>
  schedule: string | null
  last_run: string | null
  next_run: string | null
}

export default function AuditBuilder() {
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedProject, setSelectedProject] = useState<string>('')
  const [targets, setTargets] = useState<TargetSummary[]>([])
  const [selectedTarget, setSelectedTarget] = useState<string>('')
  const [categories, setCategories] = useState<Record<string, ScanCategory>>({})
  const [selectedCategories, setSelectedCategories] = useState<Set<string>>(new Set())
  const [expandedCategory, setExpandedCategory] = useState<string | null>(null)
  const [categoryConfigs, setCategoryConfigs] = useState<Record<string, Record<string, any>>>({})
  const [generatedScript, setGeneratedScript] = useState('')
  const [scanId, setScanId] = useState<string | null>(null)
  const [generating, setGenerating] = useState(false)
  const [activeTab, setActiveTab] = useState<'preview' | 'terminal' | 'compliance'>('preview')

  // Compliance / hardening profiles
  const [hardeningProfiles, setHardeningProfiles] = useState<any[]>([])
  const [selectedHardeningProfile, setSelectedHardeningProfile] = useState('cis_l1')
  const [complianceReport, setComplianceReport] = useState<any | null>(null)
  const [scoring, setScoring] = useState(false)
  const [scoreError, setScoreError] = useState('')
  const [toolStatus, setToolStatus] = useState<Record<string, { available: boolean }>>({})
  const terminalRef = useRef<TerminalHandle>(null)

  // SSH credential state
  const REMOTE_CATEGORIES = new Set(['host_hardening', 'openscap', 'log_monitoring'])
  const needsSSH = [...selectedCategories].some(c => REMOTE_CATEGORIES.has(c))
  const [sshCredentials, setSshCredentials] = useState<Array<{ id: string; username: string; target_host: string; notes: string }>>([])
  const [selectedCredentialId, setSelectedCredentialId] = useState<string>('')

  // Profile state
  const [profiles, setProfiles] = useState<Profile[]>([])
  const [selectedProfileId, setSelectedProfileId] = useState<string>('')
  const [profileName, setProfileName] = useState('')
  const [showProfileSave, setShowProfileSave] = useState(false)
  const [savingProfile, setSavingProfile] = useState(false)

  // Schedule state
  const [showSchedule, setShowSchedule] = useState(false)
  const [scheduleCron, setScheduleCron] = useState('')
  const [savingSchedule, setSavingSchedule] = useState(false)

  useEffect(() => {
    loadProjects()
    loadCategories()
    loadToolStatus()
    loadProfiles()
    loadHardeningProfiles()
  }, [])

  async function loadHardeningProfiles() {
    try {
      const res = await fetch(`${BASE_URL}/hardening/profiles`)
      if (res.ok) setHardeningProfiles(await res.json())
    } catch { /* ignore */ }
  }

  async function handleScoreScan() {
    if (!scanId || !selectedProject) return
    setScoring(true)
    setScoreError('')
    try {
      const res = await fetch(`${BASE_URL}/hardening/score`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scan_id: scanId, profile_id: selectedHardeningProfile, project_id: selectedProject }),
      })
      if (!res.ok) {
        const err = await res.json()
        setScoreError(err.detail || 'Scoring failed')
        return
      }
      setComplianceReport(await res.json())
    } catch (e: any) {
      setScoreError(e.message || 'Scoring failed')
    } finally {
      setScoring(false)
    }
  }

  async function loadProjects() {
    try {
      const data = await getProjects()
      setProjects(data)
      if (data.length > 0) setSelectedProject(data[0].id)
    } catch (err) {
      console.error('Failed to load projects', err)
    }
  }

  async function loadCategories() {
    try {
      const res = await fetch(`${BASE_URL}/audit/categories`)
      const data = await res.json()
      setCategories(data)
      const defaults: Record<string, Record<string, any>> = {}
      for (const [id, cat] of Object.entries(data as Record<string, ScanCategory>)) {
        defaults[id] = {}
        for (const [key, schema] of Object.entries(cat.config_schema)) {
          defaults[id][key] = schema.default ?? ''
        }
      }
      setCategoryConfigs(defaults)
    } catch (err) {
      console.error('Failed to load categories', err)
    }
  }

  async function loadToolStatus() {
    try {
      const res = await fetch(`${BASE_URL}/settings/tools`)
      const data = await res.json()
      setToolStatus(data)
    } catch {
      // Tool status is optional — ignore errors
    }
  }

  async function loadProfiles() {
    try {
      const res = await fetch(`${BASE_URL}/profiles`)
      if (res.ok) {
        const data = await res.json()
        const parsed = data.map((p: any) => ({
          ...p,
          scan_categories: typeof p.scan_categories === 'string'
            ? JSON.parse(p.scan_categories)
            : p.scan_categories,
        }))
        setProfiles(parsed)
      }
    } catch {
      // ignore
    }
  }

  useEffect(() => {
    if (selectedProject) {
      getTargets(selectedProject)
        .then(data => {
          setTargets(data)
          if (data.length > 0) setSelectedTarget(data[0].id)
          else setSelectedTarget('')
        })
        .catch(err => console.error('Failed to load targets', err))

      fetch(`${BASE_URL}/credentials/keys?project_id=${selectedProject}`)
        .then(r => r.ok ? r.json() : [])
        .then(setSshCredentials)
        .catch(() => {})
    }
  }, [selectedProject])

  function toggleCategory(id: string) {
    setSelectedCategories(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function updateConfig(categoryId: string, key: string, value: any) {
    setCategoryConfigs(prev => ({
      ...prev,
      [categoryId]: { ...prev[categoryId], [key]: value },
    }))
  }

  function applyProfile(profileId: string) {
    const profile = profiles.find(p => p.id === profileId)
    if (!profile) return
    const newSelected = new Set<string>()
    const newConfigs: Record<string, Record<string, any>> = { ...categoryConfigs }
    for (const cat of profile.scan_categories) {
      newSelected.add(cat.category_id)
      newConfigs[cat.category_id] = { ...newConfigs[cat.category_id], ...cat.config }
    }
    setSelectedCategories(newSelected)
    setCategoryConfigs(newConfigs)
    setSelectedProfileId('')
  }

  async function handleSaveSchedule() {
    if (!selectedProfileId) return
    setSavingSchedule(true)
    await fetch(`/api/v1/profiles/${selectedProfileId}/schedule`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        cron: scheduleCron || null,
        project_id: selectedProject || null,
        target_id: selectedTarget || null,
      }),
    })
    setSavingSchedule(false)
    setShowSchedule(false)
    await loadProfiles()
  }

  async function handleClearSchedule() {
    if (!selectedProfileId) return
    await fetch(`/api/v1/profiles/${selectedProfileId}/schedule`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cron: null }),
    })
    await loadProfiles()
  }

  async function handleSaveProfile() {
    if (!profileName.trim()) return
    setSavingProfile(true)
    try {
      await fetch(`${BASE_URL}/profiles`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: profileName.trim(),
          description: `Saved from Audit Builder — ${Array.from(selectedCategories).join(', ')}`,
          scan_categories: Array.from(selectedCategories).map(id => ({
            category_id: id,
            config: categoryConfigs[id] || {},
          })),
        }),
      })
      setProfileName('')
      setShowProfileSave(false)
      await loadProfiles()
    } catch (err) {
      console.error('Failed to save profile', err)
    } finally {
      setSavingProfile(false)
    }
  }

  async function handleGenerate() {
    if (!selectedProject || !selectedTarget || selectedCategories.size === 0) return
    setGenerating(true)
    try {
      const scanCategories = Array.from(selectedCategories).map(id => ({
        category_id: id,
        config: categoryConfigs[id] || {},
      }))
      const res = await fetch(`${BASE_URL}/audit/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          project_id: selectedProject,
          target_id: selectedTarget,
          scan_categories: scanCategories,
          credential_id: needsSSH && selectedCredentialId ? selectedCredentialId : null,
        }),
      })
      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.detail ?? `HTTP ${res.status}`)
      }
      const data = await res.json()
      setGeneratedScript(data.script)
      setScanId(data.scan_id)
      setComplianceReport(null)
      setActiveTab('preview')
    } catch (err) {
      console.error('Script generation failed', err)
    } finally {
      setGenerating(false)
    }
  }

  async function handleDownload() {
    if (!scanId) return
    const res = await fetch(`${BASE_URL}/audit/script/${scanId}/download`)
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `seraph_audit_${scanId.slice(0, 8)}.sh`
    a.click()
    URL.revokeObjectURL(url)
  }

  function handleRunOnServer() {
    if (!scanId || !generatedScript) return
    setActiveTab('terminal')
    setTimeout(() => {
      terminalRef.current?.connect(scanId, generatedScript)
    }, 100)
  }

  const inputClass = "w-full rounded px-3 py-1.5 text-sm text-slate-200 focus:outline-none border border-cyan-900/20 focus:border-cyan-500/50"

  function renderConfigField(categoryId: string, key: string, schema: ScanCategory['config_schema'][string]) {
    const value = categoryConfigs[categoryId]?.[key]

    if (schema.type === 'select') {
      return (
        <select
          className={inputClass}
          style={{ background: '#05080d' }}
          value={value}
          onChange={e => updateConfig(categoryId, key, e.target.value)}
        >
          {(schema.options ?? []).map((opt: string) => (
            <option key={opt} value={opt}>{opt}</option>
          ))}
        </select>
      )
    }

    if (schema.type === 'multiselect') {
      const selected: string[] = Array.isArray(value) ? value : []
      return (
        <div className="flex flex-wrap gap-2">
          {(schema.options ?? []).map((opt: string) => {
            const isSelected = selected.includes(opt)
            return (
              <button
                key={opt}
                onClick={() => {
                  const next = isSelected
                    ? selected.filter(s => s !== opt)
                    : [...selected, opt]
                  updateConfig(categoryId, key, next)
                }}
                className={`px-2 py-1 rounded text-xs border transition-colors ${
                  isSelected
                    ? 'bg-cyan-600 border-cyan-500 text-white'
                    : 'bg-transparent border-cyan-900/30 text-slate-400 hover:border-cyan-900/60'
                }`}
              >
                {opt}
              </button>
            )
          })}
        </div>
      )
    }

    if (schema.type === 'boolean') {
      return (
        <button
          onClick={() => updateConfig(categoryId, key, !value)}
          className="flex items-center gap-2 text-sm text-slate-300"
        >
          {value ? <CheckSquare size={16} className="text-cyan-400" /> : <Square size={16} className="text-slate-500" />}
          {value ? 'Enabled' : 'Disabled'}
        </button>
      )
    }

    return (
      <input
        type="text"
        className={inputClass}
        style={{ background: '#05080d' }}
        value={value || ''}
        placeholder={schema.placeholder || ''}
        onChange={e => updateConfig(categoryId, key, e.target.value)}
      />
    )
  }

  const selectClass = "w-full rounded px-3 py-2 text-sm text-slate-200 focus:outline-none border border-cyan-900/20 focus:border-cyan-500/50"

  return (
    <div className="flex h-full gap-4 overflow-hidden">
      {/* Left Panel */}
      <div className="w-80 flex-shrink-0 flex flex-col gap-4 min-h-0">
        {/* Project & Target Selection */}
        <div className="glass glass-hover rounded-xl p-4">
          <h3 className="text-sm font-semibold text-slate-200 mb-3">Target Selection</h3>
          <div className="space-y-3">
            <div>
              <label className="text-xs text-slate-400 mb-1 block">Project</label>
              <select
                className={selectClass}
                style={{ background: '#05080d' }}
                value={selectedProject}
                onChange={e => setSelectedProject(e.target.value)}
              >
                <option value="">Select project...</option>
                {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-slate-400 mb-1 block">Target</label>
              <select
                className={selectClass}
                style={{ background: '#05080d' }}
                value={selectedTarget}
                onChange={e => setSelectedTarget(e.target.value)}
                disabled={targets.length === 0}
              >
                <option value="">Select target...</option>
                {targets.map(t => <option key={t.id} value={t.id}>{t.hostname_or_ip}</option>)}
              </select>
            </div>

            {/* SSH credential picker — shown when a remote category is selected */}
            {needsSSH && (
              <div>
                <label className="text-xs mb-1 flex items-center gap-1.5 text-amber-400">
                  <KeyRound size={11} />
                  SSH Key Credential
                </label>
                {sshCredentials.length === 0 ? (
                  <p className="text-[11px] text-slate-500 px-1">
                    No SSH keys in vault for this project.{' '}
                    <a href="/vault" className="text-cyan-500 hover:text-cyan-300 underline">Add one →</a>
                  </p>
                ) : (
                  <select
                    className={selectClass}
                    style={{ background: '#05080d' }}
                    value={selectedCredentialId}
                    onChange={e => setSelectedCredentialId(e.target.value)}
                  >
                    <option value="">Run locally (no SSH)</option>
                    {sshCredentials.map(c => (
                      <option key={c.id} value={c.id}>
                        {c.username}@{c.target_host || 'any'}{c.notes ? ` — ${c.notes}` : ''}
                      </option>
                    ))}
                  </select>
                )}
                {selectedCredentialId && (
                  <p className="text-[10px] text-amber-500/70 mt-1 px-1">
                    Script will run on the target via SSH
                  </p>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Load Profile */}
        {profiles.length > 0 && (
          <div className="glass glass-hover rounded-xl p-4">
            <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
              <BookMarked size={14} className="text-slate-400" />
              Load Profile
            </h3>
            <div className="flex gap-2">
              <select
                className={`flex-1 ${selectClass}`}
                style={{ background: '#05080d' }}
                value={selectedProfileId}
                onChange={e => { setSelectedProfileId(e.target.value); setShowSchedule(false) }}
              >
                <option value="">Select profile...</option>
                {profiles.map(p => (
                  <option key={p.id} value={p.id}>
                    {p.schedule ? '⏰ ' : ''}{p.name}
                  </option>
                ))}
              </select>
              <button
                onClick={() => applyProfile(selectedProfileId)}
                disabled={!selectedProfileId}
                className="px-3 py-2 rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white text-sm transition-colors flex items-center gap-1"
              >
                <ChevronRight size={14} />
              </button>
              <button
                onClick={() => {
                  const p = profiles.find(p => p.id === selectedProfileId)
                  setScheduleCron(p?.schedule || '')
                  setShowSchedule(s => !s)
                }}
                disabled={!selectedProfileId}
                className="px-3 py-2 rounded border border-cyan-900/30 disabled:opacity-40 text-slate-400 hover:text-cyan-400 hover:border-cyan-700/50 text-sm transition-colors"
                title="Schedule"
              >
                <Clock size={14} />
              </button>
            </div>

            {/* Schedule panel */}
            {showSchedule && selectedProfileId && (() => {
              const prof = profiles.find(p => p.id === selectedProfileId)
              return (
                <div className="mt-3 pt-3 border-t border-cyan-900/20 space-y-2">
                  <div className="text-xs text-slate-400 flex items-center justify-between">
                    <span className="flex items-center gap-1"><Clock size={10} /> Schedule (cron)</span>
                    <button onClick={() => setShowSchedule(false)} className="text-slate-600 hover:text-slate-400"><X size={11} /></button>
                  </div>
                  {/* Quick presets */}
                  <div className="flex flex-wrap gap-1">
                    {[['Daily 2am','0 2 * * *'],['Weekly Sun','0 2 * * 0'],['Hourly','0 * * * *']].map(([label, expr]) => (
                      <button key={label} onClick={() => setScheduleCron(expr)}
                        className="text-[10px] px-1.5 py-0.5 rounded border border-cyan-900/30 text-slate-500 hover:text-cyan-400 hover:border-cyan-700/40 transition-colors">
                        {label}
                      </button>
                    ))}
                  </div>
                  <input
                    value={scheduleCron}
                    onChange={e => setScheduleCron(e.target.value)}
                    placeholder="0 2 * * *"
                    className="w-full rounded px-2 py-1.5 text-xs font-mono text-slate-200 border border-cyan-900/20 focus:outline-none focus:border-cyan-500/50 bg-[#05080d]"
                  />
                  {prof?.last_run && <div className="text-[10px] text-slate-500">Last run: {new Date(prof.last_run).toLocaleString()}</div>}
                  {prof?.next_run && <div className="text-[10px] text-slate-500">Next run: {new Date(prof.next_run).toLocaleString()}</div>}
                  <div className="flex gap-2">
                    <button onClick={handleSaveSchedule} disabled={savingSchedule || !scheduleCron}
                      className="flex-1 py-1 rounded bg-cyan-700 hover:bg-cyan-600 disabled:opacity-40 text-xs text-white transition-colors">
                      {savingSchedule ? 'Saving...' : 'Save'}
                    </button>
                    {prof?.schedule && (
                      <button onClick={handleClearSchedule}
                        className="px-2 py-1 rounded border border-red-900/40 text-xs text-red-400 hover:bg-red-950/30 transition-colors">
                        Clear
                      </button>
                    )}
                  </div>
                </div>
              )
            })()}
          </div>
        )}

        {/* Scan Categories */}
        <div className="glass rounded-xl overflow-hidden flex-1 flex flex-col min-h-0">
          <div className="px-4 py-3 border-b border-cyan-900/20 flex-shrink-0">
            <h3 className="text-sm font-semibold text-slate-200">Scan Categories</h3>
          </div>
          <div className="divide-y divide-cyan-900/10 overflow-y-auto flex-1">
            {Object.entries(categories).map(([id, cat]) => {
              const isSelected = selectedCategories.has(id)
              const isExpanded = expandedCategory === id
              const toolsAvailable = cat.tools.length === 0 || cat.tools.some(t => toolStatus[t]?.available)

              return (
                <div key={id} className={`${!toolsAvailable ? 'opacity-50' : ''}`}>
                  <div
                    className={`flex items-center gap-3 px-4 py-3 cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-cyan-900/10 border-l-2 border-l-cyan-500/40'
                        : 'hover:bg-cyan-950/10'
                    }`}
                    onClick={() => toggleCategory(id)}
                  >
                    <div className={`${isSelected ? 'text-cyan-400' : 'text-slate-500'}`}>
                      {isSelected ? <CheckSquare size={16} /> : <Square size={16} />}
                    </div>
                    <div className={`${isSelected ? 'text-cyan-400' : 'text-slate-400'}`}>
                      {CATEGORY_ICONS[id]}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-slate-200">{cat.name}</div>
                      <div className="text-xs text-slate-400 truncate">{cat.description}</div>
                    </div>
                    <button
                      onClick={e => {
                        e.stopPropagation()
                        setExpandedCategory(isExpanded ? null : id)
                      }}
                      className="text-slate-500 hover:text-slate-300 p-1"
                    >
                      {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                    </button>
                  </div>

                  {isExpanded && (
                    <div className="px-4 pb-4 border-t border-cyan-900/10" style={{ background: 'rgba(5,8,13,0.5)' }}>
                      {/* Control mappings */}
                      <div className="mt-3 mb-3">
                        <div className="text-xs text-slate-400 mb-1">Control Mappings</div>
                        <div className="flex flex-wrap gap-1">
                          {cat.control_mappings.map(m => (
                            <span
                              key={`${m.framework}-${m.control_id}`}
                              className="text-xs px-2 py-0.5 rounded text-slate-400 border border-cyan-900/20"
                              style={{ background: '#0d1520' }}
                              title={m.title}
                            >
                              {m.framework === 'NIST_800_53' ? 'NIST ' : 'CIS '}{m.control_id}
                            </span>
                          ))}
                        </div>
                      </div>
                      {/* Config fields */}
                      <div className="space-y-3">
                        {Object.entries(cat.config_schema).map(([key, schema]) => (
                          <div key={key}>
                            <label className="text-xs text-slate-400 mb-1 block capitalize">
                              {key.replace(/_/g, ' ')}
                            </label>
                            {renderConfigField(id, key, schema)}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* Generate Button */}
        <button
          onClick={handleGenerate}
          disabled={generating || selectedCategories.size === 0 || !selectedTarget}
          className="w-full py-3 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white font-semibold transition-all flex items-center justify-center gap-2 hover:shadow-glow-blue"
        >
          {generating ? (
            <><RefreshCw size={16} className="animate-spin" /> Generating...</>
          ) : (
            <><Play size={16} /> Generate Script</>
          )}
        </button>

        {/* Save Profile */}
        {selectedCategories.size > 0 && (
          <div className="glass glass-hover rounded-xl p-4">
            {!showProfileSave ? (
              <button
                onClick={() => setShowProfileSave(true)}
                className="w-full flex items-center justify-center gap-2 text-sm text-slate-400 hover:text-slate-200 transition-colors"
              >
                <BookMarked size={14} />
                Save as Profile
              </button>
            ) : (
              <div className="space-y-2">
                <label className="text-xs text-slate-400">Profile Name</label>
                <input
                  type="text"
                  value={profileName}
                  onChange={e => setProfileName(e.target.value)}
                  placeholder="e.g. Linux Full Audit"
                  className="w-full rounded px-3 py-2 text-sm text-slate-200 focus:outline-none border border-cyan-900/20 focus:border-cyan-500/50"
                  style={{ background: '#05080d' }}
                  autoFocus
                  onKeyDown={e => { if (e.key === 'Enter') handleSaveProfile() }}
                />
                <div className="flex gap-2">
                  <button
                    onClick={() => { setShowProfileSave(false); setProfileName('') }}
                    className="flex-1 py-1.5 rounded text-sm text-slate-400 hover:text-slate-200 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSaveProfile}
                    disabled={savingProfile || !profileName.trim()}
                    className="flex-1 py-1.5 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-sm text-white font-medium transition-colors"
                  >
                    {savingProfile ? 'Saving...' : 'Save'}
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Right Panel */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Tab Bar + Actions */}
        <div className="flex items-center justify-between mb-3">
          <div className="flex gap-1 glass rounded-lg p-1">
            {(['preview', 'terminal', 'compliance'] as const).map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-4 py-1.5 rounded text-sm font-medium transition-colors capitalize ${
                  activeTab === tab
                    ? 'bg-blue-600 text-white shadow-glow-blue'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab === 'compliance' ? <span className="flex items-center gap-1"><Shield size={12} />Compliance</span> : tab}
              </button>
            ))}
          </div>

          {generatedScript && (
            <div className="flex gap-2">
              <button
                onClick={handleDownload}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg glass glass-hover text-sm text-slate-300 transition-colors"
              >
                <Download size={14} /> Download
              </button>
              <button
                onClick={handleRunOnServer}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-green-600 hover:bg-green-500 text-sm text-white font-medium transition-all hover:shadow-glow-green"
              >
                <Play size={14} /> Run on Server
              </button>
            </div>
          )}
        </div>

        {/* Content */}
        <div className="flex-1 min-h-0 overflow-y-auto">
          {activeTab === 'preview' ? (
            <ScriptPreview
              script={generatedScript}
              className="h-full"
            />
          ) : activeTab === 'terminal' ? (
            <Terminal
              ref={terminalRef}
              className="h-full rounded-xl overflow-hidden border border-cyan-900/20 shadow-glow-cyan"
            />
          ) : (
            /* ── Compliance Tab ─────────────────────────────────────── */
            <div className="space-y-4 pb-6">
              {/* Profile Selector */}
              <div className="glass rounded-xl p-5">
                <h3 className="text-sm font-semibold text-slate-200 mb-1 flex items-center gap-2">
                  <Shield size={14} className="text-cyan-400" /> Hardening Profile
                </h3>
                <p className="text-xs text-slate-500 mb-4">Select a compliance framework, then run an audit with the recommended categories and click Score.</p>
                <div className="grid grid-cols-3 gap-3 mb-4">
                  {hardeningProfiles.map(p => (
                    <button
                      key={p.id}
                      onClick={() => setSelectedHardeningProfile(p.id)}
                      className={`rounded-lg p-3 text-left border transition-all ${
                        selectedHardeningProfile === p.id
                          ? 'border-cyan-500/50 bg-cyan-500/10'
                          : 'border-cyan-900/20 hover:border-cyan-900/40'
                      }`}
                    >
                      <div className="text-sm font-semibold text-slate-200 mb-1">{p.name}</div>
                      <div className="text-[10px] text-slate-500 leading-snug">{p.description}</div>
                      <div className="mt-2 text-[10px] text-cyan-500 font-mono">{p.controls?.length} controls</div>
                    </button>
                  ))}
                </div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={handleScoreScan}
                    disabled={scoring || !scanId}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white text-sm font-semibold transition-all"
                  >
                    {scoring ? <RefreshCw size={13} className="animate-spin" /> : <Gauge size={13} />}
                    {scoring ? 'Scoring...' : 'Score Scan'}
                  </button>
                  {!scanId && <span className="text-xs text-slate-500">Generate and run a scan first, then score it.</span>}
                  {scoreError && <span className="text-xs text-red-400">{scoreError}</span>}
                </div>
              </div>

              {/* Score Results */}
              {complianceReport && (
                <>
                  {/* Score Card */}
                  <div className="glass rounded-xl p-5">
                    <div className="flex items-center justify-between mb-4">
                      <div>
                        <div className="text-xs text-slate-500 mb-1">{complianceReport.profile}</div>
                        <div className="text-2xl font-bold text-slate-100">
                          {complianceReport.overall_score}
                          <span className="text-lg text-slate-500">/100</span>
                        </div>
                        <div className="text-xs text-slate-400 mt-0.5">Hardening Score</div>
                      </div>
                      <div className="flex gap-6">
                        <div className="text-center">
                          <div className="text-xl font-bold text-green-400">{complianceReport.pass_count}</div>
                          <div className="text-[10px] text-slate-500">Passed</div>
                        </div>
                        <div className="text-center">
                          <div className="text-xl font-bold text-red-400">{complianceReport.fail_count}</div>
                          <div className="text-[10px] text-slate-500">Failed</div>
                        </div>
                      </div>
                    </div>
                    {/* Score bar */}
                    <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                      <div
                        className="h-full rounded-full transition-all duration-700"
                        style={{
                          width: `${complianceReport.overall_score}%`,
                          background: complianceReport.overall_score >= 70
                            ? '#22c55e'
                            : complianceReport.overall_score >= 50
                            ? '#f59e0b'
                            : '#ef4444',
                        }}
                      />
                    </div>
                  </div>

                  {/* Controls */}
                  <div className="glass rounded-xl p-4">
                    <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3">Controls</h4>
                    <div className="space-y-1.5">
                      {complianceReport.controls.map((ctrl: any) => (
                        <div key={ctrl.id} className="flex items-center gap-3 px-3 py-2 rounded-lg" style={{ background: 'var(--bg-surface-2)' }}>
                          {ctrl.status === 'pass'
                            ? <CheckCircle size={13} className="text-green-400 shrink-0" />
                            : <XCircle size={13} className="text-red-400 shrink-0" />}
                          <span className="text-[10px] font-mono text-slate-500 shrink-0 w-16">{ctrl.id}</span>
                          <span className="text-xs text-slate-300">{ctrl.title}</span>
                          <span className={`ml-auto text-[10px] font-semibold ${ctrl.status === 'pass' ? 'text-green-400' : 'text-red-400'}`}>
                            {ctrl.status.toUpperCase()}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Warnings */}
                  {complianceReport.warnings.length > 0 && (
                    <div className="glass rounded-xl p-4">
                      <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3 flex items-center gap-1">
                        <AlertTriangle size={11} className="text-amber-400" /> Warnings ({complianceReport.warnings.length})
                      </h4>
                      <div className="space-y-1 max-h-48 overflow-y-auto">
                        {complianceReport.warnings.map((w: string, i: number) => (
                          <div key={i} className="text-xs font-mono text-amber-300/80 py-0.5 border-b border-amber-900/10">{w}</div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Suggestions */}
                  {complianceReport.suggestions.length > 0 && (
                    <div className="glass rounded-xl p-4">
                      <h4 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3">Suggestions</h4>
                      <div className="space-y-1.5">
                        {complianceReport.suggestions.map((s: string, i: number) => (
                          <div key={i} className="flex items-start gap-2 text-xs text-slate-400">
                            <ChevronRight size={11} className="text-cyan-600 shrink-0 mt-0.5" />
                            <span>{s}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
