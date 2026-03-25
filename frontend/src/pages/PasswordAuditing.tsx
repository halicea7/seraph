import { useState, useEffect, useRef } from 'react'
import { Lock, Upload, Play, RefreshCw, Check, KeyRound, ShieldAlert } from 'lucide-react'
import Terminal, { TerminalHandle } from '../components/Terminal'
import type { Project, Credential } from '../types/index'

interface ToolInfo {
  available: boolean
}

interface ToolsResponse {
  hashcat: ToolInfo
  john: ToolInfo
  hash_types: { id: string; label: string }[]
  john_formats: { id: string; label: string }[]
  wordlists: string[]
}

interface CrackedPair {
  hash: string
  plain: string
}

const ATTACK_MODES = [
  { id: '0', label: 'Wordlist (dictionary)' },
  { id: '3', label: 'Brute-force (mask)' },
  { id: '6', label: 'Hybrid (wordlist + mask)' },
]

export default function PasswordAuditing() {
  const [tools, setTools] = useState<ToolsResponse | null>(null)
  const [tool, setTool] = useState<'hashcat' | 'john'>('hashcat')
  const [hashType, setHashType] = useState('0')
  const [attackMode, setAttackMode] = useState('0')
  const [wordlist, setWordlist] = useState('')
  const [customWordlist, setCustomWordlist] = useState('')
  const [mask, setMask] = useState('?d?d?d?d?d?d?d?d')
  const [hashInput, setHashInput] = useState('')
  const [running, setRunning] = useState(false)
  const [, setJobId] = useState<string | null>(null)

  // Vault loading
  const [projects, setProjects] = useState<Project[]>([])
  const [selectedProject, setSelectedProject] = useState('')
  const [vaultCreds, setVaultCreds] = useState<Credential[]>([])
  const [selectedCredIds, setSelectedCredIds] = useState<string[]>([])

  // Results
  const [results, setResults] = useState<{ cracked: number; pairs: CrackedPair[]; vault_updated: number } | null>(null)
  const [savedPairs, setSavedPairs] = useState<Set<string>>(new Set())

  const terminalRef = useRef<TerminalHandle>(null)

  useEffect(() => {
    fetch('/api/v1/cracking/tools').then(r => r.json()).then(data => {
      setTools(data)
      if (data.wordlists.length > 0) setWordlist(data.wordlists[0])
    })
    fetch('/api/v1/projects').then(r => r.json()).then(setProjects)
  }, [])

  useEffect(() => {
    if (selectedProject) {
      fetch(`/api/v1/credentials?project_id=${selectedProject}`)
        .then(r => r.json())
        .then((data: Credential[]) => setVaultCreds(data.filter(c => c.cred_type === 'hash')))
    }
  }, [selectedProject])

  function loadFromVault() {
    const selected = vaultCreds.filter(c => selectedCredIds.includes(c.id))
    if (selected.length === 0) return
    setHashInput(selected.map(c => c.secret).join('\n'))
  }

  function toggleCredId(id: string) {
    setSelectedCredIds(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id])
  }

  function getHashes(): string[] {
    return hashInput.split('\n').map(h => h.trim()).filter(Boolean)
  }

  function buildCommandPreview(): string {
    const hashes = getHashes()
    if (!hashes.length) return '# paste hashes above'
    const wl = customWordlist || wordlist || '/path/to/wordlist.txt'
    if (tool === 'hashcat') {
      const atk = attackMode === '3' ? mask : wl
      return `hashcat -m ${hashType} -a ${attackMode} hashes.txt ${atk} --outfile cracked.txt --force`
    } else {
      const fmtFlag = hashType !== 'auto' ? `--format=${hashType} ` : ''
      return `john ${fmtFlag}--wordlist=${wl} hashes.txt`
    }
  }

  async function handleRun() {
    const hashes = getHashes()
    if (!hashes.length) { alert('Paste at least one hash.'); return }
    const wl = customWordlist || wordlist
    if (!wl && attackMode !== '3') { alert('Select or enter a wordlist.'); return }

    setRunning(true)
    setResults(null)

    const res = await fetch('/api/v1/cracking/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: selectedProject,
        tool,
        hashes,
        hash_type: hashType,
        attack_mode: attackMode,
        wordlist: wl,
        mask,
        credential_ids: selectedCredIds,
      }),
    })

    if (!res.ok) {
      const err = await res.json()
      alert(err.detail || 'Failed to start job')
      setRunning(false)
      return
    }

    const { job_id } = await res.json()
    setJobId(job_id)

    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${wsProto}//${window.location.host}/ws/cracking/${job_id}`)

    ws.onopen = () => {
      terminalRef.current?.writeln(`\x1b[33m[*] Starting ${tool}...\x1b[0m`)
      terminalRef.current?.writeln(`\x1b[33m[*] ${hashes.length} hash(es) to crack\x1b[0m\r\n`)
    }

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data)
      if (msg.type === 'stdout') {
        terminalRef.current?.write(msg.data)
      } else if (msg.type === 'stderr') {
        terminalRef.current?.write('\x1b[33m' + msg.data + '\x1b[0m')
      } else if (msg.type === 'exit') {
        const color = msg.code === 0 || msg.code === 1 ? '\x1b[32m' : '\x1b[31m'
        terminalRef.current?.writeln(`${color}\r\n[*] Tool exited (code ${msg.code})\x1b[0m`)
      } else if (msg.type === 'results') {
        setResults({ cracked: msg.cracked, pairs: msg.pairs, vault_updated: msg.vault_updated })
        terminalRef.current?.writeln(
          `\x1b[36m\r\n[+] Cracked: ${msg.cracked} | Vault updated: ${msg.vault_updated}\x1b[0m`
        )
        setRunning(false)
      } else if (msg.type === 'error') {
        terminalRef.current?.writeln(`\x1b[31m[ERROR] ${msg.data}\x1b[0m`)
        setRunning(false)
      }
    }

    ws.onerror = () => {
      terminalRef.current?.writeln('\x1b[31m[!] WebSocket error\x1b[0m')
      setRunning(false)
    }
  }

  async function saveToVault(pair: CrackedPair) {
    if (!selectedProject) return
    await fetch('/api/v1/credentials', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: selectedProject,
        username: '',
        secret: pair.plain,
        cred_type: 'password',
        source: 'brute_force',
        target_host: '',
        notes: `Cracked from hash: ${pair.hash}`,
      }),
    })
    setSavedPairs(prev => new Set([...prev, pair.hash]))
  }

  const selectClass = "w-full rounded px-3 py-2 text-xs text-slate-200 focus:outline-none border border-cyan-900/20 focus:border-cyan-500/50 bg-[#05080d]"
  const hashTypes = tool === 'hashcat' ? (tools?.hash_types || []) : (tools?.john_formats || [])

  return (
    <div className="flex h-full gap-4 min-h-0">
      {/* Left: Config */}
      <div className="w-64 flex-shrink-0 flex flex-col gap-4 overflow-y-auto min-h-0">
        {/* Tool selector */}
        <div className="glass glass-hover rounded-xl p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Tool</h3>
          <div className="flex gap-2">
            {(['hashcat', 'john'] as const).map(t => (
              <button
                key={t}
                onClick={() => { setTool(t); setHashType(t === 'hashcat' ? '0' : 'auto') }}
                className={`flex-1 py-1.5 rounded text-xs font-mono font-semibold transition-all ${
                  tool === t ? 'bg-cyan-700 text-white' : 'border border-cyan-900/30 text-slate-400 hover:text-cyan-400'
                }`}
              >
                {t}
              </button>
            ))}
          </div>

          {/* Tool availability */}
          {tools && (
            <div className="mt-2 flex gap-3">
              {(['hashcat', 'john'] as const).map(t => (
                <div key={t} className="flex items-center gap-1 text-[10px]">
                  <span className={`w-1.5 h-1.5 rounded-full ${tools[t].available ? 'bg-green-400' : 'bg-red-500'}`} />
                  <span className="text-slate-500 font-mono">{t}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Hash type */}
        <div className="glass glass-hover rounded-xl p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
            {tool === 'hashcat' ? 'Hash Type (-m)' : 'Format'}
          </h3>
          <select value={hashType} onChange={e => setHashType(e.target.value)} className={selectClass}>
            {hashTypes.map(h => <option key={h.id} value={h.id}>{h.label}</option>)}
          </select>
        </div>

        {/* Attack mode (hashcat only) */}
        {tool === 'hashcat' && (
          <div className="glass glass-hover rounded-xl p-4">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Attack Mode (-a)</h3>
            <select value={attackMode} onChange={e => setAttackMode(e.target.value)} className={selectClass}>
              {ATTACK_MODES.map(m => <option key={m.id} value={m.id}>{m.label}</option>)}
            </select>
            {attackMode === '3' && (
              <div className="mt-2">
                <label className="text-[10px] text-slate-500 mb-1 block">Mask</label>
                <input value={mask} onChange={e => setMask(e.target.value)} className={selectClass} placeholder="?d?d?d?d?d?d?d?d" />
                <div className="mt-1 text-[10px] text-slate-600">?l=lower ?u=upper ?d=digit ?s=special ?a=all</div>
              </div>
            )}
          </div>
        )}

        {/* Wordlist */}
        {attackMode !== '3' && (
          <div className="glass glass-hover rounded-xl p-4">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Wordlist</h3>
            {tools && tools.wordlists.length > 0 && (
              <select value={wordlist} onChange={e => setWordlist(e.target.value)} className={`${selectClass} mb-2`}>
                <option value="">Select wordlist...</option>
                {tools.wordlists.map(w => <option key={w} value={w}>{w.split('/').pop()}</option>)}
              </select>
            )}
            <input
              value={customWordlist}
              onChange={e => setCustomWordlist(e.target.value)}
              className={selectClass}
              placeholder="Custom path..."
            />
          </div>
        )}

        {/* Load from vault */}
        <div className="glass rounded-xl p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-1">
            <KeyRound size={10} /> Load from Vault
          </h3>
          <select value={selectedProject} onChange={e => setSelectedProject(e.target.value)} className={`${selectClass} mb-2`}>
            <option value="">Select project...</option>
            {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          {vaultCreds.length > 0 ? (
            <>
              <div className="space-y-1 max-h-32 overflow-y-auto mb-2">
                {vaultCreds.map(c => (
                  <label key={c.id} className="flex items-center gap-2 cursor-pointer group">
                    <input
                      type="checkbox"
                      checked={selectedCredIds.includes(c.id)}
                      onChange={() => toggleCredId(c.id)}
                      className="accent-cyan-500"
                    />
                    <span className="text-[10px] font-mono text-slate-400 truncate group-hover:text-slate-200">{c.secret.slice(0, 24)}…</span>
                  </label>
                ))}
              </div>
              <button
                onClick={loadFromVault}
                disabled={selectedCredIds.length === 0}
                className="w-full py-1.5 rounded border border-cyan-900/30 text-xs text-cyan-400 hover:bg-cyan-950/30 disabled:opacity-40 transition-all flex items-center justify-center gap-1"
              >
                <Upload size={11} /> Load {selectedCredIds.length || ''} hash{selectedCredIds.length !== 1 ? 'es' : ''}
              </button>
            </>
          ) : (
            <p className="text-[10px] text-slate-600 italic">{selectedProject ? 'No hash-type credentials in this project' : 'Select a project'}</p>
          )}
        </div>
      </div>

      {/* Center: hash input + command + results */}
      <div className="flex-1 flex flex-col min-w-0 gap-4 overflow-y-auto">
        <div>
          <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
            <Lock size={18} className="text-cyan-400" /> Password Auditing
          </h2>
          <p className="text-sm text-slate-400">hashcat / john the ripper — cracked plaintexts saved back to Credential Vault</p>
        </div>

        {/* Hash input */}
        <div className="glass rounded-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Hashes (one per line)</label>
            <span className="text-[10px] text-slate-500 font-mono">{getHashes().length} hash{getHashes().length !== 1 ? 'es' : ''}</span>
          </div>
          <textarea
            value={hashInput}
            onChange={e => setHashInput(e.target.value)}
            rows={6}
            placeholder="5f4dcc3b5aa765d61d8327deb882cf99&#10;098f6bcd4621d373cade4e832627b4f6&#10;..."
            className="w-full rounded px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none border border-cyan-900/20 focus:border-cyan-500/50 resize-none bg-[#05080d]"
          />
        </div>

        {/* Command preview */}
        <div className="glass rounded-xl p-4">
          <label className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 block">Command Preview</label>
          <div className="font-mono text-xs text-slate-300 rounded px-3 py-2 border border-cyan-900/20 break-all bg-[#05080d]">
            {buildCommandPreview()}
          </div>
          <button
            onClick={handleRun}
            disabled={running || !getHashes().length}
            className="mt-3 w-full py-2.5 rounded-lg bg-green-600 hover:bg-green-500 disabled:opacity-40 text-sm text-white font-semibold transition-all hover:shadow-glow-green flex items-center justify-center gap-2"
          >
            {running ? <><RefreshCw size={15} className="animate-spin" /> Cracking...</> : <><Play size={15} /> Start Cracking</>}
          </button>
        </div>

        {/* Results */}
        {results && (
          <div className="glass rounded-xl p-4">
            <div className="flex items-center gap-3 mb-3">
              <ShieldAlert size={14} className="text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-200">Results</h3>
              <span className="text-xs px-2 py-0.5 rounded-full bg-green-950/60 text-green-400 border border-green-700/30 font-semibold">
                {results.cracked} cracked
              </span>
              {results.vault_updated > 0 && (
                <span className="text-xs px-2 py-0.5 rounded-full bg-cyan-950/60 text-cyan-400 border border-cyan-700/30 font-semibold">
                  {results.vault_updated} vault updated
                </span>
              )}
            </div>

            {results.pairs.length === 0 ? (
              <p className="text-xs text-slate-500 italic">No hashes cracked in this run.</p>
            ) : (
              <div className="space-y-1">
                {results.pairs.map((pair, i) => (
                  <div key={i} className="flex items-center gap-3 px-3 py-1.5 rounded border border-cyan-900/10 hover:bg-cyan-950/10 transition-colors group">
                    <span className="font-mono text-[10px] text-slate-500 truncate w-48 flex-shrink-0">{pair.hash}</span>
                    <span className="text-slate-600 text-xs">→</span>
                    <span className="font-mono text-sm text-green-400 font-semibold flex-1">{pair.plain}</span>
                    {selectedProject && !savedPairs.has(pair.hash) && (
                      <button
                        onClick={() => saveToVault(pair)}
                        className="opacity-0 group-hover:opacity-100 text-[10px] text-cyan-500 hover:text-cyan-300 border border-cyan-900/30 px-2 py-0.5 rounded transition-all"
                      >
                        Save to Vault
                      </button>
                    )}
                    {savedPairs.has(pair.hash) && (
                      <Check size={12} className="text-green-500 flex-shrink-0" />
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Right: Terminal */}
      <div className="w-96 flex-shrink-0 flex flex-col">
        <div className="mb-3">
          <h3 className="text-sm font-semibold text-slate-200">Live Output</h3>
        </div>
        <Terminal
          ref={terminalRef}
          className="flex-1 rounded-xl overflow-hidden border border-cyan-900/20 shadow-glow-cyan"
        />
      </div>
    </div>
  )
}
