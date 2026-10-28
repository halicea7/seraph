import { useState, useEffect, useRef } from 'react'
import { useLocation } from 'react-router-dom'
import Icon from '../components/Icon'
import EmptyState from '@/components/EmptyState'
import type { Credential } from '../types/index'
import { getApiBase, wsUrl } from '@/lib/config'
import { useAppStore } from '@/stores/appStore'
import { useToast } from '@/contexts/ToastContext'

// ── Types ─────────────────────────────────────────────────────────────────────

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

interface WordlistBundle {
  id: string
  label: string
  description: string
  dest: string
  installed: boolean
}

interface CrackedPair {
  hash: string
  plain: string
}

interface Job {
  id: string
  name: string
  mode: string
  hashes: number
  state: 'active' | 'queued' | 'done' | 'failed'
  recovered: number
  progress: number
}

// ── Static data ───────────────────────────────────────────────────────────────

const ATTACK_MODES = [
  { id: '0', label: 'Wordlist (dictionary)' },
  { id: '3', label: 'Brute-force (mask)' },
  { id: '6', label: 'Hybrid (wordlist + mask)' },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

const rule = '1px solid var(--rule)'
const ruleStrong = '1px solid var(--rule-strong)'

const selStyle: React.CSSProperties = {
  width: '100%',
  boxSizing: 'border-box',
  background: 'var(--bg)',
  border: ruleStrong,
  borderRadius: 3,
  padding: '5px 8px',
  fontSize: 12,
  color: 'var(--fg)',
  fontFamily: 'var(--font-sans)',
  outline: 'none',
}

function Section({ title, right, children }: { title: string; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="rule">
      <div className="sec-h" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span className="title">{title}</span>
        {right && <span>{right}</span>}
      </div>
      {children}
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label style={{ display: 'block', marginBottom: 6, fontSize: 10, color: 'var(--fg-3)', textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: 'var(--font-mono)' }}>{label}</label>
      {children}
    </div>
  )
}

function PageHeader({ title, sub, right }: { title: string; sub: string; right?: React.ReactNode }) {
  return (
    <div style={{ borderBottom: rule, padding: '24px var(--pad) 18px', display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: 16, flexShrink: 0 }}>
      <div>
        <h1 className="mono" style={{ margin: 0, fontWeight: 500, fontSize: 22, letterSpacing: '-0.01em' }}>{title}</h1>
        <div style={{ color: 'var(--fg-3)', fontSize: 12, marginTop: 6 }}>{sub}</div>
      </div>
      {right && <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexShrink: 0 }}>{right}</div>}
    </div>
  )
}

function StatePill({ state }: { state: Job['state'] }) {
  const map: Record<Job['state'], { color: string; bg: string; border: string }> = {
    active: { color: 'var(--ok)',     bg: 'rgba(84,175,97,0.1)',   border: 'rgba(84,175,97,0.3)' },
    queued: { color: 'var(--accent)', bg: 'rgba(240,168,58,0.08)', border: 'rgba(240,168,58,0.25)' },
    done:   { color: 'var(--fg-3)',   bg: 'rgba(100,116,139,0.1)', border: 'rgba(100,116,139,0.2)' },
    failed: { color: 'var(--crit)',   bg: 'rgba(232,64,64,0.08)',  border: 'rgba(232,64,64,0.3)'  },
  }
  const s = map[state]
  return (
    <span className="mono" style={{ fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.12em', padding: '1px 6px', color: s.color, background: s.bg, border: `1px solid ${s.border}` }}>
      {state}
    </span>
  )
}

function ProgressBar({ pct }: { pct: number }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 4, background: 'var(--bg)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: 'var(--accent)', borderRadius: 2 }} />
      </div>
      <span className="mono tnum" style={{ fontSize: 10, color: 'var(--fg-3)', width: 32, textAlign: 'right' }}>{pct}%</span>
    </div>
  )
}

// ── Main ──────────────────────────────────────────────────────────────────────

export default function PasswordAuditing() {
  const { selectedProject: sp } = useAppStore()
  const projectId = sp?.id ?? ''
  const toast = useToast()
  const location = useLocation()

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

  const [vaultCreds, setVaultCreds] = useState<Credential[]>([])
  const [selectedCredIds, setSelectedCredIds] = useState<string[]>([])

  const [results, setResults] = useState<{ cracked: number; pairs: CrackedPair[]; vault_updated: number } | null>(null)
  const [savedPairs, setSavedPairs] = useState<Set<string>>(new Set())

  const [bundles, setBundles] = useState<WordlistBundle[]>([])
  const [installing, setInstalling] = useState<string | null>(null)
  const [installLog, setInstallLog] = useState<Record<string, string>>({})

  const [jobs, setJobs] = useState<Job[]>([])
  const [loadingJobs, setLoadingJobs] = useState(false)

  const [liveOutput, setLiveOutput] = useState('')
  const outputRef = useRef<HTMLDivElement>(null)

  interface CrackingServer { id: string; name: string; host: string; port: number; ssh_user: string; remote_workdir: string }
  interface SshKeyCredential { id: string; username: string; notes: string }
  const [crackingServers, setCrackingServers] = useState<CrackingServer[]>([])
  const [selectedServerId, setSelectedServerId] = useState('')
  const [remoteWordlist, setRemoteWordlist] = useState('')
  const [serversOpen, setServersOpen] = useState(false)
  const [srvFormName, setSrvFormName] = useState('')
  const [srvFormHost, setSrvFormHost] = useState('')
  const [srvFormPort, setSrvFormPort] = useState('22')
  const [srvFormUser, setSrvFormUser] = useState('root')
  const [srvFormWorkdir, setSrvFormWorkdir] = useState('/tmp/seraph_crack')
  const [srvFormKeyCredId, setSrvFormKeyCredId] = useState('')
  const [sshKeyCredentials, setSshKeyCredentials] = useState<SshKeyCredential[]>([])
  const [savingSrv, setSavingSrv] = useState(false)
  const [srvError, setSrvError] = useState('')

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [liveOutput])

  // KPI state (derived from live jobs)
  const recovered = jobs.reduce((a, j) => a + j.recovered, 0)
  const inQueue   = jobs.filter(j => j.state === 'queued').reduce((a, j) => a + j.hashes, 0)
  const activeCount = jobs.filter(j => j.state === 'active').length

  async function loadJobs() {
    if (!projectId) return
    setLoadingJobs(true)
    try {
      const res = await fetch(`${getApiBase()}/cracking/jobs?project_id=${projectId}`)
      if (res.ok) {
        const data = await res.json()
        setJobs(Array.isArray(data) ? data : data.jobs ?? [])
      }
    } catch {
      // keep empty
    } finally {
      setLoadingJobs(false)
    }
  }

  function loadBundles() {
    fetch(`${getApiBase()}/cracking/wordlists/available`).then(r => r.json()).then(setBundles)
  }

  function loadCrackingServers() {
    fetch(`${getApiBase()}/cracking/servers`).then(r => r.json()).then(data => {
      if (Array.isArray(data)) setCrackingServers(data)
    }).catch(() => {})
  }

  function loadSshCredentials() {
    fetch(`${getApiBase()}/credentials`).then(r => r.json()).then((data: any[]) => {
      if (Array.isArray(data)) setSshKeyCredentials(data.filter(c => c.cred_type === 'key').map(c => ({ id: c.id, username: c.username, notes: c.notes || '' })))
    }).catch(() => {})
  }

  async function handleAddServer() {
    if (!srvFormName || !srvFormHost) { setSrvError('Name and host are required.'); return }
    setSavingSrv(true); setSrvError('')
    try {
      const res = await fetch(`${getApiBase()}/cracking/servers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: srvFormName, host: srvFormHost, port: parseInt(srvFormPort) || 22, ssh_user: srvFormUser, remote_workdir: srvFormWorkdir, key_credential_id: srvFormKeyCredId || null }),
      })
      if (!res.ok) { const d = await res.json(); setSrvError(d.detail ?? 'Failed to save'); return }
      loadCrackingServers()
      setSrvFormName(''); setSrvFormHost('')
    } finally { setSavingSrv(false) }
  }

  async function handleDeleteServer(id: string) {
    await fetch(`${getApiBase()}/cracking/servers/${id}`, { method: 'DELETE' })
    if (selectedServerId === id) setSelectedServerId('')
    loadCrackingServers()
  }

  function loadTools() {
    fetch(`${getApiBase()}/cracking/tools`).then(r => r.json()).then(data => {
      setTools(data)
      if (data.wordlists.length > 0) setWordlist(data.wordlists[0])
    })
  }

  useEffect(() => {
    loadTools()
    loadBundles()
    loadCrackingServers()
  }, [])

  useEffect(() => {
    if (projectId) {
      fetch(`${getApiBase()}/credentials?project_id=${projectId}`)
        .then(r => r.json())
        .then((data: Credential[]) => {
          const hashes = data.filter(c => c.cred_type === 'hash')
          setVaultCreds(hashes)
          // Pre-select hashes handed off from the Credential Vault "Send to cracking" action.
          const want = (location.state as { credIds?: string[] } | null)?.credIds
          if (want?.length) setSelectedCredIds(hashes.filter(c => want.includes(c.id)).map(c => c.id))
        })
      loadJobs()
    }
  }, [projectId])

  function installBundle(bundleId: string) {
    if (installing) return
    setInstalling(bundleId)
    setInstallLog(prev => ({ ...prev, [bundleId]: '' }))
    const ws = new WebSocket(wsUrl(`/ws/wordlists/install/${bundleId}`))
    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data)
      if (msg.type === 'stdout' || msg.type === 'stderr') {
        setInstallLog(prev => ({ ...prev, [bundleId]: (prev[bundleId] || '') + msg.data }))
      } else if (msg.type === 'done') {
        setInstalling(null)
        loadBundles()
        loadTools()
      } else if (msg.type === 'error') {
        setInstallLog(prev => ({ ...prev, [bundleId]: (prev[bundleId] || '') + `\n[ERROR] ${msg.data}` }))
        setInstalling(null)
      }
    }
    ws.onerror = () => setInstalling(null)
  }

  async function loadFromVault() {
    const selected = vaultCreds.filter(c => selectedCredIds.includes(c.id))
    if (selected.length === 0) return
    // Credential.secret is never in the list payload — fetch via the
    // audited batch-reveal endpoint right before populating the hash box.
    const res = await fetch(`${getApiBase()}/credentials/reveal-batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: selected.map(c => c.id) }),
    })
    const revealed: { id: string; secret: string }[] = await res.json()
    setHashInput(revealed.map(r => r.secret).join('\n'))
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
    if (!hashes.length) { toast.error('Paste at least one hash.'); return }
    const wl = customWordlist || wordlist
    if (!wl && attackMode !== '3') { toast.error('Select or enter a wordlist.'); return }

    setRunning(true)
    setResults(null)
    setLiveOutput('')

    const res = await fetch(`${getApiBase()}/cracking/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: projectId,
        tool,
        hashes,
        hash_type: hashType,
        attack_mode: attackMode,
        wordlist: wl,
        mask,
        credential_ids: selectedCredIds,
        server_id: selectedServerId || '',
        remote_wordlist: remoteWordlist || '',
      }),
    })

    if (!res.ok) {
      const err = await res.json()
      toast.error(err.detail || 'Failed to start job')
      setRunning(false)
      return
    }

    const { job_id } = await res.json()
    setJobId(job_id)

    const ws = new WebSocket(wsUrl(`/ws/cracking/${job_id}`))

    ws.onopen = () => {
      setLiveOutput(`[*] Starting ${tool}...\n[*] ${hashes.length} hash(es) to crack\n`)
    }

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data)
      if (msg.type === 'stdout') {
        setLiveOutput(prev => prev + msg.data)
      } else if (msg.type === 'stderr') {
        setLiveOutput(prev => prev + msg.data)
      } else if (msg.type === 'exit') {
        setLiveOutput(prev => prev + `\n[*] Tool exited (code ${msg.code})\n`)
      } else if (msg.type === 'results') {
        setResults({ cracked: msg.cracked, pairs: msg.pairs, vault_updated: msg.vault_updated })
        setLiveOutput(prev => prev + `\n[+] Cracked: ${msg.cracked} | Vault updated: ${msg.vault_updated}\n`)
        setRunning(false)
      } else if (msg.type === 'error') {
        setLiveOutput(prev => prev + `\n[ERROR] ${msg.data}\n`)
        setRunning(false)
      }
    }

    ws.onerror = () => {
      setLiveOutput(prev => prev + '\n[!] WebSocket error\n')
      setRunning(false)
    }
  }

  async function saveToVault(pair: CrackedPair) {
    if (!projectId) return
    await fetch(`${getApiBase()}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: projectId,
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

  const hashTypes = tool === 'hashcat' ? (tools?.hash_types || []) : (tools?.john_formats || [])

  return (
    <div className="page-enter" style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg)', color: 'var(--fg)' }}>

      {/* PageHeader */}
      <PageHeader
        title="Password Auditing"
        sub="Local hashcat / John jobs against captured material. Hashes never leave this host."
        right={
          <>
            <button className="btn" onClick={loadFromVault} disabled={selectedCredIds.length === 0} style={{ opacity: selectedCredIds.length === 0 ? 0.4 : 1 }}>
              <Icon name="upload" size={11} color="currentColor" /> Import hashes
            </button>
            <button className="btn btn-primary" onClick={handleRun} disabled={running || !getHashes().length} style={{ opacity: running || !getHashes().length ? 0.5 : 1 }}>
              {running ? <><Icon name="refresh" size={12} color="currentColor" /> Cracking…</> : <><Icon name="play" size={12} color="currentColor" /> New job</>}
            </button>
          </>
        }
      />

      {/* KPI strip */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', borderBottom: rule, flexShrink: 0 }}>
        {[
          { label: 'recovered',       value: String(recovered), color: 'var(--ok)' },
          { label: 'in queue',        value: String(inQueue),   color: 'var(--accent)' },
          { label: 'active jobs',     value: String(activeCount),                                    color: 'var(--ok)' },
          { label: 'total hashes',   value: String(jobs.reduce((a, j) => a + j.hashes, 0)), color: 'var(--fg)' },
        ].map((kpi, i) => (
          <div key={kpi.label} style={{ padding: '18px var(--pad)', borderLeft: i > 0 ? rule : 'none' }}>
            <div className="smcap" style={{ marginBottom: 4 }}>{kpi.label}</div>
            <div className="mono tnum" style={{ fontSize: 30, fontWeight: 500, color: kpi.color }}>{kpi.value}</div>
          </div>
        ))}
      </div>

      {/* Body grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', flex: 1, minHeight: 0 }}>

        {/* Left: Jobs */}
        <div style={{ borderRight: rule, overflowY: 'auto' }}>
          <Section
            title="JOBS"
            right={<span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: 'var(--ok)', fontFamily: 'var(--font-mono)' }}>● {activeCount} active</span>}
          >
            <table className="data">
              <thead>
                <tr>
                  <th style={{ width: 56 }}>Mode</th>
                  <th>Name</th>
                  <th style={{ width: 80 }}>Hashes</th>
                  <th style={{ width: 80 }}>State</th>
                  <th style={{ width: 90 }}>Recovered</th>
                  <th style={{ width: 140 }}>Progress</th>
                </tr>
              </thead>
              <tbody>
                {loadingJobs && jobs.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', color: 'var(--fg-3)', fontSize: 12, padding: '16px 0', fontStyle: 'italic', fontFamily: 'var(--font-sans)' }}>
                      Loading jobs…
                    </td>
                  </tr>
                ) : !loadingJobs && jobs.length === 0 && projectId ? (
                  <tr>
                    <td colSpan={6} style={{ padding: 0 }}>
                      <EmptyState icon="lock" title="No cracking jobs yet" hint="Paste hashes and run a job to start auditing password strength." pad={24} />
                    </td>
                  </tr>
                ) : (
                  jobs.map(job => (
                    <tr key={job.id}>
                      <td><span className="mono tnum" style={{ color: 'var(--accent)', fontSize: 10, textTransform: 'uppercase' }}>{job.mode}</span></td>
                      <td><span className="mono" style={{ fontSize: 12 }}>{job.name}</span></td>
                      <td><span className="mono tnum" style={{ fontSize: 12 }}>{job.hashes}</span></td>
                      <td><StatePill state={job.state} /></td>
                      <td><span className="mono tnum" style={{ color: 'var(--ok)', fontSize: 12 }}>{job.recovered}</span></td>
                      <td><ProgressBar pct={job.progress} /></td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </Section>

          {/* Results */}
          {results && (
            <Section title="RESULTS">
              <div style={{ padding: '0 var(--pad) 16px' }}>
                <div style={{ display: 'flex', gap: 10, marginBottom: 10 }}>
                  <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 10, background: 'rgba(84,175,97,0.1)', color: 'var(--ok)', border: '1px solid rgba(84,175,97,0.3)', fontWeight: 700, fontFamily: 'var(--font-sans)' }}>
                    {results.cracked} cracked
                  </span>
                  {results.vault_updated > 0 && (
                    <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 10, background: 'rgba(240,168,58,0.08)', color: 'var(--accent)', border: '1px solid rgba(240,168,58,0.25)', fontWeight: 700, fontFamily: 'var(--font-sans)' }}>
                      {results.vault_updated} vault updated
                    </span>
                  )}
                </div>
                {results.pairs.length === 0 ? (
                  <p style={{ margin: 0, fontSize: 12, color: 'var(--fg-3)', fontStyle: 'italic', fontFamily: 'var(--font-sans)' }}>No hashes cracked in this run.</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {results.pairs.map((pair, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 10px', borderRadius: 3, border: rule }}>
                        <span className="mono tnum" style={{ fontSize: 10, color: 'var(--fg-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', width: 160, flexShrink: 0 }}>{pair.hash}</span>
                        <span style={{ fontSize: 12, color: 'var(--fg-3)' }}>→</span>
                        <span className="mono" style={{ fontSize: 13, color: 'var(--ok)', fontWeight: 700, flex: 1 }}>{pair.plain}</span>
                        {projectId && !savedPairs.has(pair.hash) && (
                          <button onClick={() => saveToVault(pair)} className="btn btn-sm">Save to Vault</button>
                        )}
                        {savedPairs.has(pair.hash) && <Icon name="check" size={12} color="var(--ok)" />}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Section>
          )}
        </div>

        {/* Right: Config + wordlist */}
        <div style={{ overflowY: 'auto' }}>
          <Section title="WORDLIST + RULE">
            <div style={{ padding: '14px var(--pad)', display: 'flex', flexDirection: 'column', gap: 14 }}>

              {/* Tool selector */}
              <Field label="Tool">
                <div style={{ display: 'flex', gap: 6 }}>
                  {(['hashcat', 'john'] as const).map(t => (
                    <button
                      key={t}
                      onClick={() => { setTool(t); setHashType(t === 'hashcat' ? '0' : 'auto') }}
                      className="mono"
                      style={{
                        flex: 1, padding: '5px 0', borderRadius: 3,
                        background: tool === t ? 'var(--accent)' : 'none',
                        color: tool === t ? 'var(--bg)' : 'var(--fg-3)',
                        border: tool === t ? 'none' : ruleStrong,
                        fontSize: 11, fontWeight: 700, cursor: 'pointer',
                      }}
                    >{t}</button>
                  ))}
                </div>
                {tools && (
                  <div style={{ display: 'flex', gap: 12, marginTop: 6 }}>
                    {(['hashcat', 'john'] as const).map(t => (
                      <div key={t} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: tools[t].available ? 'var(--ok)' : 'var(--crit)', display: 'inline-block' }} />
                        <span className="mono" style={{ color: 'var(--fg-3)' }}>{t}</span>
                      </div>
                    ))}
                  </div>
                )}
              </Field>

              {/* Hash type */}
              <Field label={tool === 'hashcat' ? 'Hash Type (-m)' : 'Format'}>
                <select value={hashType} onChange={e => setHashType(e.target.value)} style={selStyle}>
                  {hashTypes.map(h => <option key={h.id} value={h.id}>{h.label}</option>)}
                </select>
              </Field>

              {/* Attack mode (hashcat only) */}
              {tool === 'hashcat' && (
                <Field label="Attack Mode (-a)">
                  <select value={attackMode} onChange={e => setAttackMode(e.target.value)} style={selStyle}>
                    {ATTACK_MODES.map(m => <option key={m.id} value={m.id}>{m.label}</option>)}
                  </select>
                  {attackMode === '3' && (
                    <div style={{ marginTop: 8 }}>
                      <input value={mask} onChange={e => setMask(e.target.value)} style={{ ...selStyle, marginBottom: 4 }} placeholder="?d?d?d?d?d?d?d?d" />
                      <div className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>?l=lower ?u=upper ?d=digit ?s=special ?a=all</div>
                    </div>
                  )}
                </Field>
              )}

              {/* Run on */}
              <Field label="Run On">
                <select
                  value={selectedServerId}
                  onChange={e => setSelectedServerId(e.target.value)}
                  style={selStyle}
                >
                  <option value="">Local (this machine)</option>
                  {crackingServers.map(s => <option key={s.id} value={s.id}>{s.name} ({s.host})</option>)}
                </select>
                {selectedServerId && (
                  <input
                    value={remoteWordlist}
                    onChange={e => setRemoteWordlist(e.target.value)}
                    style={{ ...selStyle, marginTop: 6 }}
                    placeholder="Wordlist path on remote server (e.g. /opt/wordlists/rockyou.txt)"
                  />
                )}
              </Field>

              {/* Wordlist */}
              {attackMode !== '3' && !selectedServerId && (
                <Field label="Wordlist">
                  {tools && tools.wordlists.length > 0 && (
                    <select value={wordlist} onChange={e => setWordlist(e.target.value)} style={{ ...selStyle, marginBottom: 6 }}>
                      <option value="">Select wordlist…</option>
                      {tools.wordlists.map(w => <option key={w} value={w}>{w.split('/').pop()}</option>)}
                    </select>
                  )}
                  <input value={customWordlist} onChange={e => setCustomWordlist(e.target.value)} style={selStyle} placeholder="Custom path…" />
                </Field>
              )}

              {/* Hash input */}
              <Field label={`Hashes (one per line) · ${getHashes().length}`}>
                <textarea
                  value={hashInput}
                  onChange={e => setHashInput(e.target.value)}
                  rows={5}
                  placeholder={"5f4dcc3b5aa765d61d8327deb882cf99\n098f6bcd4621d373cade4e832627b4f6"}
                  style={{
                    width: '100%', boxSizing: 'border-box',
                    background: 'var(--bg)', border: ruleStrong, borderRadius: 3,
                    padding: '8px 10px', fontSize: 11, color: 'var(--fg)',
                    fontFamily: 'var(--font-mono)', outline: 'none', resize: 'none',
                  }}
                />
              </Field>

              {/* Load from vault */}
              {vaultCreds.length > 0 && (
                <Field label="Load from Vault">
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 100, overflowY: 'auto', marginBottom: 8 }}>
                    {vaultCreds.map(c => (
                      <label key={c.id} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>
                        <input
                          type="checkbox"
                          checked={selectedCredIds.includes(c.id)}
                          onChange={() => toggleCredId(c.id)}
                          style={{ accentColor: 'var(--accent)' }}
                        />
                        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.cred_type} · {c.target_host || c.username || c.id.slice(0, 8)}</span>
                      </label>
                    ))}
                  </div>
                  <button onClick={loadFromVault} disabled={selectedCredIds.length === 0} className="btn" style={{ width: '100%', justifyContent: 'center', opacity: selectedCredIds.length === 0 ? 0.4 : 1 }}>
                    <Icon name="upload" size={11} color="currentColor" /> Load {selectedCredIds.length || ''} hash{selectedCredIds.length !== 1 ? 'es' : ''}
                  </button>
                </Field>
              )}

              {/* hashcat status */}
              <div>
                <div className="smcap" style={{ marginBottom: 6 }}>hashcat status</div>
                <div className="rule" style={{ padding: 0 }}>
                  <pre className="term" style={{ margin: 0, fontSize: 10, lineHeight: 1.5, padding: '10px 12px', whiteSpace: 'pre-wrap' }}>
                    <span className="muted">{buildCommandPreview()}</span>
                    {'\n'}
                    {running
                      ? <span className="ok">Status.........: Running</span>
                      : <span className="muted">Status.........: Idle</span>
                    }
                  </pre>
                </div>
              </div>

              {/* Wordlist bundles */}
              {bundles.length > 0 && (
                <Field label="Get Wordlists">
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {bundles.map(b => (
                      <div key={b.id} style={{ background: 'var(--bg)', border: ruleStrong, borderRadius: 3, padding: '8px 10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 4 }}>
                          <span className="mono" style={{ fontSize: 11, color: 'var(--fg)' }}>{b.label}</span>
                          {b.installed ? (
                            <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, color: 'var(--ok)' }}>
                              <Icon name="check" size={9} color="currentColor" /> Installed
                            </span>
                          ) : (
                            <button onClick={() => installBundle(b.id)} disabled={installing !== null} className="btn btn-sm" style={{ opacity: installing !== null && installing !== b.id ? 0.4 : 1 }}>
                              <Icon name={installing === b.id ? 'refresh' : 'download'} size={9} color="currentColor" />
                              {installing === b.id ? 'Installing…' : 'Install'}
                            </button>
                          )}
                        </div>
                        <p style={{ margin: 0, fontSize: 10, color: 'var(--fg-3)', fontFamily: 'var(--font-sans)' }}>{b.description}</p>
                        {installLog[b.id] && (
                          <pre style={{ margin: '6px 0 0', fontSize: 9, fontFamily: 'var(--font-mono)', color: 'var(--fg-2)', background: 'var(--bg)', borderRadius: 2, padding: 6, maxHeight: 80, overflowY: 'auto', whiteSpace: 'pre-wrap' }}>
                            {installLog[b.id]}
                          </pre>
                        )}
                      </div>
                    ))}
                  </div>
                </Field>
              )}
            </div>
          </Section>

          {/* Remote Cracking Servers */}
          <Section
            title="REMOTE SERVERS"
            right={
              <button onClick={() => { setServersOpen(o => { if (!o) loadSshCredentials(); return !o }) }} className="btn btn-sm btn-ghost" style={{ fontSize: 10 }}>
                {serversOpen ? 'Hide' : 'Manage'}
              </button>
            }
          >
            {serversOpen && (
              <div style={{ padding: '0 var(--pad) 14px', display: 'flex', flexDirection: 'column', gap: 12 }}>
                {srvError && <div style={{ fontSize: 11, color: 'var(--crit)', fontFamily: 'var(--font-mono)' }}>{srvError}</div>}
                {crackingServers.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {crackingServers.map(s => (
                      <div key={s.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', background: 'var(--bg)', border: ruleStrong, borderRadius: 3 }}>
                        <span className="mono" style={{ fontSize: 11, flex: 1 }}>{s.name}</span>
                        <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>{s.ssh_user}@{s.host}:{s.port}</span>
                        <button onClick={() => handleDeleteServer(s.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--crit)', padding: 0 }}>
                          <Icon name="x" size={12} color="currentColor" />
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p style={{ margin: 0, fontSize: 11, color: 'var(--fg-3)', fontFamily: 'var(--font-mono)' }}>No remote servers configured.</p>
                )}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 60px', gap: 6 }}>
                    <input value={srvFormName} onChange={e => setSrvFormName(e.target.value)} placeholder="Server name" style={selStyle} />
                    <input value={srvFormPort} onChange={e => setSrvFormPort(e.target.value)} placeholder="Port" style={selStyle} />
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 90px', gap: 6 }}>
                    <input value={srvFormHost} onChange={e => setSrvFormHost(e.target.value)} placeholder="Host / IP" style={selStyle} />
                    <input value={srvFormUser} onChange={e => setSrvFormUser(e.target.value)} placeholder="SSH user" style={selStyle} />
                  </div>
                  <input value={srvFormWorkdir} onChange={e => setSrvFormWorkdir(e.target.value)} placeholder="Remote workdir" style={selStyle} />
                  <select value={srvFormKeyCredId} onChange={e => setSrvFormKeyCredId(e.target.value)} style={selStyle}>
                    <option value="">SSH key — select from vault (optional)</option>
                    {sshKeyCredentials.map(c => <option key={c.id} value={c.id}>{c.username}{c.notes ? ` · ${c.notes}` : ''}</option>)}
                  </select>
                  <button onClick={handleAddServer} disabled={savingSrv} className="btn btn-sm" style={{ width: '100%', justifyContent: 'center' }}>
                    <Icon name="plus" size={11} color="currentColor" /> {savingSrv ? 'Saving…' : 'Add Server'}
                  </button>
                </div>
              </div>
            )}
            {!serversOpen && crackingServers.length > 0 && (
              <div style={{ padding: '0 var(--pad) 10px' }}>
                <span className="mono" style={{ fontSize: 10, color: 'var(--fg-3)' }}>{crackingServers.length} server{crackingServers.length !== 1 ? 's' : ''} configured</span>
              </div>
            )}
            {!serversOpen && crackingServers.length === 0 && (
              <div style={{ padding: '0 var(--pad) 10px' }}>
                <span className="mono" style={{ fontSize: 10, color: 'var(--fg-4)' }}>None — jobs run locally</span>
              </div>
            )}
          </Section>

          {/* Live output */}
          <Section title="LIVE OUTPUT">
            <div style={{ padding: '0 var(--pad) 16px', height: 240 }}>
              <div ref={outputRef} style={{ height: '100%', border: ruleStrong, overflowY: 'auto', background: 'var(--bg)' }}>
                <pre className="term" style={{ margin: 0, padding: '10px 12px', fontSize: 11, lineHeight: 1.6, whiteSpace: 'pre-wrap', wordBreak: 'break-all', minHeight: '100%' }}>
                  {liveOutput || <span className="muted">No output yet. Run a job to see live output here.</span>}
                </pre>
              </div>
            </div>
          </Section>
        </div>
      </div>
    </div>
  )
}
