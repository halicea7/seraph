import { useEffect, useState } from 'react'
import Modal from './Modal'
import Icon from './Icon'
import { useAppStore } from '@/stores/appStore'
import { useToast } from '@/contexts/ToastContext'
import {
  getNessusTemplates, getNessusPolicies, getNessusFolders, launchNessusScan,
  type NessusTemplate, type NessusPolicy, type NessusFolder,
} from '@/api/client'

// ══════════════════════════════════════════════════════════════════════════════
// Launch a Nessus scan from Seraph: pick a template (+ optional policy/folder),
// name it, enter targets, and fire it. The backend creates the scan in Nessus,
// launches it, and a poller tracks it to completion (fanning out findings).
// ══════════════════════════════════════════════════════════════════════════════

const labelStyle: React.CSSProperties = {
  fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em',
  color: 'var(--fg-3)', marginBottom: 4, display: 'block',
}
const inputStyle: React.CSSProperties = {
  width: '100%', background: 'var(--bg)', border: '1px solid var(--rule-strong)',
  color: 'var(--fg)', padding: '7px 9px', fontSize: 12, fontFamily: 'var(--font-mono)',
}

export default function NessusScanModal({ onClose, onLaunched }: {
  onClose: () => void
  onLaunched?: (scanId: string) => void
}) {
  const toast = useToast()
  const { projects, selectedProject } = useAppStore()

  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [templates, setTemplates] = useState<NessusTemplate[]>([])
  const [policies, setPolicies] = useState<NessusPolicy[]>([])
  const [folders, setFolders] = useState<NessusFolder[]>([])

  const [projectId, setProjectId] = useState(selectedProject?.id ?? '')
  const [templateUuid, setTemplateUuid] = useState('')
  const [policyId, setPolicyId] = useState('')
  const [folderId, setFolderId] = useState('')
  const [name, setName] = useState('')
  const [targets, setTargets] = useState('')
  const [launching, setLaunching] = useState(false)

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const [t, p, f] = await Promise.all([
          getNessusTemplates(),
          getNessusPolicies().catch(() => [] as NessusPolicy[]),
          getNessusFolders().catch(() => [] as NessusFolder[]),
        ])
        if (cancelled) return
        setTemplates(t)
        setPolicies(p)
        setFolders(f)
        // Default to the "basic"/first non-agent template.
        const basic = t.find(x => x.name === 'basic') ?? t.find(x => !x.is_agent) ?? t[0]
        if (basic) setTemplateUuid(basic.uuid)
      } catch (e: any) {
        if (!cancelled) setLoadError(e?.message ?? 'Failed to load Nessus templates')
      } finally {
        if (!cancelled) setLoading(false)
      }
    })()
    return () => { cancelled = true }
  }, [])

  async function handleLaunch() {
    if (!projectId) { toast.error('Select a project'); return }
    if (!templateUuid) { toast.error('Select a scan template'); return }
    if (!targets.trim()) { toast.error('Enter at least one target'); return }
    setLaunching(true)
    try {
      const res = await launchNessusScan({
        project_id: projectId,
        template_uuid: templateUuid,
        policy_id: policyId ? Number(policyId) : null,
        folder_id: folderId ? Number(folderId) : null,
        name: name.trim(),
        targets: targets.trim(),
      })
      toast.success(`Launched "${res.name}" — tracking progress`)
      onLaunched?.(res.scan_id)
      onClose()
    } catch (e: any) {
      toast.error(e?.message ?? 'Failed to launch scan')
    } finally {
      setLaunching(false)
    }
  }

  return (
    <Modal
      onClose={onClose}
      title="Launch Nessus scan"
      width={560}
      footer={
        <>
          <button className="btn btn-sm" onClick={onClose} disabled={launching}>Cancel</button>
          <button className="btn btn-primary btn-sm" onClick={handleLaunch}
            disabled={launching || loading || !!loadError}>
            {launching ? 'Launching…' : 'Launch scan'}
          </button>
        </>
      }
    >
      <div style={{ padding: 'var(--pad)', display: 'flex', flexDirection: 'column', gap: 14 }}>
        {loading ? (
          <div className="mono" style={{ fontSize: 11, color: 'var(--fg-3)', padding: '24px 0', textAlign: 'center' }}>
            Loading Nessus templates…
          </div>
        ) : loadError ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: 'var(--crit)', fontSize: 12 }}>
            <Icon name="x" size={14} />
            <span>{loadError}. Check Settings → Nessus.</span>
          </div>
        ) : (
          <>
            <div>
              <label style={labelStyle}>Project</label>
              <select style={inputStyle} value={projectId} onChange={e => setProjectId(e.target.value)}>
                <option value="">— Select project —</option>
                {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>

            <div>
              <label style={labelStyle}>Scan template</label>
              <select style={inputStyle} value={templateUuid} onChange={e => setTemplateUuid(e.target.value)}>
                {templates.map(t => (
                  <option key={t.uuid} value={t.uuid}>{t.title || t.name}{t.is_agent ? ' (agent)' : ''}</option>
                ))}
              </select>
            </div>

            {policies.length > 0 && (
              <div>
                <label style={labelStyle}>Policy (optional)</label>
                <select style={inputStyle} value={policyId} onChange={e => setPolicyId(e.target.value)}>
                  <option value="">— None (use template defaults) —</option>
                  {policies.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
              </div>
            )}

            {folders.length > 0 && (
              <div>
                <label style={labelStyle}>Folder (optional)</label>
                <select style={inputStyle} value={folderId} onChange={e => setFolderId(e.target.value)}>
                  <option value="">— Default —</option>
                  {folders.filter(f => f.type !== 'trash').map(f => (
                    <option key={f.id} value={f.id}>{f.name}</option>
                  ))}
                </select>
              </div>
            )}

            <div>
              <label style={labelStyle}>Scan name</label>
              <input style={inputStyle} value={name} placeholder="Seraph scan — <date>"
                onChange={e => setName(e.target.value)} />
            </div>

            <div>
              <label style={labelStyle}>Targets</label>
              <textarea style={{ ...inputStyle, minHeight: 70, resize: 'vertical' }}
                value={targets} placeholder="192.168.1.0/24, host.example.com, 10.0.0.5"
                onChange={e => setTargets(e.target.value)} />
              <div className="mono" style={{ fontSize: 10, color: 'var(--fg-4)', marginTop: 4 }}>
                Comma- or newline-separated hosts, IPs, or CIDR ranges.
              </div>
            </div>
          </>
        )}
      </div>
    </Modal>
  )
}
