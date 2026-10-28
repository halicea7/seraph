import { useState } from 'react'
import { setServerUrl } from '@/lib/config'

export function ConnectScreen() {
  const [url, setUrl] = useState('http://192.168.1.10:8000')
  const [error, setError] = useState<string | null>(null)
  const [testing, setTesting] = useState(false)

  async function connect() {
    const trimmed = url.trim().replace(/\/$/, '')
    if (!trimmed) return
    setTesting(true)
    setError(null)
    try {
      // Trust this host's cert (self-signed/mkcert HTTPS) for the test fetch below,
      // before it's persisted. Without this the very first probe over HTTPS fails.
      await window.electronAPI!.prepareTrust(trimmed)
      const res = await fetch(`${trimmed}/api/v1/auth/me`, { method: 'GET' })
      // 401 is fine — it means the server is reachable, just not logged in yet
      if (!res.ok && res.status !== 401) throw new Error(`Server returned ${res.status}`)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not reach server')
      setTesting(false)
      return
    }
    await setServerUrl(trimmed)
    // setServerUrl triggers a window reload in main process
  }

  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', height: '100vh', background: 'var(--bg)', gap: 16,
    }}>
      <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--accent)', letterSpacing: 2, fontFamily: 'var(--font-mono)' }}>SERAPH</div>
      <p style={{ color: 'var(--fg-3)', fontSize: 13, marginBottom: 8 }}>Enter your Seraph server address</p>
      <input
        type="text"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        onKeyDown={(e) => e.key === 'Enter' && connect()}
        placeholder="http://192.168.1.10:8000"
        style={{
          width: 320, padding: '10px 14px', fontSize: 13,
          background: 'var(--bg-2)', border: '1px solid var(--rule-strong)', color: 'var(--fg)',
          outline: 'none', borderRadius: 0, fontFamily: 'var(--font-mono)',
        }}
      />
      {error && <p style={{ color: 'var(--err)', fontSize: 12 }}>{error}</p>}
      <button
        onClick={connect}
        disabled={testing}
        style={{
          padding: '10px 28px', fontSize: 13, fontWeight: 600,
          background: testing ? 'var(--fg-3)' : 'var(--accent)', color: '#1a1408',
          border: 'none', cursor: testing ? 'default' : 'pointer', borderRadius: 0,
          fontFamily: 'var(--font-mono)', letterSpacing: '0.06em', textTransform: 'uppercase',
        }}
      >
        {testing ? 'Connecting…' : 'Connect'}
      </button>
    </div>
  )
}
