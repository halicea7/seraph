import { useState, useEffect, FormEvent } from 'react'
import { Shield, Eye, EyeOff, Loader, UserPlus, LogIn } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'

type Mode = 'checking' | 'setup' | 'login'

export default function Login() {
  const { login } = useAuth()
  const [mode, setMode] = useState<Mode>('checking')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [showPw, setShowPw] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    fetch('/api/v1/auth/setup-required')
      .then(r => r.json())
      .then(data => setMode(data.required ? 'setup' : 'login'))
      .catch(() => setMode('login'))
  }, [])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (mode === 'setup') {
        if (password.length < 8) {
          setError('Password must be at least 8 characters.')
          return
        }
        const fullName = `${firstName.trim()} ${lastName.trim()}`.trim()
        const res = await fetch('/api/v1/auth/setup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: username.trim(), password, full_name: fullName || undefined }),
        })
        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || 'Setup failed')
        login(data.access_token, data.user)
      } else {
        const form = new URLSearchParams()
        form.append('username', username.trim())
        form.append('password', password)
        const res = await fetch('/api/v1/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: form.toString(),
        })
        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || 'Login failed')
        login(data.access_token, data.user)
      }
    } catch (err: any) {
      setError(err.message || 'Unknown error')
    } finally {
      setLoading(false)
    }
  }

  if (mode === 'checking') {
    return (
      <div className="flex items-center justify-center h-screen" style={{ background: '#05080d' }}>
        <Loader size={24} className="animate-spin text-cyan-500" />
      </div>
    )
  }

  return (
    <div
      className="flex items-center justify-center h-screen dot-grid"
      style={{ background: '#05080d', color: '#e2e8f0' }}
    >
      <div className="w-full max-w-sm space-y-8 px-4">
        {/* Brand */}
        <div className="text-center space-y-3">
          <div
            className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mx-auto"
            style={{ background: 'rgba(6,182,212,0.1)', border: '1px solid rgba(6,182,212,0.25)' }}
          >
            <Shield size={32} className="text-cyan-400" style={{ filter: 'drop-shadow(0 0 8px rgba(6,182,212,0.6))' }} />
          </div>
          <div>
            <h1 className="text-3xl font-bold tracking-widest gradient-text">SERAPH</h1>
            <p className="text-xs text-slate-500 font-mono tracking-wide mt-1">Security Platform</p>
          </div>
        </div>

        {/* Card */}
        <div className="glass rounded-2xl p-8 space-y-6 border border-cyan-900/20">
          {mode === 'setup' && (
            <div className="text-center space-y-1">
              <div className="flex items-center justify-center gap-2 text-cyan-400">
                <UserPlus size={16} />
                <span className="text-sm font-semibold">First-Run Setup</span>
              </div>
              <p className="text-xs text-slate-400">Create your administrator account to get started.</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === 'setup' && (
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-400">First Name</label>
                  <input
                    type="text"
                    value={firstName}
                    onChange={e => setFirstName(e.target.value)}
                    placeholder="Jane"
                    required
                    className="w-full rounded-lg px-4 py-2.5 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none transition-colors"
                    style={{ background: '#090d14' }}
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-slate-400">Last Name</label>
                  <input
                    type="text"
                    value={lastName}
                    onChange={e => setLastName(e.target.value)}
                    placeholder="Doe"
                    required
                    className="w-full rounded-lg px-4 py-2.5 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none transition-colors"
                    style={{ background: '#090d14' }}
                  />
                </div>
              </div>
            )}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-400">Username</label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder={mode === 'setup' ? 'Choose a username' : 'Enter your username'}
                required
                autoFocus
                className="w-full rounded-lg px-4 py-2.5 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none transition-colors"
                style={{ background: '#090d14' }}
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-medium text-slate-400">Password</label>
              <div className="relative">
                <input
                  type={showPw ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder={mode === 'setup' ? 'At least 8 characters' : 'Enter your password'}
                  required
                  className="w-full rounded-lg px-4 py-2.5 pr-10 text-sm text-slate-200 border border-cyan-900/20 focus:border-cyan-500/50 focus:outline-none transition-colors"
                  style={{ background: '#090d14' }}
                />
                <button
                  type="button"
                  onClick={() => setShowPw(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  {showPw ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            {error && (
              <div
                className="rounded-lg px-4 py-2.5 text-xs text-red-300 border border-red-800/30"
                style={{ background: 'rgba(127,29,29,0.2)' }}
              >
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold text-white disabled:opacity-50 transition-all"
              style={{
                background: 'linear-gradient(135deg, #0891b2, #0e7490)',
                boxShadow: '0 0 20px rgba(6,182,212,0.25)',
              }}
            >
              {loading ? (
                <Loader size={14} className="animate-spin" />
              ) : mode === 'setup' ? (
                <><UserPlus size={14} /> Create Account</>
              ) : (
                <><LogIn size={14} /> Sign In</>
              )}
            </button>
          </form>
        </div>

        <p className="text-center text-xs text-slate-600">
          Self-hosted · All data stays local
        </p>
      </div>
    </div>
  )
}
