// Resolves the backend's API/WS base URL and the "is a server configured"
// gate. Electron can point at any LAN/remote Seraph server (configured via
// IPC, persisted by the main process, changeable from ConnectScreen) — a
// browser build is always same-origin with whatever FastAPI instance served
// it, so there's nothing to configure and this collapses to relative paths.
import { getToken } from './auth-token'

let _cachedUrl: string | null | undefined = undefined

export async function initServerUrl(): Promise<void> {
  if (!__IS_ELECTRON__) return
  _cachedUrl = await window.electronAPI!.getServerUrl()
}

export function getServerUrl(): string | null {
  // Browser build: always "configured" (same-origin) — ConnectScreen never shows.
  if (!__IS_ELECTRON__) return window.location.origin
  return _cachedUrl ?? null
}

export function getApiBase(): string {
  if (!__IS_ELECTRON__) return '/api/v1'
  return `${_cachedUrl ?? 'http://localhost:8002'}/api/v1`
}

export function getWsBase(): string {
  if (!__IS_ELECTRON__) {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${proto}//${window.location.host}`
  }
  return (_cachedUrl ?? 'http://localhost:8002').replace(/^http/, 'ws')
}

// Build a WebSocket URL with the auth token attached (?token=). The backend
// gates every WS handshake on a valid JWT (see WSAuthMiddleware).
export function wsUrl(path: string): string {
  const sep = path.includes('?') ? '&' : '?'
  return `${getWsBase()}${path}${sep}token=${encodeURIComponent(getToken() ?? '')}`
}

// Build an API URL with the token in the query string — for <img>/download URLs
// that can't set the Authorization header (auth middleware also accepts ?token=).
export function authedUrl(path: string): string {
  const sep = path.includes('?') ? '&' : '?'
  return `${getApiBase()}${path}${sep}token=${encodeURIComponent(getToken() ?? '')}`
}

export async function setServerUrl(url: string | null): Promise<void> {
  if (!__IS_ELECTRON__) return
  await window.electronAPI!.setServerUrl(url ? url.trim().replace(/\/$/, '') : null)
}
