// Shared WebSocket URL builder. main.py's WSAuthMiddleware rejects every
// /ws/* handshake that doesn't carry a valid ?token= — the Electron client
// already does this (lib/config.ts: authedUrl/wsUrl); the web SPA's sockets
// never did, so all of them were closing with code 1008 on connect. One
// helper, used everywhere a component opens a socket, instead of 11 copies
// of the same URL string missing the one thing the backend requires.
const TOKEN_KEY = 'seraph_token'

export function wsUrl(path: string): string {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const token = localStorage.getItem(TOKEN_KEY) ?? ''
  const sep = path.includes('?') ? '&' : '?'
  return `${proto}//${window.location.host}${path}${sep}token=${encodeURIComponent(token)}`
}
