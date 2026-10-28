// Single source of truth for the auth token + its retention policy.
//
// "Stay signed in for 12 hours" (persist = true):
//   token goes to localStorage with an expiry timestamp 12h out. On launch, if
//   that timestamp has passed the token is dropped and the user must log in again
//   — even though the backend token itself is valid longer (~24h).
//
// Not checked (persist = false):
//   token goes to sessionStorage, which the OS/Electron clears when the app quits,
//   so closing Seraph logs you out.
//
// getToken() is the only read path (used by AuthContext and the global fetch
// interceptor in main.tsx) so expiry is enforced consistently everywhere.

const TOKEN_KEY = 'seraph_token'
const EXPIRES_KEY = 'seraph_token_expires'
const STAY_SIGNED_IN_HOURS = 12

export function saveToken(token: string, persist: boolean): void {
  // Clear both stores first so we never leave a stale copy in the other one.
  clearToken()
  if (persist) {
    const expiresAt = Date.now() + STAY_SIGNED_IN_HOURS * 60 * 60 * 1000
    localStorage.setItem(TOKEN_KEY, token)
    localStorage.setItem(EXPIRES_KEY, String(expiresAt))
  } else {
    sessionStorage.setItem(TOKEN_KEY, token)
  }
}

export function getToken(): string | null {
  // Persistent token first, honoring the 12h cap.
  const persisted = localStorage.getItem(TOKEN_KEY)
  if (persisted) {
    const expiresRaw = localStorage.getItem(EXPIRES_KEY)
    const expiresAt = expiresRaw ? Number(expiresRaw) : NaN
    if (Number.isFinite(expiresAt) && Date.now() >= expiresAt) {
      clearToken()
    } else {
      return persisted
    }
  }
  // Otherwise a session-only token (cleared when the app quits).
  return sessionStorage.getItem(TOKEN_KEY)
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(EXPIRES_KEY)
  sessionStorage.removeItem(TOKEN_KEY)
}
