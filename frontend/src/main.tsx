import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import { initServerUrl } from './lib/config'
import { getToken } from './lib/auth-token'
import App from './App'

// Initialise server URL from Electron settings before anything renders
initServerUrl().then(() => {
  // Global fetch interceptor — injects the stored JWT into every Seraph API request
  const _origFetch = window.fetch.bind(window)
  window.fetch = (input: RequestInfo | URL, init: RequestInit = {}) => {
    const token = getToken()
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url
    if (token && url.includes('/api/v1/')) {
      const headers = new Headers((init.headers as HeadersInit) ?? {})
      if (!headers.has('Authorization')) {
        headers.set('Authorization', `Bearer ${token}`)
      }
      init = { ...init, headers }
    }
    return _origFetch(input, init)
  }

  const container = document.getElementById('root')
  if (!container) throw new Error('Root element #root not found in DOM')
  createRoot(container).render(
    <StrictMode>
      <App />
    </StrictMode>
  )
})
