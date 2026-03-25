import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App'

// Global fetch interceptor — injects the stored JWT into every API request
const _origFetch = window.fetch.bind(window)
window.fetch = (input: RequestInfo | URL, init: RequestInit = {}) => {
  const token = localStorage.getItem('seraph_token')
  const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url
  // Only inject for requests to our own API (not LLM endpoints or external URLs)
  if (token && (url.startsWith('/api/') || url.startsWith('/ws/'))) {
    const headers = new Headers((init.headers as HeadersInit) ?? {})
    if (!headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`)
    }
    init = { ...init, headers }
  }
  return _origFetch(input, init)
}

const container = document.getElementById('root')
if (!container) {
  throw new Error('Root element #root not found in DOM')
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>
)
