// Shared model-source machinery — the standard for every AI feature in Seraph.
//
// Two sources, exactly as the AI Operator / Ask Seraph expose them:
//   local:<m>  → Ollama on THIS computer (called directly from the app)
//   server:<m> → Ollama on the backend host (called via /ai/chat)
//
// A feature builds its prompt server-side (the endpoint's `messages_only` mode
// returns the assembled messages), then calls runCompletion() which dispatches to
// the laptop or the backend depending on the chosen model.

import { useEffect, useState } from 'react'
import { getApiBase } from './config'

export interface AiModelOption {
  key: string // "local:<model>" | "server:<model>"
  label: string
}

export interface ChatMessage {
  role: string
  content: string
}

/** Load the combined [Local] + [Server] model list, plus the recommended default key. */
export async function loadAiModels(): Promise<{ options: AiModelOption[]; defaultKey: string }> {
  const options: AiModelOption[] = []

  // Local (this computer) Ollama — discovered via the Electron bridge.
  try {
    const localModels: string[] = await (window as any).electronAPI.ollamaModels()
    localModels.forEach(m => options.push({ key: `local:${m}`, label: `[Local] ${m}` }))
  } catch { /* local Ollama not running / not in Electron */ }

  // Server (backend host) Ollama + its configured default model.
  let serverDefault = ''
  try {
    const cfg = await fetch(`${getApiBase()}/ai/config`).then(r => r.json())
    serverDefault = cfg.model || ''
  } catch { /* backend offline */ }
  try {
    const d = await fetch(`${getApiBase()}/ai/models`).then(r => r.json())
    ;(d.models as string[] || []).forEach(m =>
      options.push({ key: `server:${m}`, label: `[Server] ${m}${m === serverDefault ? '  (default)' : ''}` }),
    )
  } catch { /* backend offline */ }

  const defaultKey = serverDefault ? `server:${serverDefault}` : (options[0]?.key ?? '')
  return { options, defaultKey }
}

/** Run a chat completion with the chosen model — laptop Ollama for local:, backend for server:. */
export async function runCompletion(modelKey: string, messages: ChatMessage[]): Promise<string> {
  const [source, ...parts] = modelKey.split(':')
  const model = parts.join(':')
  if (!model) throw new Error('No model selected')

  if (source === 'local') {
    const settings = await (window as any).electronAPI.ollamaGetSettings()
    const baseUrl = String(settings.localOllamaUrl || 'http://localhost:11434').replace(/\/$/, '')
    const resp = await fetch(`${baseUrl}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, messages, stream: false }),
    })
    if (!resp.ok) throw new Error(`Local Ollama error: ${resp.status}`)
    const data = await resp.json()
    return data.message?.content ?? ''
  }

  // server: → backend runs it against its own Ollama
  const r = await fetch(`${getApiBase()}/ai/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ messages, model }),
  })
  const data = await r.json()
  if (!r.ok) throw new Error(data.detail || 'AI chat failed')
  return data.content
}

/** Fetch a feature endpoint in `messages_only` mode and return the assembled prompt. */
export async function fetchMessages(path: string, body: Record<string, unknown>): Promise<ChatMessage[]> {
  const r = await fetch(`${getApiBase()}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...body, messages_only: true }),
  })
  const data = await r.json()
  if (!r.ok) throw new Error(data.detail || 'Failed to build prompt')
  return data.messages as ChatMessage[]
}

/** Convenience: build the prompt server-side, then run it with the chosen model. */
export async function completeFeature(
  modelKey: string,
  path: string,
  body: Record<string, unknown>,
): Promise<string> {
  const messages = await fetchMessages(path, body)
  return runCompletion(modelKey, messages)
}

/** React hook: loads the [Local]/[Server] options once and holds the selected key. */
export function useAiModel(): { options: AiModelOption[]; modelKey: string; setModelKey: (k: string) => void } {
  const [options, setOptions] = useState<AiModelOption[]>([])
  const [modelKey, setModelKey] = useState('')
  useEffect(() => {
    loadAiModels().then(({ options, defaultKey }) => {
      setOptions(options)
      setModelKey(k => k || defaultKey)
    }).catch(() => {})
  }, [])
  return { options, modelKey, setModelKey }
}
