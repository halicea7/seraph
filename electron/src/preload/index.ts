import { contextBridge, ipcRenderer } from 'electron'

export interface OllamaSettings {
  useLocalOllama: boolean
  localOllamaUrl: string
  localOllamaModel: string
}

const api = {
  getServerUrl: (): Promise<string | null> => ipcRenderer.invoke('settings:get-server-url'),
  setServerUrl: (url: string | null): Promise<boolean> => ipcRenderer.invoke('settings:set-server-url', url),
  prepareTrust: (url: string | null): Promise<boolean> => ipcRenderer.invoke('settings:prepare-trust', url),

  // Local Ollama
  ollamaGetSettings: (): Promise<OllamaSettings> => ipcRenderer.invoke('ollama:get-settings'),
  ollamaSetSettings: (s: OllamaSettings): Promise<boolean> => ipcRenderer.invoke('ollama:set-settings', s),
  ollamaModels: (): Promise<string[]> => ipcRenderer.invoke('ollama:models'),
  ollamaChat: (messages: Array<{ role: string; content: string }>, model?: string): Promise<string> =>
    ipcRenderer.invoke('ollama:chat', { messages, model }),
}

contextBridge.exposeInMainWorld('electronAPI', api)

declare global {
  interface Window {
    electronAPI: typeof api
  }
}
