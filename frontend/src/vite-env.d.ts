/// <reference types="vite/client" />

// Build-time flag — true when this renderer source is built by
// electron/electron.vite.config.ts (desktop shell), false when built by
// this package's own vite.config.ts (browser/web build, served by FastAPI).
declare const __IS_ELECTRON__: boolean

// The preload bridge (electron/src/preload/index.ts) only exists in the
// Electron build — it's declared here, in the renderer's own tsconfig
// scope, rather than in the preload file's `declare global`, so the browser
// build's typecheck also sees it and `window.electronAPI` is typed
// `undefined` unless __IS_ELECTRON__-guarded. The Electron build's real
// `window.electronAPI` is always fully populated (never partial) — this
// type is intentionally optional only so unguarded access in code meant to
// run in both builds is a type error, not a runtime one.
interface OllamaSettings {
  useLocalOllama: boolean
  localOllamaUrl: string
  localOllamaModel: string
}
interface Window {
  electronAPI?: {
    getServerUrl: () => Promise<string | null>
    setServerUrl: (url: string | null) => Promise<boolean>
    prepareTrust: (url: string | null) => Promise<boolean>
    ollamaGetSettings: () => Promise<OllamaSettings>
    ollamaSetSettings: (s: OllamaSettings) => Promise<boolean>
    ollamaModels: () => Promise<string[]>
    ollamaChat: (messages: Array<{ role: string; content: string }>, model?: string) => Promise<string>
  }
}

declare module 'js-yaml' {
  export function load(input: string, options?: Record<string, unknown>): unknown
  export function dump(obj: unknown, options?: Record<string, unknown>): string
}
