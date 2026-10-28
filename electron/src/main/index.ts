import { app, BrowserWindow, ipcMain, net, session, shell } from 'electron'
import { join } from 'path'
import { readFileSync, writeFileSync } from 'fs'
import { is } from '@electron-toolkit/utils'
import appIcon from '../../resources/icon.png?asset'

// ── Settings ──────────────────────────────────────────────────────────────────

interface Settings {
  serverUrl: string | null
  windowWidth: number
  windowHeight: number
  windowX: number | null
  windowY: number | null
  useLocalOllama: boolean
  localOllamaUrl: string
  localOllamaModel: string
}

const SETTINGS_DEFAULTS: Settings = {
  serverUrl: null,
  windowWidth: 1280,
  windowHeight: 800,
  windowX: null,
  windowY: null,
  useLocalOllama: false,
  localOllamaUrl: 'http://localhost:11434',
  localOllamaModel: '',
}

const SETTINGS_PATH = join(app.getPath('userData'), 'settings.json')

function loadSettings(): Settings {
  try {
    return { ...SETTINGS_DEFAULTS, ...JSON.parse(readFileSync(SETTINGS_PATH, 'utf-8')) }
  } catch {
    return { ...SETTINGS_DEFAULTS }
  }
}

function saveSettings(s: Settings): void {
  writeFileSync(SETTINGS_PATH, JSON.stringify(s, null, 2), 'utf-8')
}

let settings = loadSettings()

// ── Window ────────────────────────────────────────────────────────────────────

let mainWindow: BrowserWindow | null = null

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: settings.windowWidth,
    height: settings.windowHeight,
    x: settings.windowX ?? undefined,
    y: settings.windowY ?? undefined,
    minWidth: 900,
    minHeight: 600,
    show: false,
    autoHideMenuBar: true,
    icon: appIcon, // taskbar/window icon on Linux & Windows (ignored on macOS)
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  })

  mainWindow.on('ready-to-show', () => mainWindow?.show())

  mainWindow.on('moved', () => {
    if (!mainWindow) return
    const [x, y] = mainWindow.getPosition()
    settings.windowX = x
    settings.windowY = y
    saveSettings(settings)
  })

  mainWindow.on('resized', () => {
    if (!mainWindow) return
    const [w, h] = mainWindow.getSize()
    settings.windowWidth = w
    settings.windowHeight = h
    saveSettings(settings)
  })

  // Open external links in the system browser, not the app window
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url)
    return { action: 'deny' }
  })

  if (is.dev && process.env['ELECTRON_RENDERER_URL']) {
    mainWindow.loadURL(process.env['ELECTRON_RENDERER_URL'])
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'))
  }
}

// ── IPC ───────────────────────────────────────────────────────────────────────

function ollamaBase(): string {
  return (settings.localOllamaUrl || 'http://localhost:11434').replace(/\/$/, '')
}

function setupIPC(): void {
  ipcMain.handle('settings:get-server-url', () => settings.serverUrl)

  ipcMain.handle('settings:set-server-url', (_, url: string | null) => {
    settings.serverUrl = url
    saveSettings(settings)
    mainWindow?.webContents.reload()
    return true
  })

  // Trust a backend's self-signed/mkcert cert for the duration of a connection
  // test, before the URL is persisted. The ConnectScreen calls this first.
  ipcMain.handle('settings:prepare-trust', (_, url: string | null) => {
    pendingTrustUrl = url
    return true
  })

  // ── Local Ollama ──────────────────────────────────────────────────────────

  ipcMain.handle('ollama:get-settings', () => ({
    useLocalOllama: settings.useLocalOllama,
    localOllamaUrl: settings.localOllamaUrl,
    localOllamaModel: settings.localOllamaModel,
  }))

  ipcMain.handle('ollama:set-settings', (_, s: { useLocalOllama: boolean; localOllamaUrl: string; localOllamaModel: string }) => {
    settings.useLocalOllama = s.useLocalOllama
    settings.localOllamaUrl = s.localOllamaUrl.trim().replace(/\/$/, '') || 'http://localhost:11434'
    settings.localOllamaModel = s.localOllamaModel
    saveSettings(settings)
    return true
  })

  ipcMain.handle('ollama:models', async () => {
    const url = `${ollamaBase()}/v1/models`
    const res = await net.fetch(url)
    if (!res.ok) throw new Error(`Ollama ${res.status}`)
    const data = await res.json() as { data?: Array<{ id: string }> }
    return (data.data || []).map(m => m.id)
  })

  ipcMain.handle('ollama:chat', async (_, { messages, model }: { messages: Array<{ role: string; content: string }>; model?: string }) => {
    const url = `${ollamaBase()}/v1/chat/completions`
    const m = model || settings.localOllamaModel
    if (!m) throw new Error('No local Ollama model configured')

    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 300_000) // 5 min
    try {
      const res = await net.fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: m, messages, stream: false }),
        signal: controller.signal,
      })
      if (!res.ok) {
        const txt = await res.text().catch(() => '')
        throw new Error(`Ollama ${res.status}: ${txt}`)
      }
      const data = await res.json() as { choices: Array<{ message: { content: string } }> }
      return data.choices[0].message.content
    } finally {
      clearTimeout(timeout)
    }
  })
}

// ── Backend TLS trust ───────────────────────────────────────────────────────
// The Seraph backend can be served over HTTPS with a self-signed / mkcert
// certificate (see seraph/setup-https.sh). Chromium rejects it because the
// client machine doesn't trust that CA ("No matching issuer found"). Rather than
// installing the CA on every client, we trust the cert ONLY for the exact host
// the user configured as their backend — every other origin is still verified
// normally.
// A host the ConnectScreen is actively testing, set *before* it fetches the URL
// (the URL isn't persisted to settings until the test passes — so without this
// the very first reachability check could never trust a self-signed cert).
let pendingTrustUrl: string | null = null

function parseUrlLoose(raw: string | null): URL | null {
  if (!raw) return null
  try {
    return new URL(raw)
  } catch {
    // May have been entered without a scheme (e.g. "10.0.0.5:8000").
    try {
      return new URL(`https://${raw}`)
    } catch {
      return null
    }
  }
}

// "host:port" — used by certificate-error, whose url includes the port.
function trustedHosts(): string[] {
  return [parseUrlLoose(settings.serverUrl)?.host, parseUrlLoose(pendingTrustUrl)?.host]
    .filter((h): h is string => !!h)
}

// hostname only (no port) — used by setCertificateVerifyProc.
function trustedHostnames(): string[] {
  return [parseUrlLoose(settings.serverUrl)?.hostname, parseUrlLoose(pendingTrustUrl)?.hostname]
    .filter((h): h is string => !!h)
}

function setupCertificateTrust(): void {
  // Primary, most reliable path: intercept verification in the network stack.
  // Catches fetch / XHR / WebSocket. callback(0)=trust, callback(-3)=default.
  session.defaultSession.setCertificateVerifyProc((request, callback) => {
    const trust = trustedHostnames().includes(request.hostname)
    console.log(`[seraph] cert check host=${request.hostname} -> ${trust ? 'TRUST (configured backend)' : 'default verification'}`)
    callback(trust ? 0 : -3)
  })

  // Belt-and-suspenders: also handle the app-level event.
  app.on('certificate-error', (event, _webContents, url, _error, _certificate, callback) => {
    let host: string
    try {
      host = new URL(url).host
    } catch {
      callback(false)
      return
    }
    if (trustedHosts().includes(host)) {
      event.preventDefault()
      callback(true)
    } else {
      callback(false)
    }
  })

  console.log(`[seraph] backend TLS trust active; saved host: ${parseUrlLoose(settings.serverUrl)?.hostname ?? '(none yet)'}`)
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

app.whenReady().then(() => {
  // macOS shows the app's dock icon from this (in dev the packaged .icns isn't
  // used, so set it explicitly to override the stock Electron icon).
  if (process.platform === 'darwin') app.dock?.setIcon(appIcon)
  setupCertificateTrust()
  setupIPC()
  createWindow()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
