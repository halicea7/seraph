import { resolve } from 'path'
import { defineConfig, externalizeDepsPlugin } from 'electron-vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  main: {
    plugins: [externalizeDepsPlugin()],
  },
  preload: {
    plugins: [externalizeDepsPlugin()],
  },
  renderer: {
    // The renderer source is shared with the browser build — it lives in
    // ../frontend (same index.html + src/ shape electron-vite expects here),
    // not duplicated under this package. ../frontend/vite.config.ts builds
    // the same tree for FastAPI to serve; this config builds it for the
    // desktop shell. See frontend/src/vite-env.d.ts for the __IS_ELECTRON__
    // branch points that keep one source tree working both ways.
    root: resolve('../frontend'),
    resolve: {
      alias: {
        '@': resolve('../frontend/src'),
      },
    },
    define: {
      __IS_ELECTRON__: 'true',
    },
    build: {
      // electron-vite's own renderer-entry autodetection only looks for
      // <project-root>/src/renderer/index.html — it doesn't follow the
      // `root` override above for that check, so the entry has to be given
      // explicitly here.
      rollupOptions: {
        input: resolve('../frontend/index.html'),
      },
    },
    plugins: [react()],
  },
})
