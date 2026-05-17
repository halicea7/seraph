import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import fs from 'fs'

const certsDir = path.resolve(__dirname, '../certs')
const certFile = path.join(certsDir, 'localhost.pem')
const keyFile = path.join(certsDir, 'localhost-key.pem')
const hasCerts = fs.existsSync(certFile) && fs.existsSync(keyFile)

const backendProto = hasCerts ? 'https' : 'http'
const wsProto = hasCerts ? 'wss' : 'ws'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    host: '0.0.0.0',
    port: 22123,
    https: hasCerts
      ? { key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile) }
      : undefined,
    proxy: {
      '/api': {
        target: `${backendProto}://localhost:8002`,
        changeOrigin: true,
        secure: false,
      },
      '/ws': {
        target: `${wsProto}://localhost:8002`,
        ws: true,
        changeOrigin: true,
        secure: false,
      },
      '/a': {
        target: `${backendProto}://localhost:8002`,
        changeOrigin: true,
        secure: false,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
})
