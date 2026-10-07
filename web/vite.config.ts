/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const api = 'http://localhost:8080'

export default defineConfig({
  plugins: [react()],
  server: {
    // Same origin in dev, so the session cookie and CSRF checks behave as in production.
    proxy: { '/healthz': api, '/auth': api, '/v1': api },
  },
  test: { environment: 'jsdom' },
})
