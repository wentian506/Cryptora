import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: './',
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
    allowedHosts: true,
    cors: true,
    proxy: {
      // local dev: same-origin /api works too (mirrors prod nginx)
      '/api': { target: 'http://localhost:8000', changeOrigin: true },
    },
    headers: {
      // Allow embedding in preview iframes
      'X-Frame-Options': 'ALLOWALL'
    }
  },
  preview: {
    host: '0.0.0.0',
    port: 5173
  },
  build: {
    outDir: 'dist',
    sourcemap: false
  }
});
