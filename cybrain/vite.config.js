import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/analyze': {
        target:       'http://127.0.0.1:5000',
        changeOrigin: true,
        timeout:      480000,
        proxyTimeout: 480000,
      },
      '/scan_url': {
        target:       'http://127.0.0.1:5000',
        changeOrigin: true,
        timeout:      480000,
        proxyTimeout: 480000,
      },
      '/scan_network': {
        target:       'http://127.0.0.1:5000',
        changeOrigin: true,
        timeout:      480000,
        proxyTimeout: 480000,
      },
      '/analyze_code': {
        target:       'http://127.0.0.1:5000',
        changeOrigin: true,
        timeout:      480000,
        proxyTimeout: 480000,
      },
      '/fix_code': {
        target:       'http://127.0.0.1:5000',
        changeOrigin: true,
        timeout:      480000,
        proxyTimeout: 480000,
      },
      '/fix_config': {
        target:       'http://127.0.0.1:5000',
        changeOrigin: true,
        timeout:      480000,
        proxyTimeout: 480000,
      },
      '/api': {
        target:       'http://127.0.0.1:5000',
        changeOrigin: true,
        timeout:      480000,
        proxyTimeout: 480000,
      },
      '/download_report': {
        target:       'http://127.0.0.1:5000',
        changeOrigin: true,
        timeout:      60000,
        proxyTimeout: 60000,
      },
      '/download_fixed': {
        target:       'http://127.0.0.1:5000',
        changeOrigin: true,
        timeout:      60000,
        proxyTimeout: 60000,
      },
      '/health': {
        target:       'http://127.0.0.1:5000',
        changeOrigin: true,
        timeout:      10000,
        proxyTimeout: 10000,
      },
    }
  }
})
