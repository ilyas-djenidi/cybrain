import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/analyze':        'http://127.0.0.1:5000',
      '/scan_url':       'http://127.0.0.1:5000',
      '/download_report':'http://127.0.0.1:5000',
    }
  }
})
