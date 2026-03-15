import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/analyze':              'http://127.0.0.1:5000',
      '/scan_url':             'http://127.0.0.1:5000',
      '/scan_network':         'http://127.0.0.1:5000',
      '/analyze_code':         'http://127.0.0.1:5000',
      '/fix_code':             'http://127.0.0.1:5000',
      '/fix_config':           'http://127.0.0.1:5000',
      '/detect_apache_misconf':'http://127.0.0.1:5000',
      '/api':                  'http://127.0.0.1:5000',
      '/download_report':      'http://127.0.0.1:5000',
      '/download_fixed':       'http://127.0.0.1:5000',
    }
  }
})
