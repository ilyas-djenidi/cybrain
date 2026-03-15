import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import axios from 'axios'

// Set backend URL for all axios requests
// In development, this uses the vite proxy if VITE_API_URL is empty.
// In production (e.g. Netlify), set VITE_API_URL pointing to the Render backend URL.
axios.defaults.baseURL = import.meta.env.VITE_API_URL || '';

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
