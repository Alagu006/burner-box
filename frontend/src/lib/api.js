// Centralized API URL configuration.
// In production, set VITE_API_URL at build time (e.g. Cloudflare Pages env var).
// In dev, falls back to localhost:8080.
export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';

// Derive WebSocket URL from API URL (http → ws, https → wss)
export const WS_URL = API_URL.replace(/^http/, 'ws');
