// Centralized API URL configuration.
// In production, set VITE_API_URL at build time (e.g. Cloudflare Pages env var).
// In production builds, HTTPS is strictly enforced to protect credentials and payloads.

export function validateApiUrl(url, isProd = import.meta.env?.PROD) {
  if (isProd && url) {
    if (!url.startsWith('https://')) {
      throw new Error(`SECURITY ERROR: In production builds, API_URL must use HTTPS protocol (got: ${url})`);
    }
  }
  return url;
}

function resolveApiUrl() {
  const envUrl = import.meta.env?.VITE_API_URL;
  if (import.meta.env?.PROD) {
    if (envUrl) {
      validateApiUrl(envUrl, true);
      return envUrl;
    }
    // In production without an explicit VITE_API_URL, default to same-origin relative
    return '';
  }
  return envUrl || 'http://localhost:8080';
}

export const API_URL = resolveApiUrl();

// Derive WebSocket URL from API URL (http → ws, https → wss)
export const WS_URL = API_URL
  ? API_URL.replace(/^http/, 'ws')
  : (typeof window !== 'undefined'
      ? (window.location.protocol === 'https:' ? 'wss://' : 'ws://') + window.location.host
      : '');

