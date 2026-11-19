import { API_URL } from './api.js';
import { clearDerivedKey } from './crypto.js';

/**
 * Performs a centralized, robust logout:
 * 1. Calls POST /api/v1/auth/logout with the current token in the Authorization header.
 * 2. Employs a short 1.5s timeout via AbortController so local logout is never blocked by network latency/offline state.
 * 3. Clears in-memory derived encryption keys and localStorage tokens ('burnerbox_token', 'burnerbox_org').
 * 4. Redirects to /login.
 * 
 * @param {string} [token] - Optional token string
 * @param {string} [redirectTo='/login'] - Redirect destination
 */
export async function logout(token, redirectTo = '/login') {
  const currentToken = token || (typeof localStorage !== 'undefined' ? localStorage.getItem('burnerbox_token') : '');

  if (currentToken) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1500);

      await fetch(`${API_URL}/api/v1/auth/logout`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${currentToken}`,
          'Content-Type': 'application/json',
        },
        signal: controller.signal,
      }).catch(() => {
        // Silently catch network or timeout aborts so logout always proceeds
      });

      clearTimeout(timeoutId);
    } catch {
      // Ignore network errors
    }
  }

  // Clear in-memory cryptographic keys and stored credentials
  try {
    clearDerivedKey();
  } catch {}

  if (typeof localStorage !== 'undefined') {
    localStorage.removeItem('burnerbox_token');
    localStorage.removeItem('burnerbox_org');
  }

  if (typeof window !== 'undefined' && redirectTo) {
    window.location.href = redirectTo;
  }
}
