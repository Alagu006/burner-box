import { describe, it, expect, vi, beforeEach } from 'vitest';
import { logout } from '../lib/auth.js';
import * as cryptoModule from '../lib/crypto.js';

describe('Centralized Logout & Session Revocation', () => {
  let store = {};

  beforeEach(() => {
    store = {};
    global.localStorage = {
      getItem: vi.fn((key) => store[key] || null),
      setItem: vi.fn((key, val) => { store[key] = String(val); }),
      removeItem: vi.fn((key) => { delete store[key]; }),
      clear: vi.fn(() => { store = {}; }),
    };
    vi.restoreAllMocks();
  });

  it('calls POST /api/v1/auth/logout with Bearer token, clears localStorage, and calls clearDerivedKey', async () => {
    const token = 'test-jwt-token-12345';
    store['burnerbox_token'] = token;
    store['burnerbox_org'] = JSON.stringify({ id: 'org-1', name: 'Test Org' });

    const clearKeySpy = vi.spyOn(cryptoModule, 'clearDerivedKey');

    let fetchCalled = false;
    let fetchUrl = '';
    let fetchHeaders = {};
    let fetchMethod = '';

    global.fetch = vi.fn().mockImplementation(async (url, options) => {
      fetchCalled = true;
      fetchUrl = url;
      fetchMethod = options.method;
      fetchHeaders = options.headers;
      return { ok: true, json: async () => ({ message: 'Logged out' }) };
    });

    // Run logout without redirecting in test environment
    await logout(token, '');

    expect(fetchCalled).toBe(true);
    expect(fetchUrl).toContain('/api/v1/auth/logout');
    expect(fetchMethod).toBe('POST');
    expect(fetchHeaders['Authorization']).toBe(`Bearer ${token}`);

    // Verify localStorage cleared
    expect(store['burnerbox_token']).toBeUndefined();
    expect(store['burnerbox_org']).toBeUndefined();
    expect(clearKeySpy).toHaveBeenCalled();
  });

  it('handles offline / network errors gracefully and still clears local state', async () => {
    const token = 'test-jwt-token-offline';
    store['burnerbox_token'] = token;
    store['burnerbox_org'] = JSON.stringify({ id: 'org-2' });

    global.fetch = vi.fn().mockRejectedValue(new Error('Network offline'));

    // Should not throw
    await expect(logout(token, '')).resolves.not.toThrow();

    // Verify local storage is still cleared
    expect(store['burnerbox_token']).toBeUndefined();
    expect(store['burnerbox_org']).toBeUndefined();
  });
});
