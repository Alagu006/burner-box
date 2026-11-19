import { describe, it, expect } from 'vitest';
import { validateApiUrl } from '../lib/api.js';

describe('API URL Configuration & HTTPS Enforcement', () => {
  it('enforces HTTPS protocol for API_URL in production builds', () => {
    // Should succeed for valid HTTPS endpoint in production
    const validUrl = 'https://api.burnerbox.io';
    expect(validateApiUrl(validUrl, true)).toBe(validUrl);

    // Should throw a security error when an insecure HTTP URL is supplied in production
    const insecureUrl = 'http://api.burnerbox.io';
    expect(() => validateApiUrl(insecureUrl, true)).toThrowError(
      /SECURITY ERROR: In production builds, API_URL must use HTTPS protocol/
    );
  });

  it('allows http://localhost in non-production environments', () => {
    const devUrl = 'http://localhost:8080';
    expect(validateApiUrl(devUrl, false)).toBe(devUrl);
  });
});

