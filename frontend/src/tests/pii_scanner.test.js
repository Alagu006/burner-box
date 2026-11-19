import { describe, it, expect } from 'vitest';
import {
  scanPII,
  redactMatch,
  redactAllMatches,
  generateHighlightedSegments,
} from '../lib/pii_scanner.js';
import fs from 'fs';
import path from 'path';

describe('Client-Side Pattern-Based PII Scanner', () => {
  it('scans and identifies email addresses', () => {
    const text = 'Please reach out to me at whistleblower99@proton.me or jane.doe@corporate-internal.com for documents.';
    const matches = scanPII(text);

    const emails = matches.filter(m => m.type === 'email');
    expect(emails.length).toBe(2);
    expect(emails[0].text).toBe('whistleblower99@proton.me');
    expect(emails[1].text).toBe('jane.doe@corporate-internal.com');
    expect(emails[0].typeLabel).toBe('Email Address');
  });

  it('scans and identifies phone numbers in multiple standard formats', () => {
    const text = 'You can call my direct extension at (415) 555-2671 or my mobile at +1-800-555-0199 or UK line +44 7911 123456.';
    const matches = scanPII(text);

    const phones = matches.filter(m => m.type === 'phone');
    expect(phones.length).toBeGreaterThanOrEqual(2);
    expect(phones.some(p => p.text.includes('555-2671'))).toBe(true);
    expect(phones.some(p => p.text.includes('555-0199'))).toBe(true);
  });

  it('scans and identifies SSN and employee/badge ID numbers', () => {
    const text = 'Employee SSN was listed as 000-12-3456 and internal badge number is EMP-89421.';
    const matches = scanPII(text);

    const ssn = matches.find(m => m.type === 'ssn');
    expect(ssn).toBeDefined();
    expect(ssn?.text).toBe('000-12-3456');

    const idNum = matches.find(m => m.type === 'id_num');
    expect(idNum).toBeDefined();
    expect(idNum?.text).toBe('EMP-89421');
  });

  it('scans and identifies URLs with identifying/tracking query parameters', () => {
    const text = 'Check the internal ticket at https://jira.internal.corp/browse/SEC-1042?reporter=alice&session=99x81 and www.company.internal/leak';
    const matches = scanPII(text);

    const urls = matches.filter(m => m.type === 'url');
    expect(urls.length).toBe(2);
    expect(urls[0].text).toContain('https://jira.internal.corp');
    expect(urls[1].text).toContain('www.company.internal/leak');
  });

  it('scans and identifies IP addresses', () => {
    const text = 'The breach originated from internal gateway 10.14.200.55 and external server 198.51.100.4.';
    const matches = scanPII(text);

    const ips = matches.filter(m => m.type === 'ip');
    expect(ips.length).toBe(2);
    expect(ips[0].text).toBe('10.14.200.55');
    expect(ips[1].text).toBe('198.51.100.4');
  });

  it('correctly redacts a single target match with [REDACTED]', () => {
    const text = 'My email is secret@leak.com and phone is 555-901-2345.';
    const matches = scanPII(text);
    const emailMatch = matches.find(m => m.type === 'email');
    expect(emailMatch).toBeDefined();

    const redacted = redactMatch(text, emailMatch);
    expect(redacted).toBe('My email is [REDACTED] and phone is 555-901-2345.');
  });

  it('correctly redacts all detected PII matches in one operation', () => {
    const text = 'Report by EMP-4412 (alice@corp.com, phone 555-123-4567, SSN 123-45-6789) on https://intranet.corp/dossier';
    const matches = scanPII(text);
    expect(matches.length).toBeGreaterThanOrEqual(4);

    const allRedacted = redactAllMatches(text, matches, '[REDACTED]');
    expect(allRedacted).not.toContain('EMP-4412');
    expect(allRedacted).not.toContain('alice@corp.com');
    expect(allRedacted).not.toContain('555-123-4567');
    expect(allRedacted).not.toContain('123-45-6789');
    expect(allRedacted).not.toContain('https://intranet.corp/dossier');
    expect(allRedacted).toContain('[REDACTED]');
  });

  it('generates highlighted segments for visual backdrop display', () => {
    const text = 'Contact alert@corp.com immediately.';
    const matches = scanPII(text);
    const segments = generateHighlightedSegments(text, matches);

    expect(segments.length).toBe(3);
    expect(segments[0]).toEqual({ text: 'Contact ', isPII: false });
    expect(segments[1].isPII).toBe(true);
    expect(segments[1].text).toBe('alert@corp.com');
    expect(segments[2]).toEqual({ text: ' immediately.', isPII: false });
  });

  it('STRICT PRIVACY AUDIT: zero network requests or telemetry in pii_scanner.js', () => {
    const filePath = path.resolve(__dirname, '../lib/pii_scanner.js');
    const content = fs.readFileSync(filePath, 'utf-8');

    // Ensure zero networking APIs
    expect(content).not.toContain('fetch(');
    expect(content).not.toContain('XMLHttpRequest');
    expect(content).not.toContain('WebSocket');
    expect(content).not.toContain('EventSource');
    expect(content).not.toContain('sendBeacon');
    expect(content).not.toContain('navigator.sendBeacon');
    expect(content).not.toContain('axios');
    expect(content).not.toContain('http://');
    expect(content).not.toContain('https://api.');
  });
});
