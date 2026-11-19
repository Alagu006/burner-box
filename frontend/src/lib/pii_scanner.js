/**
 * Client-Side Pattern-Based Personally Identifiable Information (PII) Scanner
 * 
 * ZERO-NETWORK & ZERO-AI GUARANTEE:
 * - 100% deterministic local regular expression matching.
 * - Zero network requests or telemetry.
 * - Zero external API or LLM dependencies.
 * - Advisory-only — never blocks submission.
 */

/**
 * @typedef {Object} PIIMatch
 * @property {string} id - Unique identifier for the match instance
 * @property {'email' | 'phone' | 'ssn' | 'id_num' | 'url' | 'ip'} type - PII category
 * @property {string} typeLabel - Human-readable label
 * @property {string} text - Matched text substring
 * @property {number} start - Start index in the source text
 * @property {number} end - End index in the source text
 * @property {string} reason - Why this pattern is potentially identifying
 */

// Regex patterns for deterministic PII scanning
const PII_PATTERNS = [
  {
    type: 'email',
    typeLabel: 'Email Address',
    reason: 'Direct contact address that can directly identify you or your workplace.',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gi,
  },
  {
    type: 'phone',
    typeLabel: 'Phone Number',
    reason: 'Telephone number or mobile contact that can be linked to your identity or subscriber records.',
    regex: /(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\b\+\d{1,4}[-.\s]?\d{6,12})\b/g,
  },
  {
    type: 'ssn',
    typeLabel: 'SSN / National ID',
    reason: 'Standard 9-digit social security or government identification number format.',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    type: 'id_num',
    typeLabel: 'Employee / System ID',
    reason: 'Identifier prefix or reference code that may be tied to your employee record or badge.',
    regex: /\b(?:EMP|EMPLOYEE|BADGE|STAFF|TAX|NIN|PASSPORT|USERID|ACCOUNT|ACCT|ID)[\s#:-]*(?:[A-Z]{0,4}\d{2,12}[A-Z0-9-]*|\d{2,6}-[A-Z0-9-]{2,10})\b/gi,
  },
  {
    type: 'url',
    typeLabel: 'URL / Web Link',
    reason: 'Web links often embed session tokens, tracking UTM params, or internal intranet domains.',
    regex: /\b(?:https?:\/\/|www\.)[^\s<>"]+[^\s<>.,!?]/gi,
  },
  {
    type: 'ip',
    typeLabel: 'IP Address',
    reason: 'Static or local IP address that could reveal your corporate network or workstation origin.',
    regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  },
];

/**
 * Scans text client-side for PII patterns and returns non-overlapping matches.
 * 
 * @param {string} text - Message text to scan
 * @returns {PIIMatch[]} Array of detected PII matches sorted by position
 */
export function scanPII(text) {
  if (!text || typeof text !== 'string') {
    return [];
  }

  const rawMatches = [];

  for (const pattern of PII_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;
    while ((match = regex.exec(text)) !== null) {
      const matchText = match[0];
      const start = match.index;
      const end = start + matchText.length;

      rawMatches.push({
        id: `${pattern.type}_${start}_${end}`,
        type: pattern.type,
        typeLabel: pattern.typeLabel,
        text: matchText,
        start,
        end,
        reason: pattern.reason,
      });
    }
  }

  // Sort by start index ascending, then length descending
  rawMatches.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    return (b.end - b.start) - (a.end - a.start);
  });

  // Filter overlapping matches (prefer earlier and longer matches)
  const nonOverlapping = [];
  let lastEnd = 0;

  for (const m of rawMatches) {
    if (m.start >= lastEnd) {
      nonOverlapping.push(m);
      lastEnd = m.end;
    }
  }

  return nonOverlapping;
}

/**
 * Redacts a single match in the source text by replacing it with a placeholder.
 * 
 * @param {string} text - Original source text
 * @param {PIIMatch} match - The match to redact
 * @param {string} [replacement='[REDACTED]'] - Replacement placeholder
 * @returns {string} Text with the specific match redacted
 */
export function redactMatch(text, match, replacement = '[REDACTED]') {
  if (!text || !match) return text || '';
  const { start, end } = match;
  if (start < 0 || end > text.length || start >= end) {
    return text;
  }
  return text.substring(0, start) + replacement + text.substring(end);
}

/**
 * Redacts all detected matches in the source text from end to start.
 * 
 * @param {string} text - Original source text
 * @param {PIIMatch[]} matches - Array of matches to redact
 * @param {string} [replacement='[REDACTED]'] - Replacement placeholder
 * @returns {string} Text with all matches redacted
 */
export function redactAllMatches(text, matches, replacement = '[REDACTED]') {
  if (!text || !matches || matches.length === 0) return text || '';
  
  // Sort descending by start position so replacements don't invalidate previous offsets
  const sorted = [...matches].sort((a, b) => b.start - a.start);
  let result = text;

  for (const m of sorted) {
    result = redactMatch(result, m, replacement);
  }

  return result;
}

/**
 * Generates an array of text chunks and highlight flags for synchronized backdrop rendering.
 * 
 * @param {string} text - Original source text
 * @param {PIIMatch[]} matches - Detected PII matches
 * @returns {{ text: string, isPII: boolean, type?: string }[]}
 */
export function generateHighlightedSegments(text, matches) {
  if (!text) return [];
  if (!matches || matches.length === 0) {
    return [{ text, isPII: false }];
  }

  const sorted = [...matches].sort((a, b) => a.start - b.start);
  const segments = [];
  let currentIndex = 0;

  for (const m of sorted) {
    if (m.start > currentIndex) {
      segments.push({
        text: text.substring(currentIndex, m.start),
        isPII: false,
      });
    }
    segments.push({
      text: text.substring(m.start, m.end),
      isPII: true,
      type: m.type,
      typeLabel: m.typeLabel,
    });
    currentIndex = m.end;
  }

  if (currentIndex < text.length) {
    segments.push({
      text: text.substring(currentIndex),
      isPII: false,
    });
  }

  return segments;
}
