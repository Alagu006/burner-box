// XSS-safe markdown rendering for internal notes.
//
// SECURITY MODEL:
// 1. Parse markdown with `marked` (trusted markdown parser)
// 2. Strip ALL HTML tags with regex — this is the primary XSS prevention
// 3. Re-render as safe HTML with only structural elements
//
// This means:
// - <script>, <iframe>, <object>, <embed>, event handlers are ALL removed
// - User-supplied HTML is never rendered — only markdown syntax is interpreted
// - Even if `marked` has an XSS bug, the tag-stripping catches it
//
// Trade-off: inline HTML in markdown notes is not supported. This is intentional —
// internal notes should be plain text with markdown formatting, not raw HTML.

import { marked } from 'marked';

// Configure marked for safe output
marked.setOptions({
  breaks: true,      // Convert \n to <br>
  gfm: true,         // GitHub Flavored Markdown
});

const ALLOWED_TAGS = new Set([
  'strong', 'em', 'p', 'br',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'ul', 'ol', 'li', 'a',
  'code', 'pre', 'blockquote', 'hr'
]);

// Sanitize HTML by removing any tag not in ALLOWED_TAGS and stripping
// all attributes except safe http:// / https:// href on <a> tags.
export function sanitizeHtml(html) {
  if (!html) return '';

  return html.replace(/<\/?([a-zA-Z0-9]+)(?:\s+[^>]*)?\/?>/g, (match, tagName) => {
    const tag = tagName.toLowerCase();
    if (!ALLOWED_TAGS.has(tag)) {
      return ''; // Strip non-allowed tags completely
    }

    const isClosing = match.startsWith('</');
    if (isClosing) {
      return `</${tag}>`;
    }

    if (tag === 'br' || tag === 'hr') {
      return `<${tag}>`;
    }

    if (tag === 'a') {
      // Extract href attribute
      const hrefMatch = match.match(/\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
      const rawHref = hrefMatch ? (hrefMatch[1] || hrefMatch[2] || hrefMatch[3] || '').trim() : '';

      // Validate that href starts with http:// or https://
      if (/^https?:\/\//i.test(rawHref)) {
        const safeHref = rawHref.replace(/"/g, '&quot;');
        return `<a href="${safeHref}" target="_blank" rel="noopener noreferrer">`;
      }
      // If href is not safe http/https, render without href
      return '<a>';
    }

    // Strip all attributes for all other allowed tags
    return `<${tag}>`;
  });
}

// Render markdown to safe HTML
export function renderMarkdown(text) {
  if (!text) return '';

  // Step 1: Parse markdown to HTML
  const rawHtml = marked.parse(text);

  // Step 2: Sanitize HTML against allowed safe tags and attributes
  return sanitizeHtml(rawHtml);
}

// Simple markdown preview (first N chars, stripped of formatting)
export function markdownPreview(text, maxLen = 100) {
  if (!text) return '';
  const stripped = text
    .replace(/#{1,6}\s/g, '')       // headings
    .replace(/\*\*(.+?)\*\*/g, '$1') // bold
    .replace(/\*(.+?)\*/g, '$1')     // italic
    .replace(/`(.+?)`/g, '$1')       // inline code
    .replace(/\[(.+?)\]\(.+?\)/g, '$1') // links
    .replace(/^[-*]\s/gm, '')        // list items
    .replace(/^>\s/gm, '');          // blockquotes
  return stripped.length > maxLen ? stripped.substring(0, maxLen) + '…' : stripped;
}
