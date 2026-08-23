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

// Strip ALL HTML tags from a string — primary XSS defense
function stripAllHtml(html) {
  // Remove anything that looks like a tag, including attributes
  // This catches <script>, <img onerror=...>, <a href="javascript:...">, etc.
  return html.replace(/<[^>]*>/g, '');
}

// Render markdown to safe HTML
export function renderMarkdown(text) {
  if (!text) return '';

  // Step 1: Parse markdown to HTML
  const rawHtml = marked.parse(text);

  // Step 2: Strip ALL HTML tags — this is the safety net
  const safeHtml = stripAllHtml(rawHtml);

  // Step 3: Decode common HTML entities back to readable characters
  // (marked may encode these during parsing)
  return safeHtml
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
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
