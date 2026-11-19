import { describe, it, expect } from 'vitest';
import { renderMarkdown, sanitizeHtml } from '../lib/markdown.js';

describe('Frontend Markdown Security & Sanitization', () => {
  it('allows safe formatting tags to survive rendering', () => {
    const input = `
# Main Header
## Sub Header

This is **bold text** and *italic text*.

Here is a list:
- Item 1
- Item 2

> Important note blockquote

Inline \`code snippet\` and a [Safe Link](https://freedom.press/guide).
`;

    const rendered = renderMarkdown(input);

    expect(rendered).toContain('<h1>Main Header</h1>');
    expect(rendered).toContain('<h2>Sub Header</h2>');
    expect(rendered).toContain('<strong>bold text</strong>');
    expect(rendered).toContain('<em>italic text</em>');
    expect(rendered).toContain('<ul>');
    expect(rendered).toContain('<li>Item 1</li>');
    expect(rendered).toContain('<blockquote>');
    expect(rendered).toContain('<code>code snippet</code>');
    expect(rendered).toContain('<a href="https://freedom.press/guide" target="_blank" rel="noopener noreferrer">Safe Link</a>');
  });

  it('strips XSS script tags and event handlers', () => {
    const maliciousInput = `
<script>alert("XSS")</script>
<img src="x" onerror="alert(1)" />
<svg onload="alert('svg xss')"></svg>
<iframe src="https://attacker.test"></iframe>
`;

    const rendered = renderMarkdown(maliciousInput);

    expect(rendered).not.toContain('<script');
    expect(rendered).not.toContain('onerror');
    expect(rendered).not.toContain('<svg');
    expect(rendered).not.toContain('<iframe');
  });

  it('strips dangerous javascript: and data: URIs in links while preserving safe http/https', () => {
    const input = `
[Legitimate Link](https://secure.org/report)
[Dangerous JS](javascript:alert(document.cookie))
[Dangerous Data](data:text/html,<script>alert(1)</script>)
[Plain HTTP](http://insecure-but-safe-scheme.test)
`;

    const rendered = renderMarkdown(input);

    expect(rendered).toContain('<a href="https://secure.org/report"');
    expect(rendered).toContain('<a href="http://insecure-but-safe-scheme.test"');
    expect(rendered).not.toContain('href="javascript:');
    expect(rendered).not.toContain('href="data:');
    expect(rendered).toContain('<a>Dangerous JS</a>');
    expect(rendered).toContain('<a>Dangerous Data</a>');
  });
});
