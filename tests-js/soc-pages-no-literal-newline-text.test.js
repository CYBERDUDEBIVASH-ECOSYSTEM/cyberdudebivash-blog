'use strict';
/**
 * No page may carry the two characters backslash + n as page text.
 *
 * /intel/, /ai-security/ and /malware/ each contained three of them, written between the evidence drawer section, the
 * main grid and the shell scripts (`</section>\n<div class="main-wrap">`, `</script>\n<script ...>`). Between elements
 * inside <body> they are not an escape sequence, they are a text node, so every visitor saw a stray "\n" on the page
 * (measured in a real DOM: 3 visible text nodes per page).
 *
 * The scan covers every hand-maintained HTML page. Generated content (posts/, cve/), vendored/ignored output and raw
 * source captures are excluded, and so are <script>, <style>, comments, <pre> and <code>, where `\n` is legitimate.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist-public', 'posts', 'cve', 'raw-sources']);
const NON_TEXT = [/<script\b[\s\S]*?<\/script\s*>/gi, /<style\b[\s\S]*?<\/style\s*>/gi, /<!--[\s\S]*?-->/g, /<pre\b[\s\S]*?<\/pre\s*>/gi, /<code\b[\s\S]*?<\/code\s*>/gi];

/** Offsets of a literal backslash-n left in the markup once non-text regions are removed. */
function literalNewlineHits(html) {
  let s = html;
  for (const re of NON_TEXT) s = s.replace(re, '');
  const hits = [];
  for (let i = s.indexOf('\\n'); i !== -1; i = s.indexOf('\\n', i + 2)) hits.push(s.slice(Math.max(0, i - 30), i + 22).replace(/\s+/g, ' '));
  return hits;
}

function htmlFiles(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) { if (!SKIP_DIRS.has(entry.name)) htmlFiles(path.join(dir, entry.name), out); }
    else if (entry.name.endsWith('.html')) out.push(path.join(dir, entry.name));
  }
  return out;
}

test('detector flags the defect that shipped and ignores legitimate uses', () => {
  assert.equal(literalNewlineHits('<section>x</section>\\n<div class="main-wrap">').length, 1);
  assert.equal(literalNewlineHits('<script src="/a.js"></script>\\n<script src="/b.js"></script>\\n<!-- c -->').length, 2);
  assert.equal(literalNewlineHits('<script>var s = "a\\nb";</script>').length, 0, 'inside <script>');
  assert.equal(literalNewlineHits('<style>.a::after{content:"\\n"}</style>').length, 0, 'inside <style>');
  assert.equal(literalNewlineHits('<!-- see \\n -->').length, 0, 'inside a comment');
  assert.equal(literalNewlineHits('<pre>line\\nline</pre><code>x\\ny</code>').length, 0, 'inside pre/code');
  assert.equal(literalNewlineHits('<p>ordinary text</p>\n<p>real newline</p>').length, 0, 'a real newline is fine');
});

test('the scan is not vacuous: it reaches the SOC pages that had the defect', () => {
  const files = htmlFiles(ROOT).map(f => path.relative(ROOT, f).split(path.sep).join('/'));
  assert.ok(files.length > 100, `only ${files.length} HTML files found`);
  for (const page of ['intel/index.html', 'ai-security/index.html', 'malware/index.html']) assert.ok(files.includes(page), `${page} not scanned`);
});

test('REGRESSION: no hand-maintained page shows a literal backslash-n as text', () => {
  const offenders = [];
  for (const file of htmlFiles(ROOT)) {
    const hits = literalNewlineHits(fs.readFileSync(file, 'utf8'));
    if (hits.length) offenders.push(`${path.relative(ROOT, file)} (${hits.length}): …${hits[0]}…`);
  }
  assert.deepEqual(offenders, [], `stray "\\n" text in:\n${offenders.join('\n')}`);
});
