'use strict';
/**
 * SOC front end: text that comes from data must never be written into innerHTML as markup.
 *
 * Two sites mixed escaped and raw values:
 *   - soc-hybrid-workspace.js built the "selected record" preview from card text; the CVE pivot and the severity were
 *     concatenated raw (textContent is decoded text, so re-inserting it as HTML turns escaped markup back into markup).
 *   - api-dashboard.html wrote server strings (user id, tier, endpoint, limit) into the key card with no escaping, and
 *     `data.user.tier.toUpperCase()` threw on a missing tier, which the surrounding catch reported as "check your
 *     connection".
 *
 * The functions are extracted from the real files and executed, so a change to the shipped code is what is tested.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const HYBRID = fs.readFileSync(path.join(ROOT, 'soc-hybrid-workspace.js'), 'utf8');
const DASH = fs.readFileSync(path.join(ROOT, 'api-dashboard.html'), 'utf8');

/** Source text of `function name(...) { ... }` (balanced braces; template ${} and object literals balance). */
function extractFunction(src, name) {
  const start = src.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `function ${name} not found`);
  const open = src.indexOf('{', src.indexOf(')', start));
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(start, i + 1);
  }
  throw new Error(`unbalanced braces in ${name}`);
}

const PAYLOADS = [
  '<img src=x onerror=alert(1)>',
  '"><script>alert(2)</script>',
  "'><svg onload=alert(3)>",
];
// a tag that could execute: escaped text such as `&lt;img ... onerror=...&gt;` is harmless and must not trip this
const RAW = /<\s*(img|script|svg|iframe|object)\b/i;

// ── soc-hybrid-workspace.js: previewMarkup ───────────────────────────────────────────────────────────────────────────
function previewFor({ record = 'cdb-rec-1', sev = 'HIGH', source = 'CISA', report = 'rep-9', cve = 'CVE-2026-1234' }) {
  const el = text => (text === null ? null : { textContent: ` ${text} ` });
  const card = {
    querySelector: sel => (sel === '.source-chip' ? el(source) : sel === '.cve-badge' ? el(cve) : null),
  };
  const ctx = vm.createContext({
    recordId: () => record, severity: () => sev, reportId: () => report,
  });
  vm.runInContext(`${extractFunction(HYBRID, 'escHtml')}\n${extractFunction(HYBRID, 'previewMarkup')}\nthis.out = previewMarkup;`, ctx);
  return ctx.out(card);
}

test('REGRESSION: hostile text in any card field reaches the preview only as escaped text', () => {
  for (const field of ['record', 'sev', 'source', 'report', 'cve']) {
    for (const payload of PAYLOADS) {
      const html = previewFor({ [field]: payload });
      assert.doesNotMatch(html, RAW, `${field}: raw markup reached the preview for ${payload}`);
      assert.ok(html.includes('&lt;') || html.includes('&quot;') || html.includes('&#39;'), `${field}: payload should be visible as escaped text`);
    }
  }
});

test('ordinary values produce exactly the markup the page produced before', () => {
  const html = previewFor({});
  assert.equal(
    html,
    '<div class="ioc-sample"><strong>Record</strong><br>cdb-rec-1</div>' +
    '<div class="ioc-sample"><strong>Severity</strong><br>HIGH</div>' +
    '<div class="ioc-sample"><strong>Source</strong><br>CISA</div>' +
    '<div class="ioc-sample"><strong>Canonical report</strong><br>rep-9</div>' +
    '<div class="ioc-sample"><strong>CVE pivot</strong><br>CVE-2026-1234</div>',
  );
});

test('a card without a CVE badge or source keeps the same fallbacks', () => {
  const card = { querySelector: () => null };
  const ctx = vm.createContext({ recordId: () => null, severity: () => 'LOW', reportId: () => null });
  vm.runInContext(`${extractFunction(HYBRID, 'escHtml')}\n${extractFunction(HYBRID, 'previewMarkup')}\nthis.out = previewMarkup;`, ctx);
  const html = ctx.out(card);
  assert.match(html, /<strong>Record<\/strong><br>—<\/div>/);
  assert.match(html, /<strong>Source<\/strong><br>—<\/div>/);
  assert.match(html, /<strong>Canonical report<\/strong><br>Not bound<\/div>/);
  assert.doesNotMatch(html, /CVE pivot/);
});

test('the file has no remaining raw textContent concatenation into markup, and the preview uses the builder', () => {
  assert.doesNotMatch(HYBRID, /'\s*\+\s*cv\.textContent\.trim\(\)\s*\+/);
  assert.match(HYBRID, /preview\.innerHTML\s*=\s*previewMarkup\(card\)/);
});

// ── api-dashboard.html: keyMetaHtml ──────────────────────────────────────────────────────────────────────────────────
function keyMeta(data) {
  const ctx = vm.createContext({});
  vm.runInContext(`${extractFunction(DASH, 'esc')}\n${extractFunction(DASH, 'keyMetaHtml')}\nthis.out = keyMetaHtml;`, ctx);
  return ctx.out(data);
}

test('REGRESSION: server strings in the key card are escaped', () => {
  for (const payload of PAYLOADS) {
    const html = keyMeta({
      user: { user_id: payload, tier: payload }, rate_limit: { requests_per_day: payload }, usage: { endpoint: payload },
    });
    assert.doesNotMatch(html, RAW, `raw markup reached the key card for ${payload}`);
  }
});

test('ordinary registration data renders the same visible text as before', () => {
  const html = keyMeta({ user: { user_id: 'usr_123', tier: 'pro' }, rate_limit: { requests_per_day: 5000 }, usage: { endpoint: '/api/v1/intel/live' } });
  const text = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  assert.equal(text, 'User ID: usr_123 Tier: PRO Limit: 5000 requests/day Usage: /api/v1/intel/live');
});

test('a response missing optional objects or a tier no longer throws', () => {
  assert.doesNotThrow(() => keyMeta({ user: { user_id: 'usr_1' } }));
  assert.doesNotThrow(() => keyMeta({}));
  assert.doesNotThrow(() => keyMeta(null));
});

test('the registration handler renders the card through the escaping builder', () => {
  assert.match(DASH, /getElementById\('key-meta'\)\.innerHTML\s*=\s*keyMetaHtml\(data\)/);
  assert.doesNotMatch(DASH, /\$\{data\.user\.user_id\}|\$\{data\.usage\.endpoint\}/);
});
