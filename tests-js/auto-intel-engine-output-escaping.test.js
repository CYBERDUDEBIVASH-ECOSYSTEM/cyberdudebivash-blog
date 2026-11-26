'use strict';
/**
 * auto-intel-engine.js renders the /intel/, /ai-security/ and /malware/ dashboards from `/api/v1/intel?action=dashboard`.
 * That API passes feed strings through unchanged (`cves` is any array of strings, `description` is the raw feed text), so the
 * browser is the only place they can be neutralised. Measured in a real browser before this change, a record carrying markup in
 * `cves` or `description` executed script on all three pages:
 *   - the CVE badge wrote the id raw into href, title and text;
 *   - stripHTML() assigned the description to innerHTML of a detached <div>, which still loads <img> and fires onerror;
 *   - the ticker, the CISA KEV badge and the share button's inline onclick string also interpolated raw values.
 *
 * This test runs the real engine (and the real runtime-state.js it depends on) in a vm with a stub DOM and a stubbed fetch,
 * records EVERY innerHTML assignment on every element (a detached element counts), and fails if feed text reaches any of them as markup.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const ENGINE = fs.readFileSync(path.join(ROOT, 'auto-intel-engine.js'), 'utf8');
const RUNTIME_STATE = fs.readFileSync(path.join(ROOT, 'runtime-state.js'), 'utf8');

const NOW = new Date().toISOString();
// a real tag opening, or an attribute breakout. Escaped text such as `&lt;img src=x onerror=&quot;…` is harmless and must not trip this.
const RAW = /<\s*(img|script|svg|iframe|object|style)\b|data-pwn="1/i;
const IMG = '<img src=x onerror="window.__pwn=1">';
const BREAKOUT = 'x" data-pwn="1';

function item(overrides = {}) {
  return {
    id: 'cdb-rec-1', title: 'Plain advisory title', description: 'Plain description of the advisory.', published: NOW, first_ingested: NOW,
    severity: 'HIGH', priority: 'HIGH', exploited: false, cisa_kev: false, ransomware: true, cvss: 7.5, vendor: 'Vendor', product: 'Product',
    source: 'example.org', source_url: 'https://example.org/a0', cves: ['CVE-2026-10000'], report_id: 'rep-1', report_url: '/reports/x.html', ...overrides,
  };
}
const dashboard = items => ({ success: true, data: { section: 'intel', generated_at: NOW, report_generated_at: NOW, freshness_state: 'FRESH', source_platform: 'fixture', items }, meta: { contract: 'cdb.dashboard-feed.v1' } });

/** Boot the real engine against `items`; resolves with everything the page would have written. */
async function boot({ items, kev } = {}) {
  const assigned = [];
  const makeEl = tag => {
    const el = {
      tagName: String(tag).toUpperCase(), style: {}, dataset: {}, children: [], childNodes: [], parentNode: null, textContent: '', className: '', id: '', _html: '',
      classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
      setAttribute() {}, getAttribute: () => null, removeAttribute() {}, hasAttribute: () => false, appendChild: c => c, insertBefore: c => c, removeChild() {}, remove() {},
      addEventListener() {}, removeEventListener() {}, querySelector: () => null, querySelectorAll: () => [], closest: () => null, cloneNode: () => makeEl(tag),
      insertAdjacentHTML(_pos, html) { assigned.push({ tag: el.tagName, html: String(html) }); },
    };
    Object.defineProperty(el, 'innerHTML', { get: () => el._html, set: v => { el._html = String(v); assigned.push({ tag: el.tagName, html: el._html }); } });
    return el;
  };
  const container = makeEl('div'); const ticker = makeEl('div'); const kevEl = makeEl('div'); const named = new Map([['intel-feed', container]]);
  if (kev) named.set('kev-live-list', kevEl);
  const document = {
    readyState: 'complete', head: makeEl('head'), body: makeEl('body'), documentElement: makeEl('html'), cookie: '',
    getElementById: id => (named.has(id) ? named.get(id) : (id === 'kev-live-list' ? null : (named.set(id, makeEl('div')), named.get(id)))),
    querySelector: sel => (/ticker/.test(sel) ? ticker : null), querySelectorAll: () => [], createElement: makeEl, addEventListener() {}, removeEventListener() {},
  };
  const json = body => ({ ok: true, status: 200, json: () => Promise.resolve(body) });
  const sandbox = {
    document, console, URL, URLSearchParams, setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0, clearInterval() {}, Event: function Event() {}, CustomEvent: function CustomEvent() {},
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} }, sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    location: { pathname: '/intel/', origin: 'https://blog.cyberdudebivash.in', href: 'https://blog.cyberdudebivash.in/intel/', search: '', hash: '' },
    // text extraction only; the security property is asserted on the recorded innerHTML assignments, not on this stub
    DOMParser: function DOMParser() { this.parseFromString = html => ({ body: { textContent: String(html).replace(/<[^>]*>/g, '') } }); },
    fetch: url => {
      const u = String(url);
      if (u.includes('/api/v1/intel')) return Promise.resolve(json(dashboard(items)));
      if (/cisa\.gov/.test(u) && kev) return Promise.resolve(json({ vulnerabilities: kev }));
      return Promise.resolve({ ok: false, status: 404, json: () => Promise.reject(new Error('stub')) });
    },
  };
  sandbox.window = sandbox; sandbox.self = sandbox; sandbox.globalThis = sandbox;
  const ctx = vm.createContext(sandbox);
  vm.runInContext(RUNTIME_STATE, ctx, { filename: 'runtime-state.js' });
  vm.runInContext(ENGINE, ctx, { filename: 'auto-intel-engine.js' });
  for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r));
  return { assigned, container, ticker, kevEl, ctx, html: assigned.map(a => a.html).join('\n') };
}

// ── harness sanity: the detector must not trip on the engine's own markup, and the page must really render ──────────────────
test('ordinary records render, and the engine\'s own markup is not flagged by the detector', async () => {
  const r = await boot({ items: [item()] });
  assert.match(r.container.innerHTML, /class="intel-post"/, 'no card was rendered; the harness is not exercising the renderer');
  assert.doesNotMatch(r.html, RAW);
});

// ── the regression: feed text must never reach any innerHTML as markup ────────────────────────────────────────────────────────
for (const field of ['id', 'title', 'description', 'source', 'report_id', 'priority', 'vendor', 'product', 'cves']) {
  for (const payload of [IMG, BREAKOUT, `'><script>alert(1)</script>`]) {
    test(`REGRESSION: hostile ${field} (${payload.slice(0, 18)}…) never reaches innerHTML as markup`, async () => {
      const value = field === 'cves' ? ['CVE-2026-10000' + payload, payload] : payload;
      const r = await boot({ items: [item({ [field]: value, ...(field === 'title' ? { title: 'ransomware ' + payload } : {}) })] });
      assert.match(r.container.innerHTML, /class="intel-post"/, 'record was not rendered');
      assert.doesNotMatch(r.html, RAW, `${field}: raw markup reached an innerHTML assignment`);
    });
  }
}

test('REGRESSION: stripHTML never assigns feed text to innerHTML, even on a detached element', async () => {
  const r = await boot({ items: [item({ description: 'Intro ' + IMG + ' tail' })] });
  const leaked = r.assigned.filter(a => /<\s*img\b/i.test(a.html));
  assert.deepEqual(leaked.map(a => a.tag), [], 'feed text was assigned to innerHTML of an element (a detached <div> still fires onerror)');
  // the text itself survives, as text
  assert.match(r.container.innerHTML, /Intro/);
});

test('REGRESSION: the ticker escapes the CVE id', async () => {
  const r = await boot({ items: [item({ exploited: true, cves: ['CVE-2026-10000' + IMG] })] });
  assert.doesNotMatch(r.ticker.innerHTML, RAW);
  assert.match(r.ticker.innerHTML, /ticker-item/);
});

test('REGRESSION: the CISA KEV badge and date are escaped', async () => {
  const r = await boot({ items: [item()], kev: [{ cveID: 'CVE-2026-1' + IMG, dateAdded: '2026-11-01' + IMG, vendorProject: 'v', product: 'p', requiredAction: 'a', cvssScore: 9 }] });
  assert.match(r.kevEl.innerHTML, /kev-item/, 'KEV list was not rendered');
  assert.doesNotMatch(r.kevEl.innerHTML, RAW);
});

test('REGRESSION: no inline onclick carries feed data inside a JS string literal', async () => {
  const hostile = `\\');window.__pwn=1;//`;
  const r = await boot({ items: [item({ title: 'ransomware ' + hostile })] });
  const handlers = [...r.html.matchAll(/onclick="([^"]*)"/g)].map(m => m[1]);
  assert.ok(handlers.some(h => h.startsWith('sharePost(')), 'share button not rendered');
  for (const h of handlers) assert.ok(!h.includes('__pwn'), `feed text reached an inline handler: ${h}`);
  assert.ok(handlers.includes('sharePost(this.dataset.shareTitle,this.dataset.shareUrl)'));
});

// ── behaviour for legitimate data is unchanged ───────────────────────────────────────────────────────────────────────────────
test('a well-formed CVE id renders exactly the link the page produced before', async () => {
  const r = await boot({ items: [item({ cves: ['CVE-2026-10000', 'CVE-2025-123456'] })] });
  assert.ok(r.container.innerHTML.includes('<a class="cve-badge" href="/cve/CVE-2026-10000.html" title="CVE-2026-10000">CVE-2026-10000</a>'));
  assert.ok(r.container.innerHTML.includes('<a class="cve-badge" href="/cve/CVE-2025-123456.html" title="CVE-2025-123456">CVE-2025-123456</a>'));
});

test('a malformed id is shown as inert escaped text, not as a link', async () => {
  const r = await boot({ items: [item({ cves: ['not-a-cve <b>x</b>'] })] });
  assert.ok(r.container.innerHTML.includes('<span class="cve-badge">not-a-cve &lt;b&gt;x&lt;/b&gt;</span>'));
  assert.doesNotMatch(r.container.innerHTML, /href="\/cve\/not-a-cve/);
});

test('the share button still hands sharePost the original title and url', async () => {
  const title = `O'Brien & "Co" <b>x</b>`;
  const r = await boot({ items: [item({ title: 'ransomware ' + title })] });
  const attr = name => { const m = r.container.innerHTML.match(new RegExp(`${name}="([^"]*)"`)); return m && m[1].replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&'); };
  assert.equal(attr('data-share-title'), 'ransomware ' + title);
  assert.equal(attr('data-share-url'), 'https://example.org/a0');
});

test('description text is kept as text and markup is dropped', async () => {
  const r = await boot({ items: [item({ description: 'Alpha <b>bold</b> beta &amp; gamma' })] });
  assert.match(r.container.innerHTML, /Alpha bold beta/);
  assert.doesNotMatch(r.container.innerHTML, /<b>bold<\/b>/);
});

// ── source contract ──────────────────────────────────────────────────────────────────────────────────────────────────────────
test('source contract: stripHTML parses with DOMParser and assigns no innerHTML; the CVE link goes through cveBadgeHTML', () => {
  const start = ENGINE.indexOf('function stripHTML(');
  const body = ENGINE.slice(start, ENGINE.indexOf('\n  }', start));
  assert.match(body, /new DOMParser\(\)/);
  assert.doesNotMatch(body, /innerHTML/);
  assert.match(ENGINE, /item\.cveIds\.map\(cveBadgeHTML\)/);
  assert.doesNotMatch(ENGINE, /href="\/cve\/' \+ c \+/);
  assert.doesNotMatch(ENGINE, /sharePost\('\$\{/);
});
