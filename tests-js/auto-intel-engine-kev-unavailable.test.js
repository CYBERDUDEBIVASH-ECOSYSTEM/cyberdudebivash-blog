'use strict';
/**
 * The CISA KEV panel on /intel/ and /malware/ is filled by auto-intel-engine.js, which fetches
 * https://www.cisa.gov/.../known_exploited_vulnerabilities.json straight from the visitor's browser. Measured before this change:
 *   - the page's CSP (the live header and the <meta> that security-engine.js injects) does not list www.cisa.gov in connect-src,
 *     so the browser blocks the request ("Connecting to ... violates the following Content Security Policy directive");
 *   - on any failure renderCISAKEV() returned silently, so the panel kept its static "Loading CISA KEV catalog…" text for ever.
 * A panel that looks busy and never resolves reads as a broken product. This test pins the honest behaviour: on failure or an empty
 * list the placeholder is replaced by an explicit unavailable state with a link to the catalog; on success nothing changes.
 *
 * It runs the real engine (and the real runtime-state.js) in a vm with a stub DOM and a stubbed fetch.
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
const PLACEHOLDER = '<div style="color:#9ca3af">Loading CISA KEV catalog…</div>';

const record = {
  id: 'cdb-rec-1', title: 'Plain advisory title', description: 'Plain description.', published: NOW, first_ingested: NOW, severity: 'HIGH', priority: 'HIGH',
  exploited: false, cisa_kev: false, ransomware: true, cvss: 7.5, vendor: 'Vendor', product: 'Product', source: 'example.org', source_url: 'https://example.org/a0',
  cves: ['CVE-2026-10000'], report_id: 'rep-1', report_url: '/reports/x.html',
};
const dashboard = { success: true, data: { section: 'intel', generated_at: NOW, report_generated_at: NOW, freshness_state: 'FRESH', source_platform: 'fixture', items: [record] }, meta: { contract: 'cdb.dashboard-feed.v1' } };

/** kev: 'blocked' (fetch rejects, as a CSP violation does) | 'http-error' | 'empty' | an array of KEV rows */
async function boot(kev, blockedMessage = 'Failed to fetch') {
  const makeEl = tag => {
    const el = {
      tagName: String(tag).toUpperCase(), style: {}, dataset: {}, children: [], childNodes: [], parentNode: null, textContent: '', className: '', id: '', _html: '',
      classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
      setAttribute() {}, getAttribute: () => null, removeAttribute() {}, hasAttribute: () => false, appendChild: c => c, insertBefore: c => c, removeChild() {}, remove() {},
      addEventListener() {}, removeEventListener() {}, querySelector: () => null, querySelectorAll: () => [], closest: () => null, cloneNode: () => makeEl(tag), insertAdjacentHTML() {},
    };
    Object.defineProperty(el, 'innerHTML', { get: () => el._html, set: v => { el._html = String(v); } });
    return el;
  };
  const kevEl = makeEl('div'); kevEl._html = PLACEHOLDER;
  const named = new Map([['intel-feed', makeEl('div')], ['kev-live-list', kevEl]]);
  const document = {
    readyState: 'complete', head: makeEl('head'), body: makeEl('body'), documentElement: makeEl('html'), cookie: '',
    getElementById: id => (named.has(id) ? named.get(id) : (named.set(id, makeEl('div')), named.get(id))),
    querySelector: () => null, querySelectorAll: () => [], createElement: makeEl, addEventListener() {}, removeEventListener() {},
  };
  const json = body => ({ ok: true, status: 200, json: () => Promise.resolve(body) });
  const sandbox = {
    document, console, URL, URLSearchParams, setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0, clearInterval() {}, Event: function Event() {}, CustomEvent: function CustomEvent() {},
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} }, sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    location: { pathname: '/intel/', origin: 'https://blog.cyberdudebivash.in', href: 'https://blog.cyberdudebivash.in/intel/', search: '', hash: '' },
    DOMParser: function DOMParser() { this.parseFromString = html => ({ body: { textContent: String(html).replace(/<[^>]*>/g, '') } }); },
    fetch: url => {
      const u = String(url);
      if (u.includes('/api/v1/intel')) return Promise.resolve(json(dashboard));
      if (/cisa\.gov/.test(u)) {
        if (kev === 'blocked') return Promise.reject(new TypeError(blockedMessage));
        if (kev === 'http-error') return Promise.resolve({ ok: false, status: 503, json: () => Promise.reject(new Error('not json')) });
        return Promise.resolve(json({ vulnerabilities: kev === 'empty' ? [] : kev }));
      }
      return Promise.resolve({ ok: false, status: 404, json: () => Promise.reject(new Error('stub')) });
    },
  };
  sandbox.window = sandbox; sandbox.self = sandbox; sandbox.globalThis = sandbox;
  const ctx = vm.createContext(sandbox);
  vm.runInContext(RUNTIME_STATE, ctx, { filename: 'runtime-state.js' });
  vm.runInContext(ENGINE, ctx, { filename: 'auto-intel-engine.js' });
  for (let i = 0; i < 8; i++) await new Promise(r => setImmediate(r));
  return kevEl.innerHTML;
}

const ROWS = [{ cveID: 'CVE-2026-1', dateAdded: '2026-11-01', vendorProject: 'Vend', product: 'Prod', requiredAction: 'Apply updates', cvssScore: 9.8 }];

test('REGRESSION: a blocked CISA fetch (CSP/CORS/offline) replaces the Loading placeholder with an explicit unavailable state', async () => {
  const html = await boot('blocked');
  assert.doesNotMatch(html, /Loading/, 'the panel is still showing the static Loading placeholder');
  assert.match(html, /class="kev-unavailable"/);
  assert.match(html, /Live CISA KEV list is unavailable in this view\./);
});

test('REGRESSION: an HTTP error or an empty catalog resolves to the same explicit state', async () => {
  for (const kind of ['http-error', 'empty']) {
    const html = await boot(kind);
    assert.doesNotMatch(html, /Loading/, `${kind}: still loading`);
    assert.match(html, /class="kev-unavailable"/, `${kind}: no unavailable state`);
  }
});

test('the unavailable state links to the official CISA catalog with a safe rel, using constant markup only', async () => {
  const html = await boot('blocked', '<img src=x onerror="window.__pwn=1"> blocked');
  const link = html.match(/<a href="([^"]+)" target="_blank" rel="([^"]+)"/);
  assert.ok(link, 'no catalog link');
  assert.equal(link[1], 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog');
  assert.match(link[2], /noopener/);
  assert.doesNotMatch(html, /<\s*img\b|__pwn|onerror/i, 'the error message must never reach the markup');
});

test('behaviour on success is unchanged: KEV rows render and the unavailable state is absent', async () => {
  const html = await boot(ROWS);
  assert.match(html, /class="kev-item"/);
  assert.match(html, /CVE-2026-1/);
  assert.doesNotMatch(html, /kev-unavailable|Loading/);
});

test('source contract: the failure branch no longer returns silently', () => {
  const start = ENGINE.indexOf('function renderCISAKEV(');
  const body = ENGINE.slice(start, ENGINE.indexOf('function escHTML(', start));
  assert.doesNotMatch(body, /if \(err \|\| !items\.length\) return;/);
  assert.match(body, /kev-unavailable/);
});
