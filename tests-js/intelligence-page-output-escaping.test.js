'use strict';
/**
 * intelligence.html renders NVD, CISA KEV and RSS items (fetched in the visitor's browser, directly or through public CORS proxies)
 * into cards with innerHTML. Measured in a real browser before this change, renderCard() executed 37 distinct payloads across
 * 132 renders: title, link (attribute breakout), date, id, cveID, severity, vector, cwes, product, dueDate, vendorProject,
 * vulnerabilityName, and entity-encoded description / requiredAction / shortDescription (strip() decoded `&lt;` back into live markup).
 *
 * Production is protected today only by a <meta http-equiv="Content-Security-Policy"> that blocks the proxy hosts, so the sink was
 * latent; it must not depend on that. This test extracts the page's real functions and runs them in a vm. DOMParser is stubbed with an
 * entity-decoding text extractor, which is exactly the situation the escaping has to survive: decoded text containing `<` and `"`.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const PAGE = fs.readFileSync(path.join(__dirname, '..', 'intelligence.html'), 'utf8');

function extractFunction(src, name) {
  const start = src.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `function ${name} not found in intelligence.html`);
  const open = src.indexOf('{', src.indexOf(')', start));
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(start, i + 1);
  }
  throw new Error(`unbalanced braces in ${name}`);
}

const FUNCTIONS = ['cdbPlain', 'cdbEsc', 'cdbSafeUrl', 'strip', 'truncate', 'severityFromStr', 'scoreSeverity', 'cvssColor', 'fmtDate', 'relativeTime', 'renderCard', 'renderError'];
const decode = s => s.replace(/&#(\d+);/g, (_, n) => String.fromCharCode(+n)).replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
function load() {
  const sandbox = {
    window: { location: { href: 'https://blog.cyberdudebivash.in/intelligence.html' } }, URL, Date, Math, String, Number, JSON,
    // text extraction as a browser's DOMParser(...).body.textContent would do it: tags dropped, entities decoded
    DOMParser: function DOMParser() { this.parseFromString = html => ({ body: { textContent: decode(String(html).replace(/<[^>]*>/g, '')) } }); },
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(`${FUNCTIONS.map(f => extractFunction(PAGE, f)).join('\n')}\nthis.api = { renderCard, renderError, cdbSafeUrl, cdbEsc, cdbPlain };`, ctx);
  return ctx.api;
}
const api = load();

// a real tag opening, or an attribute breakout marker; escaped text such as `&lt;img src=x onerror=&quot;…` is harmless
const RAW = /<\s*(img|script|svg|iframe|object|style)\b|data-pwn="1/i;
const NOW = new Date().toISOString();
const BASE = {
  rss: { type: 'rss', sourceName: 'The Hacker News', title: 'T', description: 'D', link: 'https://example.org/a', date: NOW, pubDate: NOW },
  nvd: { type: 'nvd', id: 'CVE-2026-1', title: 'CVE-2026-1', description: 'D', score: 9.8, severity: 'CRITICAL', vector: 'CVSS:3.1/AV:N', cwes: ['CWE-79'], published: NOW, link: 'https://nvd.nist.gov/x', sourceName: 'NVD' },
  kev: { type: 'kev', cveID: 'CVE-2026-2', vulnerabilityName: 'V', shortDescription: 'S', vendorProject: 'Vend', product: 'Prod', requiredAction: 'Patch', dueDate: '2026-12-01', dateAdded: '2026-11-01', cisaRequired: true, link: 'https://www.cisa.gov/x', sourceName: 'CISA' },
};
const FIELDS = ['title', 'description', 'summary', 'content', 'link', 'url', 'date', 'pubDate', 'dateAdded', 'id', 'cveID', 'sourceName', 'severity', 'vector', 'cwes0', 'vendorProject', 'product', 'requiredAction', 'dueDate', 'vulnerabilityName', 'shortDescription', 'published', 'score'];
const PAYLOADS = {
  raw: `"'><img src=x onerror="window.__pwn=1">`,
  entity: `&lt;img src=x onerror="window.__pwn=1"&gt;`,
  breakout: 'x" data-pwn="1',
  script: `'><script>alert(1)</script>`,
};

test('the extracted functions are the real ones (harness sanity)', () => {
  const html = api.renderCard(BASE.rss, 'X');
  assert.match(html, /class="intel-card/);
  assert.match(html, /<h3 class="card-title">/);
});

for (const type of Object.keys(BASE)) {
  for (const field of FIELDS) {
    for (const [kind, payload] of Object.entries(PAYLOADS)) {
      test(`REGRESSION: hostile ${type}.${field} (${kind}) never reaches the card as markup`, () => {
        const item = JSON.parse(JSON.stringify(BASE[type]));
        if (field === 'cwes0') item.cwes = [payload]; else item[field] = payload;
        let html;
        try { html = api.renderCard(item, 'X'); } catch (e) { return; } // a throw renders nothing; that is a robustness question, not a leak
        assert.doesNotMatch(html, RAW, `${type}.${field} (${kind}): raw markup reached the card`);
        assert.doesNotMatch(html, /href="\s*javascript:/i);
      });
    }
  }
}

test('REGRESSION: link targets are limited to http(s)', () => {
  for (const bad of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'data:text/html,<script>alert(1)</script>', 'vbscript:x', ' \tjavascript:alert(1)']) {
    assert.equal(api.cdbSafeUrl(bad), '#', bad);
    const html = api.renderCard({ ...BASE.rss, link: bad }, 'X');
    assert.doesNotMatch(html, /href="[^"]*javascript:/i);
  }
  assert.equal(api.cdbSafeUrl('https://example.org/a?x=1&y=2'), 'https://example.org/a?x=1&y=2');
});

test('REGRESSION: the error message and the archive date group are escaped', () => {
  assert.doesNotMatch(api.renderError(`<img src=x onerror="window.__pwn=1">`, 'live-breaking'), RAW);
  assert.match(api.renderError('', 'live-breaking'), /Unable to load data from this source/);
  assert.match(PAGE, /archive-date-title">📅 \$\{cdbEsc\(date\)\}/);
});

// ── legitimate content renders as before ───────────────────────────────────────────────────────────────────────────────────────
test('entities in titles and markup in descriptions display as text, exactly as the page showed them', () => {
  const html = api.renderCard({ ...BASE.rss, title: 'Tom &amp; Jerry&#8217;s &quot;edge&quot; gateway', description: '<p>Use <b>Remote</b> code &amp; more: R&amp;D found a flaw.</p>' }, 'X');
  assert.ok(html.includes('Tom &amp; Jerry’s &quot;edge&quot; gateway'));
  assert.ok(html.includes('Use Remote code &amp; more: R&amp;D found a flaw.'));
  assert.doesNotMatch(html, /<b>Remote<\/b>/);
});

test('NVD and KEV cards keep their badges, meta rows and links', () => {
  const nvd = api.renderCard(BASE.nvd, 'X');
  assert.ok(nvd.includes('<span class="severity-badge critical">CVSS 9.8</span>'));
  assert.ok(nvd.includes('<span class="severity-badge critical">CRITICAL</span>'));
  assert.ok(nvd.includes('CVSS:3.1/AV:N') && nvd.includes('CWE-79'));
  assert.ok(nvd.includes('<a href="https://nvd.nist.gov/x" target="_blank" rel="noopener noreferrer">CVE-2026-1</a>'));
  const kev = api.renderCard(BASE.kev, 'X');
  assert.ok(kev.includes('<span class="cisa-badge">CISA KEV</span>'));
  assert.ok(kev.includes('Vend Prod') && kev.includes('Patch') && kev.includes('2026-12-01'));
});

test('ampersands in link query strings are encoded correctly for an attribute', () => {
  const html = api.renderCard({ ...BASE.rss, link: 'https://example.org/a?x=1&y=2' }, 'X');
  assert.ok(html.includes('href="https://example.org/a?x=1&amp;y=2"'));
});

// ── source contract ────────────────────────────────────────────────────────────────────────────────────────────────────────────
test('source contract: no raw feed value is interpolated into renderCard, and strip() no longer decodes into markup', () => {
  const body = extractFunction(PAGE, 'renderCard');
  assert.doesNotMatch(body, /href="\$\{link\}"/);
  assert.doesNotMatch(body, /\$\{(title|desc|cveId|timeAgo|item\.[A-Za-z]+(\[0\])?)(\.substring\([^)]*\))?\}/);
  assert.doesNotMatch(extractFunction(PAGE, 'strip'), /replace\(\/&lt;/);
  assert.match(extractFunction(PAGE, 'cdbPlain'), /new DOMParser\(\)/);
});
