'use strict';
// Option A: switching a path from "static asset" to "runtime object" must change NO customer-visible
// header. The static site's headers come from the build's own `_headers` rules (canonical); the
// Worker's runtime responses carry a copy (workers/lib/runtime-feed-headers.js). This test EVALUATES
// the build's rules the way Cloudflare does and fails if the copy drifts.
//
// What this prevents (found reviewing activation): without these headers the feeds lost
// `Access-Control-Allow-Origin: *` (cross-origin consumers break) and dossiers lost their
// Content-Security-Policy, so the Worker baseline applied `default-src 'none'` and pages rendered unstyled.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { serveFeed, serveDossier, PREFIX } = require('../workers/lib/runtime-feed');
const HEADERS = require('../workers/lib/runtime-feed-headers');
const { HEADERS_FILE_CONTENT } = require('../scripts/build-cloudflare-assets.js');
const { handleFetch } = require('../workers/lib/router');

// ---- a faithful evaluator of the `_headers` file format ----
function parseRules(text) {
  const rules = []; let cur = null;
  for (const raw of text.split('\n')) {
    if (!raw.trim() || /^\s*#/.test(raw)) continue;
    if (!/^\s/.test(raw)) { cur = { pattern: raw.trim(), lines: [] }; rules.push(cur); } else cur.lines.push(raw.trim());
  }
  return rules;
}
const matches = (pattern, path) => new RegExp('^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '(.*)') + '$').test(path);
/** Effective headers for a path: later matching rules JOIN earlier values; `! Name` detaches. */
function effectiveStatic(path) {
  const out = new Map();
  for (const rule of parseRules(HEADERS_FILE_CONTENT)) {
    if (!matches(rule.pattern, path)) continue;
    for (const line of rule.lines) {
      if (line.startsWith('!')) { out.delete(line.slice(1).trim().toLowerCase()); continue; }
      const i = line.indexOf(':');
      const name = line.slice(0, i).trim().toLowerCase(); const value = line.slice(i + 1).trim();
      out.set(name, out.has(name) ? out.get(name) + ', ' + value : value);
    }
  }
  return out;
}

test('evaluator sanity: later rules join, `!` detaches (so the comparison below means something)', () => {
  const real = HEADERS_FILE_CONTENT;
  assert.equal(effectiveStatic('/api/intel/live.json').get('cache-control'), 'public, max-age=60, must-revalidate', '`! Cache-Control` must detach the broader /api/intel/* value');
  assert.ok(effectiveStatic('/live-intel.json').get('access-control-allow-origin') === '*');
  assert.ok(real.includes('/live-intel.json') && real.includes('/rss.xml') && real.includes('/*.html'));
  assert.match(effectiveStatic('/posts/example-post.html').get('content-security-policy'), /^default-src 'self'/, 'dossiers get their CSP from the /*.html rule');
});

// ---- fixtures ----
const NOW = Date.parse('2026-11-24T16:00:00Z');
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const object = (body, meta) => ({ size: Buffer.byteLength(body), customMetadata: meta || { sha256: sha(body), 'generated-at': iso(NOW - 120000) }, body: new Response(body).body });
const bucketOf = (map) => ({ async get(key) { return map[key] ? map[key]() : null; } });
const req = (path, init) => new Request('https://soc.cyberdudebivash.in' + path, init);
const PROVENANCE_AND_VALIDATORS = new Set(['etag', 'x-feed-source', 'x-feed-sha256', 'x-feed-generated-at', 'content-length']);

const CASES = [
  ['/live-intel.json', 'feed'], ['/api/intel/live.json', 'feed'], ['/rss.xml', 'feed'],
  ['/posts/cve-2026-135696.html', 'dossier'],
];
async function runtimeResponse(path, kind, method = 'GET') {
  const body = kind === 'dossier' ? '<!doctype html><title>x</title>' : '{"a":1}';
  if (kind === 'dossier') {
    const b = bucketOf({ [PREFIX + path.slice(1)]: () => object(body, { sha256: sha(body) }) });
    return serveDossier(req(path, { method }), { RUNTIME_FEED: b }, path);
  }
  const b = bucketOf({ [PREFIX + path.slice(1)]: () => object(body) });
  return serveFeed(req(path, { method }), { RUNTIME_FEED: b }, path, null, NOW);
}

for (const [path, kind] of CASES) {
  test('runtime ' + kind + ' ' + path + ' carries EVERY header the static build gives the same path, with identical values', async () => {
    const want = effectiveStatic(path);
    assert.ok(want.size >= 6, 'the static rules define headers for ' + path);
    const r = await runtimeResponse(path, kind);
    assert.equal(r.status, 200);
    for (const [name, value] of want) assert.equal(r.headers.get(name), value, path + ' ' + name);
    // Nothing unexplained is added: everything else is a validator or provenance header, or the Content-Type
    // the static asset service derives from the file extension when `_headers` does not set one.
    const extra = [...r.headers.keys()].filter((n) => !want.has(n) && !PROVENANCE_AND_VALIDATORS.has(n) && n !== 'content-type');
    assert.deepEqual(extra, [], path + ' has undocumented headers');
    if (!want.has('content-type')) assert.ok(r.headers.get('content-type'), path + ' still has a Content-Type');
  });
}

test('the router path (baseline headers applied) keeps those headers: the Worker baseline never replaces a static-parity header', async () => {
  const body = '{"a":1}';
  const env = {
    RUNTIME_FEED: bucketOf({ [PREFIX + 'live-intel.json']: () => object(body) }),
    ASSETS: { async fetch() { return new Response('static', { status: 200 }); } },
  };
  const realNow = Date.now; Date.now = () => NOW;
  try {
    const r = await handleFetch(req('/live-intel.json'), env, { waitUntil() {} });
    assert.equal(r.headers.get('x-feed-source'), 'runtime-r2');
    for (const [name, value] of effectiveStatic('/live-intel.json')) assert.equal(r.headers.get(name), value, name);
  } finally { Date.now = realNow; }
});

test('304 and HEAD responses carry the same public headers (CORS must not depend on the method)', async () => {
  const want = effectiveStatic('/live-intel.json');
  const head = await runtimeResponse('/live-intel.json', 'feed', 'HEAD');
  for (const [name, value] of want) assert.equal(head.headers.get(name), value, 'HEAD ' + name);
  const body = '{"a":1}';
  const b = bucketOf({ [PREFIX + 'live-intel.json']: () => object(body) });
  const cond = await serveFeed(req('/live-intel.json', { headers: { 'If-None-Match': '"' + sha(body) + '"' } }), { RUNTIME_FEED: b }, '/live-intel.json', null, NOW);
  assert.equal(cond.status, 304);
  for (const [name, value] of want) assert.equal(cond.headers.get(name), value, '304 ' + name);
});

test('Worker-side Cache API TTL stays 60 s even when the PUBLIC Cache-Control is long (rss: 1 h); a cache hit restores the public value', async () => {
  const body = '<?xml version="1.0"?><rss/>';
  const b = bucketOf({ [PREFIX + 'rss.xml']: () => object(body) });
  const store = new Map(); const pending = [];
  const original = globalThis.caches;
  globalThis.caches = { default: {
    async match(k) { const v = store.get(k.url); return v ? v.clone() : undefined; },
    async put(k, v) { store.set(k.url, v); },
  } };
  try {
    const first = await serveFeed(req('/rss.xml'), { RUNTIME_FEED: b }, '/rss.xml', { waitUntil: (p) => pending.push(p) }, NOW);
    await Promise.all(pending);
    assert.equal(first.headers.get('cache-control'), 'public, max-age=3600, stale-while-revalidate=86400', 'client-facing value is the static one');
    const stored = [...store.values()][0];
    assert.equal(stored.headers.get('cache-control'), 'public, max-age=60', 'the stored copy must expire after 60 s, not 1 h');
    const hit = await serveFeed(req('/rss.xml'), { RUNTIME_FEED: bucketOf({}) }, '/rss.xml', null, NOW);
    assert.equal(hit.headers.get('cache-control'), 'public, max-age=3600, stale-while-revalidate=86400', 'a cache hit is served with the public header again');
    assert.equal(hit.headers.get('access-control-allow-origin'), '*');
    assert.equal(hit.headers.get('x-feed-source'), 'runtime-r2');
    assert.equal(await hit.text(), body);
  } finally { globalThis.caches = original; }
});

test('the header table is frozen (a request can never mutate shared state)', () => {
  for (const t of Object.values(HEADERS)) assert.ok(Object.isFrozen(t));
  assert.throws(() => { 'use strict'; HEADERS.RSS['Access-Control-Allow-Origin'] = 'https://evil.example'; }, TypeError);
});
