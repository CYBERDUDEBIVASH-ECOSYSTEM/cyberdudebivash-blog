'use strict';
// Option A (durable SOC freshness): Worker-side read-through of the runtime feed
// bucket. These tests pin the SAFETY CONTRACT documented in workers/lib/runtime-feed.js:
// inert without the binding, fail-open to the static asset on every anomaly,
// allowlist-only keys, GET/HEAD only, route precedence preserved.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { serveFeed, serveDossier, FEEDS, PREFIX, FEED_MAX_AGE_MS, FUTURE_SKEW_MS, FEED_MAX_BYTES, DOSSIER_MAX_BYTES } = require('../workers/lib/runtime-feed');
const { handleFetch } = require('../workers/lib/router');
const { resolveRoute } = require('../workers/lib/route-table');

const NOW = Date.parse('2026-11-24T16:00:00Z');
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const FEED_BODY = JSON.stringify({ generatedAt: iso(NOW - 120000), items: [] });

function object(body, over = {}) {
  const bytes = Buffer.from(body);
  return {
    size: over.size !== undefined ? over.size : bytes.length,
    customMetadata: over.customMetadata !== undefined ? over.customMetadata
      : { sha256: sha(body), 'generated-at': iso(NOW - 120000) },
    body: new Response(bytes).body,
  };
}
function bucket(map, record = []) {
  return {
    record,
    async get(key) {
      record.push(key);
      const v = map[key];
      return typeof v === 'function' ? v() : (v || null);
    },
  };
}
const req = (path, init = {}) => new Request('https://soc.cyberdudebivash.in' + path, init);

test('INERT: with no RUNTIME_FEED binding every path falls through (null) and nothing is read', async () => {
  for (const p of [...Object.keys(FEEDS), '/posts/cve-2026-1.html', '/index.html']) {
    assert.equal(await serveFeed(req(p), {}, p, null, NOW), null, p);
    assert.equal(await serveDossier(req(p), {}, p), null, p);
  }
  assert.equal(await serveFeed(req('/live-intel.json'), { RUNTIME_FEED: {} }, '/live-intel.json', null, NOW), null, 'binding without get() is ignored');
  assert.equal(await serveFeed(req('/live-intel.json'), undefined, '/live-intel.json', null, NOW), null);
});

test('ALLOWLIST: only the three feed paths are served; the key is always runtime/v1/ + a constant', async () => {
  const b = bucket({});
  for (const p of ['/', '/index.html', '/api/v1/intel', '/api/intel/other.json', '/live-intel.json/', '/LIVE-INTEL.JSON',
    '/../live-intel.json', '/live-intel.json%00', '/intel-state.json', '/premium/report.pdf', '/_headers', '/__proto__', '/constructor', '/toString']) {
    assert.equal(await serveFeed(req('/x'), { RUNTIME_FEED: b }, p, null, NOW), null, p);
  }
  assert.deepEqual(b.record, [], 'no non-allowlisted path may touch the bucket');
  assert.deepEqual(Object.keys(FEEDS).sort(), ['/api/intel/live.json', '/live-intel.json', '/rss.xml']);
  for (const spec of Object.values(FEEDS)) assert.ok(spec.key.startsWith(PREFIX));
});

test('a fresh feed object is served with the right bytes, type, validators and provenance headers', async () => {
  const b = bucket({ [FEEDS['/live-intel.json'].key]: object(FEED_BODY) });
  const r = await serveFeed(req('/live-intel.json'), { RUNTIME_FEED: b }, '/live-intel.json', null, NOW);
  assert.equal(r.status, 200);
  assert.equal(await r.text(), FEED_BODY);
  assert.equal(r.headers.get('content-type'), 'application/json; charset=utf-8');
  assert.equal(r.headers.get('etag'), '"' + sha(FEED_BODY) + '"');
  assert.equal(r.headers.get('x-feed-source'), 'runtime-r2');
  assert.equal(r.headers.get('x-feed-sha256'), sha(FEED_BODY));
  assert.equal(r.headers.get('x-feed-generated-at'), iso(NOW - 120000));
  // Static-build parity (exhaustively pinned in runtime-feed-headers.test.js).
  assert.equal(r.headers.get('cache-control'), 'public, max-age=60, must-revalidate');
  assert.equal(r.headers.get('access-control-allow-origin'), '*');
  assert.equal(r.headers.get('set-cookie'), null);
  assert.deepEqual(b.record, [FEEDS['/live-intel.json'].key]);
});

test('each feed path maps to its own key and content type', async () => {
  const rss = '<?xml version="1.0"?><rss/>';
  const b = bucket({
    [FEEDS['/api/intel/live.json'].key]: object(FEED_BODY),
    [FEEDS['/rss.xml'].key]: object(rss),
  });
  const api = await serveFeed(req('/api/intel/live.json'), { RUNTIME_FEED: b }, '/api/intel/live.json', null, NOW);
  assert.equal(api.headers.get('content-type'), 'application/json; charset=UTF-8');
  const x = await serveFeed(req('/rss.xml'), { RUNTIME_FEED: b }, '/rss.xml', null, NOW);
  assert.equal(x.headers.get('content-type'), 'application/rss+xml; charset=UTF-8');
  assert.equal(await x.text(), rss);
});

test('HEAD returns headers with no body; If-None-Match returns 304; POST/PUT/DELETE are never served', async () => {
  const key = FEEDS['/live-intel.json'].key;
  const env = () => ({ RUNTIME_FEED: bucket({ [key]: object(FEED_BODY) }) });
  const head = await serveFeed(req('/live-intel.json', { method: 'HEAD' }), env(), '/live-intel.json', null, NOW);
  assert.equal(head.status, 200); assert.equal(await head.text(), '');
  assert.equal(head.headers.get('content-length'), String(Buffer.byteLength(FEED_BODY)));
  const cond = await serveFeed(req('/live-intel.json', { headers: { 'If-None-Match': '"' + sha(FEED_BODY) + '"' } }), env(), '/live-intel.json', null, NOW);
  assert.equal(cond.status, 304);
  const weak = await serveFeed(req('/live-intel.json', { headers: { 'If-None-Match': 'W/"' + sha(FEED_BODY) + '"' } }), env(), '/live-intel.json', null, NOW);
  assert.equal(weak.status, 304);
  const other = await serveFeed(req('/live-intel.json', { headers: { 'If-None-Match': '"deadbeef"' } }), env(), '/live-intel.json', null, NOW);
  assert.equal(other.status, 200);
  for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
    const e = env();
    assert.equal(await serveFeed(req('/live-intel.json', { method, body: method === 'DELETE' ? undefined : 'x' }), e, '/live-intel.json', null, NOW), null, method);
    assert.deepEqual(e.RUNTIME_FEED.record, [], method + ' must not read the bucket');
  }
});

test('FAIL-OPEN: every anomaly returns null so the static asset is served', async () => {
  const key = FEEDS['/live-intel.json'].key;
  const good = { sha256: sha(FEED_BODY), 'generated-at': iso(NOW - 60000) };
  const cases = {
    'missing object': () => null,
    'no metadata': () => object(FEED_BODY, { customMetadata: null }),
    'metadata not an object': () => object(FEED_BODY, { customMetadata: 'x' }),
    'missing sha256': () => object(FEED_BODY, { customMetadata: { 'generated-at': good['generated-at'] } }),
    'sha256 wrong length': () => object(FEED_BODY, { customMetadata: { ...good, sha256: 'abc' } }),
    'sha256 not hex': () => object(FEED_BODY, { customMetadata: { ...good, sha256: 'z'.repeat(64) } }),
    'missing generated-at': () => object(FEED_BODY, { customMetadata: { sha256: good.sha256 } }),
    'generated-at not ISO-Z': () => object(FEED_BODY, { customMetadata: { ...good, 'generated-at': '2026-11-24 15:59' } }),
    'generated-at garbage': () => object(FEED_BODY, { customMetadata: { ...good, 'generated-at': 'yesterday' } }),
    'stale (older than max age)': () => object(FEED_BODY, { customMetadata: { ...good, 'generated-at': iso(NOW - FEED_MAX_AGE_MS - 2000) } }),
    'in the future': () => object(FEED_BODY, { customMetadata: { ...good, 'generated-at': iso(NOW + FUTURE_SKEW_MS + 5000) } }),
    'size zero': () => object(FEED_BODY, { size: 0 }),
    'size over limit': () => object(FEED_BODY, { size: FEED_MAX_BYTES + 1 }),
    'size not an integer': () => object(FEED_BODY, { size: NaN }),
    'bucket.get throws': () => { throw new Error('R2 unavailable'); },
  };
  for (const [name, make] of Object.entries(cases)) {
    const r = await serveFeed(req('/live-intel.json'), { RUNTIME_FEED: bucket({ [key]: make }) }, '/live-intel.json', null, NOW);
    assert.equal(r, null, name);
  }
});

test('freshness boundaries: exactly max-age and exactly the future skew are still served', async () => {
  const key = FEEDS['/live-intel.json'].key;
  const at = (generatedAt) => ({ RUNTIME_FEED: bucket({ [key]: object(FEED_BODY, { customMetadata: { sha256: sha(FEED_BODY), 'generated-at': generatedAt } }) }) });
  assert.equal((await serveFeed(req('/live-intel.json'), at(iso(NOW - FEED_MAX_AGE_MS)), '/live-intel.json', null, NOW)).status, 200);
  assert.equal((await serveFeed(req('/live-intel.json'), at(iso(NOW + FUTURE_SKEW_MS)), '/live-intel.json', null, NOW)).status, 200);
});

test('edge cache: a hit never reads R2; a miss populates the cache through ctx.waitUntil (GET only)', async () => {
  const key = FEEDS['/live-intel.json'].key;
  const store = new Map(); const puts = [];
  const original = globalThis.caches;
  globalThis.caches = { default: {
    async match(k) { return store.get(k.url) || undefined; },
    async put(k, res) { store.set(k.url, res); puts.push(k.url); },
  } };
  try {
    const b = bucket({ [key]: object(FEED_BODY) });
    const waits = []; const ctx = { waitUntil: (p) => waits.push(p) };
    const miss = await serveFeed(req('/live-intel.json'), { RUNTIME_FEED: b }, '/live-intel.json', ctx, NOW);
    assert.equal(miss.status, 200); await Promise.all(waits);
    assert.deepEqual(puts, ['https://soc.cyberdudebivash.in/live-intel.json']);
    assert.equal(b.record.length, 1);
    const hit = await serveFeed(req('/live-intel.json'), { RUNTIME_FEED: b }, '/live-intel.json', ctx, NOW);
    assert.equal(await hit.text(), FEED_BODY);
    assert.equal(b.record.length, 1, 'cache hit must not touch R2');
    // HEAD bypasses the cache entirely (never stores a body-less entry)
    const headCtx = { waitUntil: (p) => waits.push(p) };
    await serveFeed(req('/live-intel.json', { method: 'HEAD' }), { RUNTIME_FEED: bucket({ [key]: object(FEED_BODY) }) }, '/live-intel.json', headCtx, NOW);
    assert.equal(puts.length, 1);
  } finally { globalThis.caches = original; }
});

test('DOSSIER fallback: valid slug served with immutable-style metadata; invalid slugs never reach R2', async () => {
  const html = '<!doctype html><title>x</title>';
  const key = PREFIX + 'posts/cve-2026-135696.html';
  const b = bucket({ [key]: object(html, { customMetadata: { sha256: sha(html) } }) });
  const r = await serveDossier(req('/posts/cve-2026-135696.html'), { RUNTIME_FEED: b }, '/posts/cve-2026-135696.html');
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('content-type'), 'text/html; charset=utf-8');
  assert.equal(r.headers.get('cache-control'), 'public, max-age=3600, stale-while-revalidate=86400');
  assert.match(r.headers.get('content-security-policy'), /^default-src 'self'/, 'dossier keeps the static page CSP (the baseline default-src none would unstyle it)');
  assert.equal(await r.text(), html);
  const bad = ['/posts/CVE-2026-1.html', '/posts/../secret.html', '/posts/a/b.html', '/posts/.html', '/posts/-x.html',
    '/posts/x.htm', '/posts/x.html/', '/posts//x.html', '/posts/' + 'a'.repeat(121) + '.html', '/post/x.html', '/posts/x.html%2e', '/posts/x y.html'];
  const probe = bucket({});
  for (const p of bad) assert.equal(await serveDossier(req('/x'), { RUNTIME_FEED: probe }, p), null, p);
  assert.deepEqual(probe.record, [], 'malformed slugs must never produce a bucket read');
});

test('DOSSIER fail-open: missing, oversize, no sha256, throwing bucket and non-GET/HEAD all return null', async () => {
  const key = PREFIX + 'posts/x.html'; const p = '/posts/x.html';
  const mk = (make) => ({ RUNTIME_FEED: bucket({ [key]: make }) });
  assert.equal(await serveDossier(req(p), mk(() => null), p), null);
  assert.equal(await serveDossier(req(p), mk(() => object('<p>x</p>', { size: DOSSIER_MAX_BYTES + 1 })), p), null);
  assert.equal(await serveDossier(req(p), mk(() => object('<p>x</p>', { customMetadata: {} })), p), null);
  assert.equal(await serveDossier(req(p), mk(() => { throw new Error('boom'); }), p), null);
  assert.equal(await serveDossier(req(p, { method: 'POST', body: 'x' }), mk(() => object('<p>x</p>')), p), null);
});

// ---- router integration ---------------------------------------------------------
function routerEnv({ assets, runtime } = {}) {
  const calls = [];
  const env = { ASSETS: { async fetch(r) { calls.push(new URL(r.url).pathname); return assets ? assets(r) : new Response('static-body', { status: 200, headers: { 'content-type': 'text/plain' } }); } } };
  if (runtime) env.RUNTIME_FEED = runtime;
  return { env, calls };
}

test('router: feed paths are unrouted/asset routes today (the hook point is real)', () => {
  assert.equal(resolveRoute('/live-intel.json'), null);
  assert.equal(resolveRoute('/api/intel/live.json'), null);
  assert.equal(resolveRoute('/posts/cve-2026-1.html'), null);
  assert.deepEqual(resolveRoute('/feed.xml'), resolveRoute('/feed.xml')); // alias exists
  const alias = resolveRoute('/feed.xml');
  assert.equal(alias && alias.type, 'asset'); assert.equal(alias.path, '/rss.xml');
});

test('router: without the binding behaviour is byte-identical to before (static asset, no baseline headers added)', async () => {
  const { env, calls } = routerEnv();
  const r = await handleFetch(req('/live-intel.json'), env);
  assert.equal(r.status, 200); assert.equal(await r.text(), 'static-body');
  assert.equal(r.headers.get('x-feed-source'), null);
  assert.equal(r.headers.get('content-security-policy'), null, 'static passthrough keeps no Worker-added CSP');
  assert.deepEqual(calls, ['/live-intel.json']);
});

test('router: with a fresh runtime object the Worker serves it (with baseline security headers) and skips the static asset', async () => {
  const runtime = bucket({ [FEEDS['/live-intel.json'].key]: object(FEED_BODY) });
  const { env, calls } = routerEnv({ runtime });
  const now = Date.now;
  Date.now = () => NOW;
  try {
    const r = await handleFetch(req('/live-intel.json'), env, { waitUntil() {} });
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('x-feed-source'), 'runtime-r2');
    assert.equal(await r.text(), FEED_BODY);
    assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
    assert.ok(r.headers.get('strict-transport-security'));
    assert.equal(r.headers.get('cache-control'), 'public, max-age=60, must-revalidate', 'baseline must not override the explicit Cache-Control');
    assert.equal(r.headers.get('access-control-allow-origin'), '*', 'cross-origin consumers of the feed must keep working');
    assert.deepEqual(calls, [], 'static asset must not be fetched when runtime serves');
  } finally { Date.now = now; }
});

test('router: a stale runtime object transparently falls back to the static asset', async () => {
  const stale = object(FEED_BODY, { customMetadata: { sha256: sha(FEED_BODY), 'generated-at': iso(NOW - FEED_MAX_AGE_MS - 60000) } });
  const { env, calls } = routerEnv({ runtime: bucket({ [FEEDS['/live-intel.json'].key]: stale }) });
  const now = Date.now; Date.now = () => NOW;
  try {
    const r = await handleFetch(req('/live-intel.json'), env);
    assert.equal(await r.text(), 'static-body'); assert.deepEqual(calls, ['/live-intel.json']);
  } finally { Date.now = now; }
});

test('router: the /feed.xml alias serves the runtime rss.xml, and falls back to static when absent', async () => {
  const rss = '<rss version="2.0"/>';
  const now = Date.now; Date.now = () => NOW;
  try {
    const withRt = routerEnv({ runtime: bucket({ [FEEDS['/rss.xml'].key]: object(rss) }) });
    const r = await handleFetch(req('/feed.xml'), withRt.env);
    assert.equal(await r.text(), rss); assert.equal(r.headers.get('x-feed-source'), 'runtime-r2');
    const without = routerEnv({ runtime: bucket({}) });
    const s = await handleFetch(req('/feed.xml'), without.env);
    assert.equal(await s.text(), 'static-body'); assert.deepEqual(without.calls, ['/rss.xml']);
  } finally { Date.now = now; }
});

test('router: dossier fallback happens ONLY after a static 404; a static hit never reads R2', async () => {
  const html = '<!doctype html><h1>dossier</h1>';
  const key = PREFIX + 'posts/cve-2026-135696.html';
  const mkRuntime = () => bucket({ [key]: object(html, { customMetadata: { sha256: sha(html) } }) });
  const miss = routerEnv({ runtime: mkRuntime(), assets: () => new Response('nf', { status: 404 }) });
  const r = await handleFetch(req('/posts/cve-2026-135696.html'), miss.env);
  assert.equal(r.status, 200); assert.equal(await r.text(), html);
  assert.equal(r.headers.get('x-feed-source'), 'runtime-r2');
  const hit = routerEnv({ runtime: mkRuntime() });
  const h = await handleFetch(req('/posts/cve-2026-135696.html'), hit.env);
  assert.equal(await h.text(), 'static-body');
  assert.deepEqual(hit.env.RUNTIME_FEED.record, [], 'static hit must not read R2');
  const nowhere = routerEnv({ runtime: bucket({}), assets: () => new Response('nf', { status: 404 }) });
  assert.equal((await handleFetch(req('/posts/missing.html'), nowhere.env)).status, 404);
});

test('router: blocked/redirect/handler routes keep precedence and NEVER consult the runtime bucket', async () => {
  // Self-validating: assert the route TYPE of each probe so this cannot pass vacuously.
  const probes = { '/CLAUDE.md': 'blocked', '/posts': 'redirect', '/rss': 'redirect', '/api/cron/dispatch-intel': 'handler', '/api/v1/intel': 'handler' };
  for (const [p, type] of Object.entries(probes)) {
    const route = resolveRoute(p);
    assert.ok(route && route.type === type, p + ' expected route type ' + type + ' got ' + (route && route.type));
  }
  const runtime = bucket({});
  const { env } = routerEnv({ runtime });
  for (const p of Object.keys(probes)) await handleFetch(req(p), env).catch(() => {});
  assert.deepEqual(runtime.record, [], 'route precedence: the runtime bucket must not be read for non-static routes');
});
