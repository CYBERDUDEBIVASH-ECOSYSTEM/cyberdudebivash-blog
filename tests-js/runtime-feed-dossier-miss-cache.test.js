'use strict';
// Option A cost control: a dossier lookup that finds nothing must not cost an R2 read (Class B,
// metered) on every request. Confirmed misses are remembered for 60 s in the Cache API (free).
// These tests pin both the saving and the safety rules around it (what is, and is NOT, remembered).
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { serveDossier, serveFeed, PREFIX, MISS_CACHE_SECONDS, MISS_KEY_ORIGIN } = require('../workers/lib/runtime-feed');
const { handleFetch } = require('../workers/lib/router');

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const HTML = '<!doctype html><title>x</title>';
const SLUG = 'cve-2026-135696.html';
const PATH = '/posts/' + SLUG;
const req = (path, init) => new Request('https://soc.cyberdudebivash.in' + path, init);

/** A Cache API stand-in with real TTL semantics (from the stored Cache-Control max-age) and a manual clock. */
function installCache() {
  const clock = { ms: 0 }; const store = new Map(); const log = [];
  const cache = {
    async match(k) {
      log.push('match ' + k.url);
      const e = store.get(k.url);
      if (!e) return undefined;
      if (clock.ms >= e.expires) { store.delete(k.url); return undefined; }
      return e.response.clone();
    },
    async put(k, v) {
      log.push('put ' + k.url);
      const m = /max-age=(\d+)/.exec(v.headers.get('cache-control') || '');
      store.set(k.url, { response: v, expires: clock.ms + (m ? Number(m[1]) * 1000 : 0) });
    },
  };
  const original = globalThis.caches;
  globalThis.caches = { default: cache };
  return { clock, store, log, restore: () => { globalThis.caches = original; } };
}
function bucket(map = {}) {
  const reads = [];
  return {
    reads,
    async get(key) { reads.push(key); const v = map[key]; if (typeof v === 'function') return v(); return v || null; },
  };
}
const object = (body, over = {}) => ({
  size: over.size !== undefined ? over.size : Buffer.byteLength(body),
  customMetadata: over.customMetadata !== undefined ? over.customMetadata : { sha256: sha(body) },
  body: new Response(body).body,
});
function ctxOf() { const pending = []; return { pending, waitUntil: (p) => pending.push(p), settle: () => Promise.all(pending) }; }
const KEY = PREFIX + 'posts/' + SLUG;

test('a confirmed miss is remembered: repeated probes of the same URL read R2 once, then once per minute', async () => {
  const c = installCache(); const b = bucket(); const ctx = ctxOf();
  try {
    assert.equal(await serveDossier(req(PATH), { RUNTIME_FEED: b }, PATH, ctx), null);
    await ctx.settle();
    assert.equal(b.reads.length, 1);
    for (let i = 0; i < 25; i++) assert.equal(await serveDossier(req(PATH), { RUNTIME_FEED: b }, PATH, ctx), null);
    assert.equal(b.reads.length, 1, '25 further probes within the TTL must not read R2');
    c.clock.ms = (MISS_CACHE_SECONDS - 1) * 1000;
    await serveDossier(req(PATH), { RUNTIME_FEED: b }, PATH, ctx);
    assert.equal(b.reads.length, 1, 'still cached at 59 s');
    c.clock.ms = (MISS_CACHE_SECONDS + 1) * 1000;
    await serveDossier(req(PATH), { RUNTIME_FEED: b }, PATH, ctx); await ctx.settle();
    assert.equal(b.reads.length, 2, 'expired after 60 s: one fresh read');
  } finally { c.restore(); }
});

test('the TTL is exactly 60 s and the marker is a bodyless 200 under a reserved synthetic key', async () => {
  assert.equal(MISS_CACHE_SECONDS, 60);
  const c = installCache(); const ctx = ctxOf();
  try {
    await serveDossier(req(PATH), { RUNTIME_FEED: bucket() }, PATH, ctx); await ctx.settle();
    const [[url, entry]] = [...c.store.entries()];
    assert.equal(url, MISS_KEY_ORIGIN + SLUG);
    assert.ok(!url.startsWith('https://soc.cyberdudebivash.in') && !url.startsWith('https://blog.cyberdudebivash.in'), 'must never equal a real request URL');
    assert.equal(entry.response.headers.get('cache-control'), 'public, max-age=60');
    assert.equal(await entry.response.text(), '');
  } finally { c.restore(); }
});

test('slugs are independent: a cached miss for one URL never hides another, and a newly uploaded dossier is served', async () => {
  const c = installCache(); const ctx = ctxOf(); const other = 'cve-2026-999999.html';
  const b = bucket({ [PREFIX + 'posts/' + other]: () => object(HTML) });
  try {
    await serveDossier(req(PATH), { RUNTIME_FEED: b }, PATH, ctx); await ctx.settle();
    const hit = await serveDossier(req('/posts/' + other), { RUNTIME_FEED: b }, '/posts/' + other, ctx);
    assert.equal(hit.status, 200); assert.equal(await hit.text(), HTML);
  } finally { c.restore(); }
});

test('after the TTL a dossier uploaded since the miss is served (a miss delays a new dossier by at most 60 s)', async () => {
  const c = installCache(); const ctx = ctxOf(); const map = {}; const b = bucket(map);
  try {
    assert.equal(await serveDossier(req(PATH), { RUNTIME_FEED: b }, PATH, ctx), null); await ctx.settle();
    map[KEY] = () => object(HTML);                                   // the publisher uploads it
    assert.equal(await serveDossier(req(PATH), { RUNTIME_FEED: b }, PATH, ctx), null, 'inside the TTL the miss still holds');
    c.clock.ms = 61 * 1000;
    const r = await serveDossier(req(PATH), { RUNTIME_FEED: b }, PATH, ctx);
    assert.equal(r.status, 200); assert.equal(await r.text(), HTML);
  } finally { c.restore(); }
});

test('only CONFIRMED misses are remembered: hits, thrown errors and non-read methods never create an entry', async () => {
  const c = installCache(); const ctx = ctxOf();
  try {
    const hit = await serveDossier(req(PATH), { RUNTIME_FEED: bucket({ [KEY]: () => object(HTML) }) }, PATH, ctx);
    assert.equal(hit.status, 200); await ctx.settle();
    assert.equal(c.store.size, 0, 'a hit must not be remembered as a miss');
    const boom = bucket({ [KEY]: () => { throw new Error('R2 fault'); } });
    assert.equal(await serveDossier(req(PATH), { RUNTIME_FEED: boom }, PATH, ctx), null); await ctx.settle();
    assert.equal(c.store.size, 0, 'a transient R2 error must not hide a dossier');
    // Control: a genuine miss IS remembered (so the "nothing stored" assertions above are not vacuous).
    assert.equal(await serveDossier(req(PATH), { RUNTIME_FEED: bucket() }, PATH, ctx), null);
    await ctx.settle();
    assert.equal(c.store.size, 1, 'a genuine miss is remembered');
    c.store.clear();
    for (const method of ['POST', 'PUT', 'DELETE']) assert.equal(await serveDossier(req(PATH, { method }), { RUNTIME_FEED: bucket() }, PATH, ctx), null);
    await ctx.settle();
    assert.equal(c.store.size, 0, 'non-GET/HEAD never touches the cache');
  } finally { c.restore(); }
});

test('invalid objects (oversize, empty, no sha256) are treated as misses and remembered (their bytes are discarded)', async () => {
  for (const bad of [object(HTML, { size: 384 * 1024 + 1 }), object(HTML, { size: 0 }), object(HTML, { customMetadata: {} })]) {
    const c = installCache(); const ctx = ctxOf(); const b = bucket({ [KEY]: () => bad });
    try {
      assert.equal(await serveDossier(req(PATH), { RUNTIME_FEED: b }, PATH, ctx), null); await ctx.settle();
      assert.equal(c.store.size, 1);
      await serveDossier(req(PATH), { RUNTIME_FEED: b }, PATH, ctx);
      assert.equal(b.reads.length, 1);
    } finally { c.restore(); }
  }
});

test('without ctx.waitUntil nothing is written (callers that cannot write the cache behave exactly as before)', async () => {
  const c = installCache(); const b = bucket();
  try {
    assert.equal(await serveDossier(req(PATH), { RUNTIME_FEED: b }, PATH), null);
    assert.equal(await serveDossier(req(PATH), { RUNTIME_FEED: b }, PATH, {}), null);
    assert.equal(c.store.size, 0);
    assert.equal(b.reads.length, 2, 'both probes read R2');
  } finally { c.restore(); }
});

test('FAIL-OPEN: a broken Cache API never blocks serving a real dossier or a miss', async () => {
  const original = globalThis.caches; const ctx = ctxOf();
  globalThis.caches = { default: { async match() { throw new Error('cache down'); }, async put() { throw new Error('cache down'); } } };
  try {
    const hit = await serveDossier(req(PATH), { RUNTIME_FEED: bucket({ [KEY]: () => object(HTML) }) }, PATH, ctx);
    assert.equal(hit.status, 200); assert.equal(await hit.text(), HTML);
    assert.equal(await serveDossier(req(PATH), { RUNTIME_FEED: bucket() }, PATH, ctx), null);
    await ctx.settle(); // a rejected put must not surface as an unhandled rejection
  } finally { globalThis.caches = original; }
});

test('grammar and binding checks come first: invalid slugs and a missing binding never touch the cache or R2', async () => {
  const c = installCache(); const ctx = ctxOf(); const b = bucket();
  try {
    for (const p of ['/posts/CVE-2026-1.html', '/posts/../x.html', '/posts/a/b.html', '/posts/x.htm', '/posts/' + 'a'.repeat(121) + '.html', '/index.html']) {
      assert.equal(await serveDossier(req(p), { RUNTIME_FEED: b }, p, ctx), null, p);
    }
    assert.equal(await serveDossier(req(PATH), {}, PATH, ctx), null);
    assert.equal(b.reads.length, 0); assert.equal(c.log.length, 0, 'no cache calls at all');
  } finally { c.restore(); }
});

test('HEAD requests honour the remembered miss too', async () => {
  const c = installCache(); const ctx = ctxOf(); const b = bucket();
  try {
    await serveDossier(req(PATH), { RUNTIME_FEED: b }, PATH, ctx); await ctx.settle();
    assert.equal(await serveDossier(req(PATH, { method: 'HEAD' }), { RUNTIME_FEED: b }, PATH, ctx), null);
    assert.equal(b.reads.length, 1);
  } finally { c.restore(); }
});

test('the feed cache and the miss cache never collide (different key spaces)', async () => {
  const c = installCache(); const ctx = ctxOf();
  const feedBody = '{"a":1}';
  const feedObj = () => ({ size: feedBody.length, customMetadata: { sha256: sha(feedBody), 'generated-at': '2026-11-24T15:58:00Z' }, body: new Response(feedBody).body });
  try {
    const b = bucket({ [PREFIX + 'live-intel.json']: feedObj });
    await serveFeed(req('/live-intel.json'), { RUNTIME_FEED: b }, '/live-intel.json', ctx, Date.parse('2026-11-24T16:00:00Z'));
    await serveDossier(req(PATH), { RUNTIME_FEED: b }, PATH, ctx); await ctx.settle();
    const urls = [...c.store.keys()];
    assert.equal(urls.length, 2); assert.equal(new Set(urls).size, 2);
    assert.ok(urls.some((u) => u === 'https://soc.cyberdudebivash.in/live-intel.json'));
    assert.ok(urls.some((u) => u === MISS_KEY_ORIGIN + SLUG));
  } finally { c.restore(); }
});

test('router: after a static 404 the runtime miss is read once for repeated requests; a static hit never reaches R2', async () => {
  const c = installCache(); const b = bucket(); let assetCalls = 0; const ctx = ctxOf();
  const env = { RUNTIME_FEED: b, ASSETS: { async fetch() { assetCalls++; return new Response('nf', { status: 404 }); } } };
  try {
    for (let i = 0; i < 5; i++) { const r = await handleFetch(req(PATH), env, ctx); assert.equal(r.status, 404); await ctx.settle(); }
    assert.equal(assetCalls, 5, 'the static asset is still consulted first every time');
    assert.equal(b.reads.length, 1, 'five requests, one R2 read');
    const okEnv = { RUNTIME_FEED: bucket(), ASSETS: { async fetch() { return new Response('static', { status: 200 }); } } };
    assert.equal((await handleFetch(req(PATH), okEnv, ctx)).status, 200);
    assert.equal(okEnv.RUNTIME_FEED.reads.length, 0);
  } finally { c.restore(); }
});

test('router without the binding is inert: no R2, no cache calls, same 404', async () => {
  const c = installCache(); const ctx = ctxOf();
  try {
    const r = await handleFetch(req(PATH), { ASSETS: { async fetch() { return new Response('nf', { status: 404 }); } } }, ctx);
    assert.equal(r.status, 404); await ctx.settle();
    assert.equal(c.log.length, 0);
  } finally { c.restore(); }
});
