'use strict';

/**
 * SOC runtime feed read-through ("Option A": durable freshness without a deploy).
 *
 * WHY: the public feeds are baked into the Worker's static assets at deploy
 * time, and deploys are manual, SHA-pinned and budget-gated, so the public SOC
 * feed goes STALE (>180 min) minutes after any release. Option A lets the
 * publisher write the feed to a DEDICATED R2 bucket each run and lets the Worker
 * serve it live, so deploys ship code only.
 *
 * SAFETY CONTRACT (every point is covered by tests-js/runtime-feed.test.js):
 *  - FAIL-OPEN TO STATIC. If the RUNTIME_FEED binding is absent, the object is
 *    missing, its metadata is invalid or stale, it is oversize, or anything
 *    throws, these functions return null and the caller serves the static asset
 *    exactly as before. A broken runtime store can never take the site down.
 *  - ALLOWLIST ONLY. Three public feed paths and /posts/<slug>.html. Nothing
 *    else is ever read from the bucket and keys are built from constants or a
 *    strictly validated slug; no request-controlled string reaches an R2 key
 *    outside the runtime/v1/ prefix.
 *  - NO PRIVATE DATA. This is a different bucket from PREMIUM_REPORTS (paid
 *    artifacts); a publisher token scoped to this bucket cannot touch them.
 *  - GET/HEAD only. No cookies, no request-derived output.
 *  - Integrity is enforced at WRITE time (publisher) and VERIFIED by the release
 *    and monitor gates against the sha256 carried in the object metadata; the
 *    Worker deliberately does not hash bodies per request (CPU is budgeted).
 */

const HEADERS = require('./runtime-feed-headers');

const PREFIX = 'runtime/v1/';
const JSON_TYPE = 'application/json; charset=utf-8';
// `headers` are the static build's exact headers for the same path (CORS, caching, CSP...),
// pinned by tests-js/runtime-feed-headers.test.js. `type` is used only if they define no Content-Type.
const FEEDS = Object.freeze({
  '/live-intel.json': Object.freeze({ key: PREFIX + 'live-intel.json', type: JSON_TYPE, headers: HEADERS.LIVE_INTEL }),
  '/api/intel/live.json': Object.freeze({ key: PREFIX + 'api/intel/live.json', type: JSON_TYPE, headers: HEADERS.API_LIVE }),
  '/rss.xml': Object.freeze({ key: PREFIX + 'rss.xml', type: 'application/rss+xml; charset=utf-8', headers: HEADERS.RSS }),
});
const DOSSIER_SPEC = Object.freeze({ type: 'text/html; charset=utf-8', headers: HEADERS.DOSSIER });
// Same slug grammar the Blogger source-delivery guard and the build accept.
const DOSSIER_PATH = /^\/posts\/([a-z0-9][a-z0-9-]{0,119}\.html)$/;
const FEED_MAX_BYTES = 8 * 1024 * 1024;       // matches the parity certifier MAX_BYTES
const DOSSIER_MAX_BYTES = 384 * 1024;         // matches source_delivery_guard _MAX_SOURCE_BYTES
// A runtime object older than this is not trusted over the static baseline.
const FEED_MAX_AGE_MS = 6 * 60 * 60 * 1000;
const FUTURE_SKEW_MS = 5 * 60 * 1000;
const FEED_CACHE_SECONDS = 60; // Worker-side Cache API TTL only; the public Cache-Control is the static build's
const MISS_CACHE_SECONDS = 60; // negative cache for dossier lookups that found nothing in R2
const MISS_KEY_ORIGIN = 'https://runtime-feed.internal/dossier-miss/';
const SHA256 = /^[a-f0-9]{64}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

const isReadMethod = (request) => request && (request.method === 'GET' || request.method === 'HEAD');

function bucketOf(env) {
  const bucket = env && env.RUNTIME_FEED;
  return bucket && typeof bucket.get === 'function' ? bucket : null;
}

function metadataOf(object) {
  const meta = object && object.customMetadata;
  return meta && typeof meta === 'object' ? meta : null;
}

/** Valid, fresh, non-future feed metadata, or null. */
function feedInfo(object, nowMs) {
  const meta = metadataOf(object);
  if (!meta) return null;
  const sha = typeof meta.sha256 === 'string' ? meta.sha256.toLowerCase() : '';
  const generatedAt = meta['generated-at'];
  if (!SHA256.test(sha) || typeof generatedAt !== 'string' || !ISO_UTC.test(generatedAt)) return null;
  const generated = Date.parse(generatedAt);
  if (!Number.isFinite(generated)) return null;
  if (generated > nowMs + FUTURE_SKEW_MS) return null;
  if (nowMs - generated > FEED_MAX_AGE_MS) return null;
  return { sha, generatedAt };
}

/** Valid dossier metadata (immutable content; no age limit), or null. */
function dossierInfo(object) {
  const meta = metadataOf(object);
  const sha = meta && typeof meta.sha256 === 'string' ? meta.sha256.toLowerCase() : '';
  return SHA256.test(sha) ? { sha, generatedAt: null } : null;
}

async function discard(object) {
  try { if (object && object.body && typeof object.body.cancel === 'function') await object.body.cancel(); } catch (_) { /* best effort */ }
}

function respond(request, object, spec, info) {
  const etag = '"' + info.sha + '"';
  // Start from the static build's headers for this path so the switch from static asset to
  // runtime object is invisible to customers (CORS, caching, CSP), then add provenance.
  const headers = new Headers(spec.headers);
  if (!headers.has('Content-Type')) headers.set('Content-Type', spec.type);
  headers.set('ETag', etag);
  headers.set('X-Feed-Source', 'runtime-r2');
  headers.set('X-Feed-Sha256', info.sha);
  if (info.generatedAt) headers.set('X-Feed-Generated-At', info.generatedAt);
  const inm = request.headers.get('If-None-Match');
  if (inm && inm.split(',').some((v) => v.trim().replace(/^W\//, '') === etag)) {
    return new Response(null, { status: 304, headers });
  }
  headers.set('Content-Length', String(object.size));
  return new Response(request.method === 'HEAD' ? null : object.body, { status: 200, headers });
}

/**
 * @param {Request} request
 * @param {{RUNTIME_FEED?: {get(key: string): Promise<object|null>}}} env
 * @param {string} pathname  path to resolve (the request path, or the aliased asset path)
 * @param {{waitUntil?: Function}} [ctx]
 * @param {number} [nowMs]
 * @returns {Promise<Response|null>} a Response, or null to fall through to the static asset
 */
async function serveFeed(request, env, pathname, ctx, nowMs = Date.now()) {
  try {
    if (!isReadMethod(request)) return null;
    const spec = Object.prototype.hasOwnProperty.call(FEEDS, pathname) ? FEEDS[pathname] : null;
    if (!spec) return null;
    const bucket = bucketOf(env);
    if (!bucket) return null;

    const cache = request.method === 'GET' && typeof caches !== 'undefined' && caches && caches.default ? caches.default : null;
    const cacheKey = cache ? new Request(new URL(pathname, request.url).toString(), { method: 'GET' }) : null;
    if (cache) {
      const hit = await cache.match(cacheKey);
      if (hit) {
        // The cached copy carries the short internal TTL; restore the public Cache-Control.
        const out = new Response(hit.body, hit);
        out.headers.set('Cache-Control', spec.headers['Cache-Control']);
        return out;
      }
    }

    const object = await bucket.get(spec.key);
    if (!object) return null;
    if (!(Number.isSafeInteger(object.size) && object.size > 0 && object.size <= FEED_MAX_BYTES)) {
      await discard(object);
      return null;
    }
    const info = feedInfo(object, nowMs);
    if (!info) { await discard(object); return null; }

    const response = respond(request, object, spec, info);
    if (cache && response.status === 200 && ctx && typeof ctx.waitUntil === 'function') {
      // The Cache API honours the stored response's Cache-Control, and the public value (rss: 1 h)
      // must not set the Worker-side TTL: store a copy that expires after FEED_CACHE_SECONDS.
      const stored = new Response(response.clone().body, response);
      stored.headers.set('Cache-Control', 'public, max-age=' + FEED_CACHE_SECONDS);
      ctx.waitUntil(cache.put(cacheKey, stored));
    }
    return response;
  } catch (_) {
    return null; // fail open to the static asset
  }
}

/**
 * Called ONLY after the static asset lookup returned 404.
 *
 * COST CONTROL (R2 Class B reads are metered): a valid-slug path that is absent from the
 * static build AND from R2 would cost one R2 read per request. A confirmed miss is therefore
 * remembered for MISS_CACHE_SECONDS in the Cache API (free), so repeated probes of the same
 * URL read R2 at most once per data center per minute. Only confirmed misses are remembered:
 * never a thrown error (a transient R2 fault must not hide a dossier), never a hit, and never
 * without ctx.waitUntil (so callers that cannot write the cache behave exactly as before).
 * A dossier uploaded right after a miss can therefore 404 for up to MISS_CACHE_SECONDS.
 * A flood of DISTINCT valid slugs still costs one read each; that volume is already a Worker
 * request each today and is bounded by the request rate.
 * @returns {Promise<Response|null>}
 */
async function serveDossier(request, env, pathname, ctx) {
  try {
    if (!isReadMethod(request)) return null;
    const match = DOSSIER_PATH.exec(pathname);
    if (!match) return null;
    const bucket = bucketOf(env);
    if (!bucket) return null;

    const cache = typeof caches !== 'undefined' && caches && caches.default ? caches.default : null;
    // Synthetic key on a reserved host: it can never equal a real request URL or a feed cache key.
    const missKey = cache ? new Request(MISS_KEY_ORIGIN + match[1], { method: 'GET' }) : null;
    if (cache) {
      try { if (await cache.match(missKey)) return null; } catch (_) { /* cache fault: fall through to R2 */ }
    }
    const rememberMiss = () => {
      if (!cache || !ctx || typeof ctx.waitUntil !== 'function') return;
      try {
        const marker = new Response(null, { status: 200, headers: { 'Cache-Control': 'public, max-age=' + MISS_CACHE_SECONDS } });
        ctx.waitUntil(Promise.resolve().then(() => cache.put(missKey, marker)).catch(() => {}));
      } catch (_) { /* best effort */ }
    };

    const object = await bucket.get(PREFIX + 'posts/' + match[1]);
    if (!object) { rememberMiss(); return null; }
    if (!(Number.isSafeInteger(object.size) && object.size > 0 && object.size <= DOSSIER_MAX_BYTES)) {
      await discard(object);
      rememberMiss();
      return null;
    }
    const info = dossierInfo(object);
    if (!info) { await discard(object); rememberMiss(); return null; }
    return respond(request, object, DOSSIER_SPEC, info);
  } catch (_) {
    return null;
  }
}

module.exports = {
  serveFeed, serveDossier, feedInfo, dossierInfo, MISS_CACHE_SECONDS, MISS_KEY_ORIGIN,
  FEEDS, PREFIX, DOSSIER_PATH, FEED_MAX_BYTES, DOSSIER_MAX_BYTES, FEED_MAX_AGE_MS, FUTURE_SKEW_MS,
};
