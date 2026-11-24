'use strict';

/**
 * Cloudflare Access verification for the admin surface (zero-trust layer 1).
 *
 * WHY: the admin endpoints that approve or reject payments are protected only by one shared static key
 * (X-Admin-Key). A leaked key means anonymous, untraceable payment approval. Cloudflare Access puts a
 * named, MFA-backed identity in front of those paths. This module is the Worker-side half: it VERIFIES
 * the signed Access token itself instead of trusting that a request "came through Access", so a
 * misconfigured policy, a removed application, or a request that reaches the Worker another way
 * (for example a workers.dev hostname) is still refused. The shared key stays as a second factor.
 *
 * Rollout is staged and reversible without a deploy (Worker secrets persist across deploys):
 *   ADMIN_ACCESS_MODE unset / "off"  -> nothing changes (the default; merging or deploying is inert)
 *   ADMIN_ACCESS_MODE = "audit"      -> verify and record the result, never block
 *   ADMIN_ACCESS_MODE = "enforce"    -> a valid Access token is REQUIRED (the key is still required too)
 * Any other non-empty value is treated as "enforce" with a configuration problem, so a typo can lock
 * admins out (recoverable by fixing the secret) but can never silently disable the protection.
 *
 * Required when mode is audit or enforce:
 *   CF_ACCESS_TEAM_DOMAIN  "<team>", "<team>.cloudflareaccess.com" or the https:// form
 *   CF_ACCESS_AUD          the Application Audience (AUD) tag, 64 hex chars; comma-separated for several apps
 *
 * Security properties (each pinned by api/_lib/__tests__/admin-access.test.js):
 *   - RS256 only; "none", HS256 and every other algorithm are rejected before any key is consulted.
 *   - Claims are read only after the signature verifies; issuer, audience, exp and nbf are all checked.
 *   - Keys come only from https://<team>.cloudflareaccess.com/cdn-cgi/access/certs (never from the token:
 *     jku/x5u/jwk headers are ignored); redirects are refused; the response size is capped.
 *   - Unknown key ids cause at most one key-set refetch per minute (no refetch amplification).
 *   - The last good key set is reused for up to 24 h if Cloudflare is briefly unreachable.
 *   - Clients never see the internal reason; it goes to the audit log as a short code. Tokens are never logged.
 */

const MODE = Object.freeze({ OFF: 'off', AUDIT: 'audit', ENFORCE: 'enforce' });

const CLOCK_SKEW_SECONDS = 60;
const MAX_TOKEN_CHARS = 8192;
const MAX_JWKS_CHARS = 65536;
const JWKS_FRESH_MS = 60 * 60 * 1000;
const JWKS_REFETCH_MIN_MS = 60 * 1000;
const JWKS_STALE_MAX_MS = 24 * 60 * 60 * 1000;
const JWKS_TIMEOUT_MS = 3000;

const TEAM_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const AUD_RE = /^[a-f0-9]{64}$/;
const KID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;

/** team slug -> { entry: { keys: Map<kid, jwk>, imported: Map<kid, Promise<CryptoKey>>, fetchedAt }, inflight } */
const jwksState = new Map();

/* ── configuration ─────────────────────────────────────────────────────────────────────────── */

function normalizeTeam(value) {
  let v = String(value || '').trim().toLowerCase();
  v = v.replace(/^https:\/\//, '').replace(/\/+$/, '');
  if (v.endsWith('.cloudflareaccess.com')) v = v.slice(0, -'.cloudflareaccess.com'.length);
  return TEAM_RE.test(v) ? v : null;
}

function parseAuds(value) {
  const list = String(value || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  return list.length > 0 && list.length <= 8 && list.every((a) => AUD_RE.test(a)) ? list : [];
}

function readConfig(env) {
  const source = env || process.env;
  const raw = String(source.ADMIN_ACCESS_MODE || '').trim().toLowerCase();
  if (raw === '' || raw === MODE.OFF) return { mode: MODE.OFF, problem: null };
  if (raw !== MODE.AUDIT && raw !== MODE.ENFORCE) return { mode: MODE.ENFORCE, problem: 'ACCESS_MODE_INVALID' };
  const team = normalizeTeam(source.CF_ACCESS_TEAM_DOMAIN);
  const auds = parseAuds(source.CF_ACCESS_AUD);
  const problem = !team ? 'ACCESS_TEAM_INVALID' : auds.length === 0 ? 'ACCESS_AUD_INVALID' : null;
  const issuer = team ? `https://${team}.cloudflareaccess.com` : null;
  return { mode: raw, team, issuer, certsUrl: issuer ? `${issuer}/cdn-cgi/access/certs` : null, auds, problem };
}

/* ── token extraction ──────────────────────────────────────────────────────────────────────── */

function readCookie(header, name) {
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return '';
}

/**
 * The header is added by Cloudflare Access on requests that match an Access application. The
 * CF_Authorization cookie carries the same token and is accepted only where the caller opts in (an
 * action that cannot be isolated by URL path, such as ?action=review-queue on a shared endpoint).
 */
function extractToken(req, opts) {
  const headers = (req && req.headers) || {};
  const fromHeader = String(headers['cf-access-jwt-assertion'] || '').trim();
  if (fromHeader) return fromHeader;
  if (opts && opts.allowCookie) return readCookie(headers.cookie, 'CF_Authorization');
  return '';
}

/* ── encoding helpers ──────────────────────────────────────────────────────────────────────── */

function b64urlToBytes(segment) {
  const padded = segment.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (segment.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function decodeJson(segment) {
  try {
    const value = JSON.parse(new TextDecoder().decode(b64urlToBytes(segment)));
    return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : null;
  } catch (_) {
    return null;
  }
}

function webcrypto(deps) {
  if (deps && deps.crypto) return deps.crypto;
  if (globalThis.crypto && globalThis.crypto.subtle) return globalThis.crypto;
  return require('crypto').webcrypto; // Node (tests, scripts); Workers always has globalThis.crypto
}

/* ── signing keys (JWKS) ───────────────────────────────────────────────────────────────────── */

class AccessKeyError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

async function fetchJwks(certsUrl, deps) {
  const doFetch = (deps && deps.fetch) || globalThis.fetch;
  const controller = typeof AbortController === 'function' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), JWKS_TIMEOUT_MS) : null;
  try {
    const res = await doFetch(certsUrl, {
      redirect: 'error',
      headers: { accept: 'application/json' },
      signal: controller ? controller.signal : undefined,
    });
    if (!res || !res.ok) throw new AccessKeyError('ACCESS_JWKS_UNAVAILABLE');
    const text = await res.text();
    if (typeof text !== 'string' || text.length === 0 || text.length > MAX_JWKS_CHARS) throw new AccessKeyError('ACCESS_JWKS_UNAVAILABLE');
    const body = JSON.parse(text);
    const keys = new Map();
    for (const jwk of Array.isArray(body && body.keys) ? body.keys : []) {
      if (!jwk || jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') continue;
      if (typeof jwk.kid !== 'string' || !KID_RE.test(jwk.kid)) continue;
      if (jwk.alg !== undefined && jwk.alg !== 'RS256') continue;
      if (jwk.use !== undefined && jwk.use !== 'sig') continue;
      keys.set(jwk.kid, { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true });
    }
    if (keys.size === 0) throw new AccessKeyError('ACCESS_JWKS_UNAVAILABLE');
    return { keys, imported: new Map(), fetchedAt: deps && deps.nowMs ? deps.nowMs() : Date.now() };
  } catch (err) {
    throw err instanceof AccessKeyError ? err : new AccessKeyError('ACCESS_JWKS_UNAVAILABLE');
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function getKeySet(config, deps, nowMs, forceRefresh) {
  let state = jwksState.get(config.team);
  if (!state) {
    state = { entry: null, inflight: null };
    jwksState.set(config.team, state);
  }
  const age = state.entry ? nowMs - state.entry.fetchedAt : Infinity;
  const fresh = age < JWKS_FRESH_MS;
  const mayRefetch = age >= JWKS_REFETCH_MIN_MS;
  if (fresh && !(forceRefresh && mayRefetch)) return state.entry;
  if (state.inflight) return state.inflight;
  state.inflight = (async () => {
    try {
      const entry = await fetchJwks(config.certsUrl, deps);
      state.entry = entry;
      return entry;
    } catch (err) {
      if (state.entry && nowMs - state.entry.fetchedAt < JWKS_STALE_MAX_MS) return state.entry; // stale-if-error
      throw err;
    } finally {
      state.inflight = null;
    }
  })();
  return state.inflight;
}

async function resolveKey(config, kid, deps, nowMs) {
  let set = await getKeySet(config, deps, nowMs, false);
  if (!set.keys.has(kid)) set = await getKeySet(config, deps, nowMs, true); // rotation: one bounded refetch
  const jwk = set.keys.get(kid);
  if (!jwk) return null;
  if (!set.imported.has(kid)) {
    const pending = webcrypto(deps).subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    pending.catch(() => set.imported.delete(kid)); // never cache a failed import
    set.imported.set(kid, pending);
  }
  return set.imported.get(kid);
}

/* ── token verification ────────────────────────────────────────────────────────────────────── */

const bad = (code) => ({ ok: false, code });

async function verifyAccessToken(token, config, deps) {
  const nowMs = deps && deps.nowMs ? deps.nowMs() : Date.now();
  if (typeof token !== 'string' || token === '') return bad('ACCESS_TOKEN_MISSING');
  if (token.length > MAX_TOKEN_CHARS) return bad('ACCESS_TOKEN_MALFORMED');
  const parts = token.split('.');
  if (parts.length !== 3 || !parts.every((p) => p.length > 0 && B64URL_RE.test(p))) return bad('ACCESS_TOKEN_MALFORMED');

  const header = decodeJson(parts[0]);
  const payload = decodeJson(parts[1]);
  if (!header || !payload) return bad('ACCESS_TOKEN_MALFORMED');
  if (header.alg !== 'RS256') return bad('ACCESS_TOKEN_ALG');
  if (typeof header.kid !== 'string' || !KID_RE.test(header.kid)) return bad('ACCESS_TOKEN_MALFORMED');

  let signature;
  try {
    signature = b64urlToBytes(parts[2]);
  } catch (_) {
    return bad('ACCESS_TOKEN_MALFORMED');
  }

  let key;
  try {
    key = await resolveKey(config, header.kid, deps, nowMs);
  } catch (_) {
    return bad('ACCESS_JWKS_UNAVAILABLE'); // fetch failure, bad key set or an unimportable key: fail closed in enforce mode
  }
  if (!key) return bad('ACCESS_TOKEN_KID_UNKNOWN');

  let valid = false;
  try {
    valid = await webcrypto(deps).subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, signature, new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  } catch (_) {
    valid = false;
  }
  if (!valid) return bad('ACCESS_TOKEN_SIGNATURE');

  // Claims are trusted only from here on.
  if (payload.iss !== config.issuer) return bad('ACCESS_TOKEN_ISSUER');
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audiences.some((a) => typeof a === 'string' && config.auds.includes(a.toLowerCase()))) return bad('ACCESS_TOKEN_AUDIENCE');

  const nowS = Math.floor(nowMs / 1000);
  const num = (v) => typeof v === 'number' && Number.isFinite(v);
  if (!num(payload.exp)) return bad('ACCESS_TOKEN_CLAIMS');
  if (nowS > payload.exp + CLOCK_SKEW_SECONDS) return bad('ACCESS_TOKEN_EXPIRED');
  if (payload.nbf !== undefined && (!num(payload.nbf) || nowS + CLOCK_SKEW_SECONDS < payload.nbf)) return bad('ACCESS_TOKEN_NOT_YET_VALID');
  if (payload.iat !== undefined && (!num(payload.iat) || payload.iat > nowS + CLOCK_SKEW_SECONDS)) return bad('ACCESS_TOKEN_NOT_YET_VALID');

  let identity = null;
  if (typeof payload.email === 'string' && payload.email.length <= 254 && payload.email.includes('@')) {
    identity = { kind: 'user', id: payload.email.toLowerCase(), email: payload.email, sub: typeof payload.sub === 'string' ? payload.sub : null };
  } else if (typeof payload.common_name === 'string' && payload.common_name.length > 0 && payload.common_name.length <= 128) {
    identity = { kind: 'service', id: payload.common_name, email: null, sub: null }; // Access service token
  }
  if (!identity) return bad('ACCESS_TOKEN_NO_IDENTITY');
  identity.exp = payload.exp;
  return { ok: true, identity };
}

/* ── decision ──────────────────────────────────────────────────────────────────────────────── */

const PUBLIC = Object.freeze({
  denied: { status: 401, code: 'ACCESS_REQUIRED', message: 'Cloudflare Access sign-in is required for the admin API.' },
  unavailable: { status: 503, code: 'ACCESS_UNAVAILABLE', message: 'Admin access verification is temporarily unavailable. No action was taken.' },
});

async function evaluateAccess(req, opts) {
  const options = opts || {};
  const config = readConfig(options.env);
  if (config.mode === MODE.OFF) return { mode: MODE.OFF, allowed: true, identity: null, code: null };

  const result = config.problem
    ? { ok: false, code: config.problem, config: true }
    : await verifyAccessToken(extractToken(req, options), config, options.deps);

  if (result.ok) return { mode: config.mode, allowed: true, identity: result.identity, code: 'ACCESS_OK' };
  if (config.mode === MODE.AUDIT) return { mode: config.mode, allowed: true, identity: null, code: result.code };

  const unavailable = Boolean(result.config) || result.code === 'ACCESS_JWKS_UNAVAILABLE';
  const pub = unavailable ? PUBLIC.unavailable : PUBLIC.denied;
  return { mode: config.mode, allowed: false, identity: null, code: result.code, status: pub.status, publicCode: pub.code, publicMessage: pub.message };
}

function actorLabel(identity) {
  return identity && identity.id ? `${identity.kind}:${identity.id}` : null;
}

/**
 * Admin-endpoint gate. Returns true when the request may continue; otherwise it has already responded.
 * Records an audit event for every audit-mode request and every denial (never for an allowed enforce-mode
 * request, whose operator is attached to the action's own audit entry through req.adminIdentity).
 */
async function gate(req, opts) {
  const o = opts || {};
  const verdict = await evaluateAccess(req, { allowCookie: Boolean(o.allowCookie), env: o.env, deps: o.deps });
  if (verdict.mode === MODE.OFF) return true;
  if ((verdict.mode === MODE.AUDIT || !verdict.allowed) && typeof o.audit === 'function') {
    await o.audit(verdict.allowed ? 'ADMIN_ACCESS_AUDIT' : 'ADMIN_ACCESS_DENIED', {
      ip: o.ip,
      endpoint: o.endpoint,
      // "requested", never "action": auditLog() reserves "action" for the event name (a colliding key is stored
      // as "requested" anyway), so use the final name here and keep the entry shape explicit.
      requested: o.action,
      mode: verdict.mode,
      result: verdict.code,
      actor: actorLabel(verdict.identity),
    });
  }
  if (!verdict.allowed) {
    o.respond(verdict.status, verdict.publicCode, verdict.publicMessage);
    return false;
  }
  if (verdict.identity) req.adminIdentity = verdict.identity;
  return true;
}

function resetForTest() {
  jwksState.clear();
}

module.exports = {
  MODE,
  CLOCK_SKEW_SECONDS,
  JWKS_FRESH_MS,
  JWKS_REFETCH_MIN_MS,
  JWKS_STALE_MAX_MS,
  readConfig,
  extractToken,
  verifyAccessToken,
  evaluateAccess,
  gate,
  actorLabel,
  resetForTest,
};
