'use strict';
/**
 * Cloudflare Access verification for the admin surface (api/_lib/admin-access.js).
 *
 * Real RSA keys and real signed tokens, an injected fetch/crypto/clock: every rule the verifier enforces
 * is proven by a token that breaks exactly that rule and nothing else.
 */
const { webcrypto } = require('node:crypto');
const access = require('../admin-access');

const subtle = webcrypto.subtle;
const TEAM = 'acme-sec';
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const CERTS = `${ISS}/cdn-cgi/access/certs`;
const AUD = 'a'.repeat(64);
const AUD2 = 'b'.repeat(64);
const NOW_MS = Date.UTC(2026, 10, 25, 12, 0, 0);
const NOW_S = NOW_MS / 1000;
const ENV_ENFORCE = { ADMIN_ACCESS_MODE: 'enforce', CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD };

const b64u = (value) => Buffer.from(typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value)).toString('base64url');

async function newKey(kid) {
  const pair = await subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify']
  );
  const jwk = await subtle.exportKey('jwk', pair.publicKey);
  return { kid, privateKey: pair.privateKey, jwk: { ...jwk, kid, alg: 'RS256', use: 'sig' } };
}

async function mint(key, { header = {}, payload = {}, signWith } = {}) {
  const h = { alg: 'RS256', kid: key.kid, typ: 'JWT', ...header };
  const p = { iss: ISS, aud: [AUD], exp: NOW_S + 3600, iat: NOW_S - 10, email: 'Ops@Example.com', sub: 'user-1', ...payload };
  const input = `${b64u(h)}.${b64u(p)}`;
  const sig = await subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, (signWith || key).privateKey, Buffer.from(input));
  return `${input}.${Buffer.from(sig).toString('base64url')}`;
}

let keyA;
let keyB;
let attacker;
let clock;
let jwksBody;
let fetchImpl;
let deps;

beforeAll(async () => {
  keyA = await newKey('kid-a');
  keyB = await newKey('kid-b');
  attacker = await newKey('kid-a'); // same kid as keyA, different key material
}, 60000);

beforeEach(() => {
  access.resetForTest();
  clock = { now: NOW_MS };
  jwksBody = () => JSON.stringify({ keys: [keyA.jwk] });
  fetchImpl = jest.fn(async () => ({ ok: true, status: 200, text: async () => jwksBody() }));
  deps = { fetch: fetchImpl, crypto: webcrypto, nowMs: () => clock.now };
});

const config = (env = ENV_ENFORCE) => access.readConfig(env);
const verify = (token, env) => access.verifyAccessToken(token, config(env), deps);

describe('configuration', () => {
  test('unset, empty and "off" disable the feature and need no other setting', () => {
    for (const mode of [undefined, '', '   ', 'off', 'OFF']) {
      expect(access.readConfig({ ADMIN_ACCESS_MODE: mode })).toEqual({ mode: 'off', problem: null });
    }
  });

  test('audit and enforce parse team and audience and are case-insensitive', () => {
    const c = access.readConfig({ ADMIN_ACCESS_MODE: ' Enforce ', CF_ACCESS_TEAM_DOMAIN: 'ACME-sec', CF_ACCESS_AUD: AUD.toUpperCase() });
    expect(c).toMatchObject({ mode: 'enforce', problem: null, team: TEAM, issuer: ISS, certsUrl: CERTS, auds: [AUD] });
    expect(access.readConfig({ ...ENV_ENFORCE, ADMIN_ACCESS_MODE: 'audit' }).mode).toBe('audit');
  });

  test('the team may be given as a slug, a hostname or a URL', () => {
    for (const form of [TEAM, `${TEAM}.cloudflareaccess.com`, `https://${TEAM}.cloudflareaccess.com`, `https://${TEAM}.cloudflareaccess.com/`]) {
      expect(access.readConfig({ ...ENV_ENFORCE, CF_ACCESS_TEAM_DOMAIN: form }).team).toBe(TEAM);
    }
  });

  test('a bad team (path tricks, other hosts, empty) is a configuration problem and no URL is built', () => {
    for (const bad of ['', 'evil.com', 'acme.evil.com', 'acme/../x', 'acme sec', '-acme', 'a'.repeat(64), 'https://evil.com/', 'acme.cloudflareaccess.com.evil.com']) {
      const c = access.readConfig({ ...ENV_ENFORCE, CF_ACCESS_TEAM_DOMAIN: bad });
      expect(c.problem).toBe('ACCESS_TEAM_INVALID');
      expect(c.certsUrl).toBeNull();
    }
  });

  test('audience must be 64 hex characters; several may be listed; garbage is a problem', () => {
    expect(access.readConfig({ ...ENV_ENFORCE, CF_ACCESS_AUD: `${AUD}, ${AUD2}` }).auds).toEqual([AUD, AUD2]);
    for (const bad of ['', 'abc', 'g'.repeat(64), `${AUD},nothex`, 'a'.repeat(63)]) {
      expect(access.readConfig({ ...ENV_ENFORCE, CF_ACCESS_AUD: bad }).problem).toBe('ACCESS_AUD_INVALID');
    }
  });

  test('an unrecognised mode fails CLOSED (enforce with a problem), never silently off', () => {
    for (const typo of ['enfroce', 'on', 'true', 'disabled', '1']) {
      expect(access.readConfig({ ...ENV_ENFORCE, ADMIN_ACCESS_MODE: typo })).toMatchObject({ mode: 'enforce', problem: 'ACCESS_MODE_INVALID' });
    }
  });
});

describe('token extraction', () => {
  test('header wins; cookie only when the caller opts in; other cookies are ignored', () => {
    const req = { headers: { 'cf-access-jwt-assertion': 'from-header', cookie: 'a=1; CF_Authorization=from-cookie; b=2' } };
    expect(access.extractToken(req, {})).toBe('from-header');
    expect(access.extractToken({ headers: { cookie: 'a=1; CF_Authorization=from-cookie; b=2' } }, {})).toBe('');
    expect(access.extractToken({ headers: { cookie: 'a=1; CF_Authorization=from-cookie; b=2' } }, { allowCookie: true })).toBe('from-cookie');
    expect(access.extractToken({ headers: { cookie: 'XCF_Authorization=nope; CF_Authorization_x=nope' } }, { allowCookie: true })).toBe('');
    expect(access.extractToken({ headers: {} }, { allowCookie: true })).toBe('');
    expect(access.extractToken({}, { allowCookie: true })).toBe('');
  });
});

describe('verifyAccessToken: acceptance', () => {
  test('a valid user token yields a lower-cased identity', async () => {
    const r = await verify(await mint(keyA));
    expect(r.ok).toBe(true);
    expect(r.identity).toMatchObject({ kind: 'user', id: 'ops@example.com', email: 'Ops@Example.com', sub: 'user-1' });
    expect(access.actorLabel(r.identity)).toBe('user:ops@example.com');
  });

  test('a service token (common_name, no email) yields a service identity', async () => {
    const r = await verify(await mint(keyA, { payload: { email: undefined, sub: '', common_name: 'abc123.access' } }));
    expect(r.ok).toBe(true);
    expect(access.actorLabel(r.identity)).toBe('service:abc123.access');
  });

  test('aud may be a string, or an array containing any configured audience', async () => {
    expect((await verify(await mint(keyA, { payload: { aud: AUD } }))).ok).toBe(true);
    expect((await verify(await mint(keyA, { payload: { aud: ['x', AUD2] } }), { ...ENV_ENFORCE, CF_ACCESS_AUD: `${AUD},${AUD2}` })).ok).toBe(true);
  });

  test('the time window honours exactly 60 s of clock skew', async () => {
    expect((await verify(await mint(keyA, { payload: { exp: NOW_S - 60 } }))).ok).toBe(true);
    expect((await verify(await mint(keyA, { payload: { exp: NOW_S - 61 } }))).code).toBe('ACCESS_TOKEN_EXPIRED');
    expect((await verify(await mint(keyA, { payload: { nbf: NOW_S + 60 } }))).ok).toBe(true);
    expect((await verify(await mint(keyA, { payload: { nbf: NOW_S + 61 } }))).code).toBe('ACCESS_TOKEN_NOT_YET_VALID');
    expect((await verify(await mint(keyA, { payload: { iat: NOW_S + 61 } }))).code).toBe('ACCESS_TOKEN_NOT_YET_VALID');
  });
});

describe('verifyAccessToken: every rule rejects on its own', () => {
  test('missing and malformed tokens', async () => {
    expect((await verify('')).code).toBe('ACCESS_TOKEN_MISSING');
    expect((await verify(undefined)).code).toBe('ACCESS_TOKEN_MISSING');
    for (const t of ['a.b', 'a.b.c.d', '..', 'a..c', 'a.b.c!', 'not a jwt', 'a'.repeat(9000)]) {
      expect((await verify(t)).code).toBe('ACCESS_TOKEN_MALFORMED');
    }
    const garbage = `${b64u('not json')}.${b64u('{}')}.${b64u('sig')}`;
    expect((await verify(garbage)).code).toBe('ACCESS_TOKEN_MALFORMED');
    const arrays = `${b64u('[]')}.${b64u('{}')}.${b64u('sig')}`;
    expect((await verify(arrays)).code).toBe('ACCESS_TOKEN_MALFORMED');
  });

  test('size cap: a correctly signed token over 8 KB is refused, one just under is accepted', async () => {
    const big = await mint(keyA, { payload: { pad: 'x'.repeat(9000) } });
    expect(big.length).toBeGreaterThan(8192);
    expect((await verify(big)).code).toBe('ACCESS_TOKEN_MALFORMED');
    const ok = await mint(keyA, { payload: { pad: 'x'.repeat(3000) } });
    expect(ok.length).toBeLessThan(8192);
    expect((await verify(ok)).ok).toBe(true);
  });

  test('only RS256: none, HS256, RS384, ES256 and a missing alg are refused BEFORE any key is fetched', async () => {
    for (const alg of ['none', 'None', 'HS256', 'RS384', 'RS512', 'ES256', 'PS256', '', undefined]) {
      const r = await verify(await mint(keyA, { header: { alg } }));
      expect(r).toEqual({ ok: false, code: 'ACCESS_TOKEN_ALG' });
    }
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  test('a token with no usable kid is malformed', async () => {
    for (const kid of [undefined, '', 'bad kid', 'a'.repeat(129), 5]) {
      expect((await verify(await mint(keyA, { header: { kid } }))).code).toBe('ACCESS_TOKEN_MALFORMED');
    }
  });

  test('a payload altered after signing fails the signature check', async () => {
    const good = (await mint(keyA)).split('.');
    const forged = `${good[0]}.${b64u({ iss: ISS, aud: [AUD], exp: NOW_S + 3600, email: 'attacker@evil.com' })}.${good[2]}`;
    expect((await verify(forged)).code).toBe('ACCESS_TOKEN_SIGNATURE');
  });

  test('a token signed by a different key that reuses the kid fails', async () => {
    expect((await verify(await mint(attacker))).code).toBe('ACCESS_TOKEN_SIGNATURE');
  });

  test('an embedded jwk / jku / x5u header is never used to find a key', async () => {
    const token = await mint(attacker, { header: { kid: 'attacker-kid', jwk: attacker.jwk, jku: 'https://evil.example/keys', x5u: 'https://evil.example/x5' } });
    expect((await verify(token)).code).toBe('ACCESS_TOKEN_KID_UNKNOWN');
    expect(fetchImpl.mock.calls.every(([url]) => url === CERTS)).toBe(true);
  });

  test('wrong issuer, wrong or missing audience', async () => {
    expect((await verify(await mint(keyA, { payload: { iss: 'https://other.cloudflareaccess.com' } }))).code).toBe('ACCESS_TOKEN_ISSUER');
    expect((await verify(await mint(keyA, { payload: { iss: undefined } }))).code).toBe('ACCESS_TOKEN_ISSUER');
    expect((await verify(await mint(keyA, { payload: { aud: [AUD2] } }))).code).toBe('ACCESS_TOKEN_AUDIENCE');
    expect((await verify(await mint(keyA, { payload: { aud: undefined } }))).code).toBe('ACCESS_TOKEN_AUDIENCE');
    expect((await verify(await mint(keyA, { payload: { aud: [] } }))).code).toBe('ACCESS_TOKEN_AUDIENCE');
    expect((await verify(await mint(keyA, { payload: { aud: [42, null] } }))).code).toBe('ACCESS_TOKEN_AUDIENCE');
  });

  test('missing or non-numeric exp, and no identity at all', async () => {
    expect((await verify(await mint(keyA, { payload: { exp: undefined } }))).code).toBe('ACCESS_TOKEN_CLAIMS');
    expect((await verify(await mint(keyA, { payload: { exp: '9999999999' } }))).code).toBe('ACCESS_TOKEN_CLAIMS');
    expect((await verify(await mint(keyA, { payload: { email: undefined } }))).code).toBe('ACCESS_TOKEN_NO_IDENTITY');
    expect((await verify(await mint(keyA, { payload: { email: 'no-at-sign' } }))).code).toBe('ACCESS_TOKEN_NO_IDENTITY');
  });

  test('claims are never trusted before the signature: a forged token with perfect claims still fails', async () => {
    const r = await verify(await mint(keyA, { signWith: keyB }));
    expect(r.code).toBe('ACCESS_TOKEN_SIGNATURE');
  });
});

describe('signing keys (JWKS)', () => {
  test('keys come only from the team certs URL, with redirects refused, and are cached', async () => {
    const t = await mint(keyA);
    expect((await verify(t)).ok).toBe(true);
    expect((await verify(t)).ok).toBe(true);
    expect((await verify(t)).ok).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0];
    expect(url).toBe(CERTS);
    expect(init.redirect).toBe('error');
  });

  test('an unknown kid refetches ONCE per minute, so random kids cannot amplify into fetches', async () => {
    await verify(await mint(keyA)); // primes the cache (1 fetch)
    for (let i = 0; i < 20; i++) {
      expect((await verify(await mint(keyB, { header: { kid: `random-${i}` } }))).code).toBe('ACCESS_TOKEN_KID_UNKNOWN');
    }
    expect(fetchImpl).toHaveBeenCalledTimes(1); // all within the first minute of the cache
    clock.now += 61 * 1000;
    await verify(await mint(keyB, { header: { kid: 'random-late' } }));
    await verify(await mint(keyB, { header: { kid: 'random-late-2' } }));
    expect(fetchImpl).toHaveBeenCalledTimes(2); // one bounded refetch after a minute, not one per request
  });

  test('key rotation: a new kid is picked up by that single refetch', async () => {
    await verify(await mint(keyA));
    jwksBody = () => JSON.stringify({ keys: [keyA.jwk, keyB.jwk] });
    clock.now += 61 * 1000;
    expect((await verify(await mint(keyB))).ok).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  test('an expired cache is refreshed', async () => {
    await verify(await mint(keyA));
    clock.now += 60 * 60 * 1000 - 1000; // just under an hour: still cached
    await verify(await mint(keyA));
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    clock.now += 2000; // just over an hour: refreshed
    await verify(await mint(keyA));
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  test('no cache and Cloudflare unreachable: fail closed with a distinct code', async () => {
    fetchImpl.mockImplementation(async () => { throw new Error('network down'); });
    expect((await verify(await mint(keyA))).code).toBe('ACCESS_JWKS_UNAVAILABLE');
  });

  test('stale-if-error: the last good key set is used while it is under 24 h old, and not after', async () => {
    await verify(await mint(keyA, { payload: { exp: NOW_S + 72 * 3600 } }));
    fetchImpl.mockImplementation(async () => { throw new Error('network down'); });
    const longLived = () => mint(keyA, { payload: { exp: NOW_S + 72 * 3600 } });
    clock.now += 2 * 60 * 60 * 1000; // expired cache (>1 h) and Cloudflare down: stale keys are reused
    expect((await verify(await longLived())).ok).toBe(true);
    clock.now += 21 * 60 * 60 * 1000; // now 23 h old: still within 24 h
    expect((await verify(await longLived())).ok).toBe(true);
    clock.now += 2 * 60 * 60 * 1000; // now 25 h old: too stale to trust
    expect((await verify(await longLived())).code).toBe('ACCESS_JWKS_UNAVAILABLE');
  });

  test('bad key-set responses are unavailable, never accepted', async () => {
    const bodies = ['not json', '{}', '{"keys":[]}', '{"keys":"x"}', JSON.stringify({ keys: [{ kty: 'EC', kid: 'kid-a', n: 'x', e: 'y' }] }),
      JSON.stringify({ keys: [{ ...keyA.jwk, alg: 'RS512' }] }), JSON.stringify({ keys: [{ ...keyA.jwk, use: 'enc' }] }),
      JSON.stringify({ keys: [keyA.jwk], pad: 'x'.repeat(70000) })];
    for (const body of bodies) {
      access.resetForTest();
      jwksBody = () => body;
      expect((await verify(await mint(keyA))).code).toBe('ACCESS_JWKS_UNAVAILABLE');
    }
    access.resetForTest();
    fetchImpl.mockImplementation(async () => ({ ok: false, status: 500, text: async () => '' }));
    expect((await verify(await mint(keyA))).code).toBe('ACCESS_JWKS_UNAVAILABLE');
  });

  test('concurrent verifications share a single key-set fetch', async () => {
    const token = await mint(keyA);
    const results = await Promise.all(Array.from({ length: 12 }, () => verify(token)));
    expect(results.every((r) => r.ok)).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  test('keys are cached per team (a second team gets its own fetch)', async () => {
    await verify(await mint(keyA));
    const other = { ...ENV_ENFORCE, CF_ACCESS_TEAM_DOMAIN: 'other-team' };
    await access.verifyAccessToken(await mint(keyA, { payload: { iss: 'https://other-team.cloudflareaccess.com' } }), config(other), deps);
    expect(fetchImpl.mock.calls.map(([u]) => u)).toEqual([CERTS, 'https://other-team.cloudflareaccess.com/cdn-cgi/access/certs']);
  });
});

describe('evaluateAccess: the three modes', () => {
  const req = (token) => ({ headers: token ? { 'cf-access-jwt-assertion': token } : {} });

  test('off: always allowed and does no work at all, even for garbage input', async () => {
    for (const env of [{}, { ADMIN_ACCESS_MODE: 'off' }]) {
      const v = await access.evaluateAccess(req('garbage'), { env, deps });
      expect(v).toEqual({ mode: 'off', allowed: true, identity: null, code: null });
    }
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  test('audit: never blocks; reports what enforce would have done', async () => {
    const env = { ...ENV_ENFORCE, ADMIN_ACCESS_MODE: 'audit' };
    const ok = await access.evaluateAccess(req(await mint(keyA)), { env, deps });
    expect(ok).toMatchObject({ mode: 'audit', allowed: true, code: 'ACCESS_OK' });
    expect(ok.identity.id).toBe('ops@example.com');
    for (const [token, code] of [[null, 'ACCESS_TOKEN_MISSING'], ['x.y.z', 'ACCESS_TOKEN_MALFORMED'], [await mint(keyA, { payload: { aud: [AUD2] } }), 'ACCESS_TOKEN_AUDIENCE']]) {
      const v = await access.evaluateAccess(req(token), { env, deps });
      expect(v).toMatchObject({ mode: 'audit', allowed: true, identity: null, code });
    }
    const broken = await access.evaluateAccess(req(null), { env: { ADMIN_ACCESS_MODE: 'audit' }, deps });
    expect(broken).toMatchObject({ allowed: true, code: 'ACCESS_TEAM_INVALID' }); // misconfiguration is reported, not enforced
  });

  test('enforce: valid token passes; missing or invalid is 401 with a generic public message', async () => {
    const ok = await access.evaluateAccess(req(await mint(keyA)), { env: ENV_ENFORCE, deps });
    expect(ok).toMatchObject({ mode: 'enforce', allowed: true });
    for (const token of [null, 'x.y.z', await mint(keyA, { payload: { aud: [AUD2] } }), await mint(keyA, { payload: { exp: NOW_S - 999 } }), await mint(attacker)]) {
      const v = await access.evaluateAccess(req(token), { env: ENV_ENFORCE, deps });
      expect(v).toMatchObject({ allowed: false, status: 401, publicCode: 'ACCESS_REQUIRED' });
      expect(v.publicMessage).not.toMatch(/AUDIENCE|SIGNATURE|EXPIRED|MALFORMED|kid|jwks/i);
    }
  });

  test('enforce: a key-set outage or a configuration problem is 503 and still denies', async () => {
    fetchImpl.mockImplementation(async () => { throw new Error('down'); });
    const down = await access.evaluateAccess(req(await mint(keyA)), { env: ENV_ENFORCE, deps });
    expect(down).toMatchObject({ allowed: false, status: 503, publicCode: 'ACCESS_UNAVAILABLE', code: 'ACCESS_JWKS_UNAVAILABLE' });
    for (const env of [{ ADMIN_ACCESS_MODE: 'enforce' }, { ...ENV_ENFORCE, CF_ACCESS_AUD: 'bad' }, { ...ENV_ENFORCE, ADMIN_ACCESS_MODE: 'enfroce' }]) {
      const v = await access.evaluateAccess(req(await mint(keyA)), { env, deps });
      expect(v).toMatchObject({ allowed: false, status: 503, publicCode: 'ACCESS_UNAVAILABLE' });
    }
  });

  test('the cookie is honoured only when the caller opts in', async () => {
    const token = await mint(keyA);
    const cookieReq = { headers: { cookie: `CF_Authorization=${token}` } };
    expect((await access.evaluateAccess(cookieReq, { env: ENV_ENFORCE, deps })).allowed).toBe(false);
    expect((await access.evaluateAccess(cookieReq, { env: ENV_ENFORCE, deps, allowCookie: true })).allowed).toBe(true);
  });
});

describe('gate: auditing, responding, attributing', () => {
  const run = async (env, headers, extra = {}) => {
    const audit = jest.fn(async () => {});
    const respond = jest.fn();
    const req = { headers };
    const allowed = await access.gate(req, { endpoint: 'admin-router', action: 'approve', ip: '203.0.113.7', audit, respond, env, deps, ...extra });
    return { allowed, audit, respond, req };
  };

  test('off: allowed, silent, no identity', async () => {
    const r = await run({}, {});
    expect(r.allowed).toBe(true);
    expect(r.audit).not.toHaveBeenCalled();
    expect(r.respond).not.toHaveBeenCalled();
    expect(r.req.adminIdentity).toBeUndefined();
  });

  test('enforce + valid: allowed, operator attached, nothing extra logged', async () => {
    const r = await run(ENV_ENFORCE, { 'cf-access-jwt-assertion': await mint(keyA) });
    expect(r.allowed).toBe(true);
    expect(r.req.adminIdentity).toMatchObject({ kind: 'user', id: 'ops@example.com' });
    expect(r.audit).not.toHaveBeenCalled();
  });

  test('enforce + denied: responds with the public code only, logs a short internal code and no token', async () => {
    const token = await mint(keyA, { payload: { aud: [AUD2] } });
    const r = await run(ENV_ENFORCE, { 'cf-access-jwt-assertion': token });
    expect(r.allowed).toBe(false);
    expect(r.respond).toHaveBeenCalledWith(401, 'ACCESS_REQUIRED', expect.any(String));
    expect(r.audit).toHaveBeenCalledWith('ADMIN_ACCESS_DENIED', { ip: '203.0.113.7', endpoint: 'admin-router', requested: 'approve', mode: 'enforce', result: 'ACCESS_TOKEN_AUDIENCE', actor: null });
    expect(JSON.stringify(r.audit.mock.calls)).not.toContain(token.split('.')[2]);
    expect(r.req.adminIdentity).toBeUndefined();
  });

  test('the audit payload can never overwrite the event name (no "action" key; auditLog spreads data after it)', async () => {
    const r = await run(ENV_ENFORCE, {});
    const [event, data] = r.audit.mock.calls[0];
    expect(event).toBe('ADMIN_ACCESS_DENIED');
    expect(Object.keys(data)).not.toContain('action');
    // simulate auditLog's own composition and prove the event type survives
    expect({ action: event, ts: 'x', ...data }.action).toBe('ADMIN_ACCESS_DENIED');
  });

  test('audit mode logs every request (allowed) with the observed result and the operator when known', async () => {
    const env = { ...ENV_ENFORCE, ADMIN_ACCESS_MODE: 'audit' };
    const ok = await run(env, { 'cf-access-jwt-assertion': await mint(keyA) });
    expect(ok.allowed).toBe(true);
    expect(ok.audit).toHaveBeenCalledWith('ADMIN_ACCESS_AUDIT', expect.objectContaining({ mode: 'audit', result: 'ACCESS_OK', actor: 'user:ops@example.com' }));
    expect(ok.req.adminIdentity.id).toBe('ops@example.com');
    const missing = await run(env, {});
    expect(missing.allowed).toBe(true);
    expect(missing.respond).not.toHaveBeenCalled();
    expect(missing.audit).toHaveBeenCalledWith('ADMIN_ACCESS_AUDIT', expect.objectContaining({ result: 'ACCESS_TOKEN_MISSING', actor: null }));
  });

  test('an audit-sink failure never results in an allow: the gate rejects instead of continuing', async () => {
    const audit = jest.fn(async () => { throw new Error('redis down'); });
    const respond = jest.fn();
    await expect(access.gate({ headers: {} }, { endpoint: 'e', action: 'a', ip: 'i', audit, respond, env: ENV_ENFORCE, deps })).rejects.toThrow('redis down');
    expect(respond).not.toHaveBeenCalled(); // the caller's own auditLog never throws (it swallows), so this documents the contract
  });
});

describe('actorLabel', () => {
  test('labels users and services, and is null without an identity', () => {
    expect(access.actorLabel({ kind: 'user', id: 'a@b.co' })).toBe('user:a@b.co');
    expect(access.actorLabel({ kind: 'service', id: 'cid' })).toBe('service:cid');
    expect(access.actorLabel(null)).toBeNull();
    expect(access.actorLabel(undefined)).toBeNull();
    expect(access.actorLabel({ kind: 'user' })).toBeNull();
  });
});
