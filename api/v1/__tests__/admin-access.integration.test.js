'use strict';
/**
 * Cloudflare Access in front of the admin router (api/v1/admin.js), end to end through the real handler:
 * real Access gate, real X-Admin-Key gate, real signed tokens. Only Redis, the request guard and the IP
 * rate limiter are replaced.
 */
process.env.ADMIN_SECRET_KEY = 'test-admin-key-0123456789abcdef';

jest.mock('../../_lib/redis', () => ({
  zrevrange: jest.fn(async () => []),
  zadd: jest.fn(async () => 1),
  pipeline: jest.fn(async () => []),
}));
jest.mock('../../_lib/security', () => {
  const actual = jest.requireActual('../../_lib/security');
  return { ...actual, guardRequest: jest.fn(async () => true), adminIpRateLimit: jest.fn(async () => true) };
});

const fs = require('node:fs');
const path = require('node:path');
const { webcrypto } = require('node:crypto');
const redis = require('../../_lib/redis');
const access = require('../../_lib/admin-access');
const handler = require('../admin');

const subtle = webcrypto.subtle;
const TEAM = 'acme-sec';
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = 'c'.repeat(64);
const OTHER_AUD = 'd'.repeat(64);
const KEY = process.env.ADMIN_SECRET_KEY;
const b64u = (v) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');

let signer;
async function mint(payload = {}) {
  const nowS = Math.floor(Date.now() / 1000);
  const input = `${b64u({ alg: 'RS256', kid: 'int-kid', typ: 'JWT' })}.${b64u({ iss: ISS, aud: [AUD], exp: nowS + 3600, iat: nowS - 5, email: 'Finance@Example.com', sub: 's1', ...payload })}`;
  const sig = await subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, signer.privateKey, Buffer.from(input));
  return `${input}.${Buffer.from(sig).toString('base64url')}`;
}

function mockRes() {
  const res = { statusCode: null, body: null, headers: {} };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn((s) => { res.statusCode = s; return res; });
  res.json = jest.fn((b) => { res.body = b; return res; });
  res.end = jest.fn(() => res);
  return res;
}
async function call({ headers = {}, query = { action: 'audit' } } = {}) {
  const req = { method: 'GET', query, headers: { 'content-type': 'application/json', ...headers }, url: '/api/v1/admin' };
  const res = mockRes();
  await handler(req, res);
  return { res, req };
}
const auditActions = () => redis.zadd.mock.calls.map((c) => JSON.parse(c[2]));
const accessEvents = () => auditActions().filter((e) => String(e.action).startsWith('ADMIN_ACCESS_'));

const SET = { ADMIN_ACCESS_MODE: undefined, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD };
function setMode(mode) {
  process.env.CF_ACCESS_TEAM_DOMAIN = SET.CF_ACCESS_TEAM_DOMAIN;
  process.env.CF_ACCESS_AUD = SET.CF_ACCESS_AUD;
  if (mode === undefined) delete process.env.ADMIN_ACCESS_MODE; else process.env.ADMIN_ACCESS_MODE = mode;
}

beforeAll(async () => {
  const pair = await subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const jwk = await subtle.exportKey('jwk', pair.publicKey);
  signer = { privateKey: pair.privateKey, jwk: { ...jwk, kid: 'int-kid', alg: 'RS256', use: 'sig' } };
}, 60000);

beforeEach(() => {
  access.resetForTest();
  redis.zadd.mockClear();
  global.fetch = jest.fn(async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ keys: [signer.jwk] }) }));
});
afterAll(() => {
  delete process.env.ADMIN_ACCESS_MODE;
  delete process.env.CF_ACCESS_TEAM_DOMAIN;
  delete process.env.CF_ACCESS_AUD;
});

describe('mode off (the default): behaviour is exactly as before', () => {
  test.each([undefined, 'off'])('ADMIN_ACCESS_MODE=%s: no key -> 401 UNAUTHORIZED + ADMIN_AUTH_FAIL; valid key -> 200', async (mode) => {
    setMode(mode);
    const denied = await call();
    expect(denied.res.statusCode).toBe(401);
    expect(denied.res.body.error.code).toBe('UNAUTHORIZED');
    expect(auditActions()).toHaveLength(1); // the key-failure entry, and nothing from the Access gate
    expect(auditActions()[0]).toMatchObject({ action: 'ADMIN_AUTH_FAIL', requested: 'audit', endpoint: 'admin-router' });
    expect(accessEvents()).toEqual([]);
    const allowed = await call({ headers: { 'x-admin-key': KEY } });
    expect(allowed.res.statusCode).toBe(200);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test('a garbage Access header is ignored entirely when off', async () => {
    setMode(undefined);
    const r = await call({ headers: { 'x-admin-key': KEY, 'cf-access-jwt-assertion': 'garbage' } });
    expect(r.res.statusCode).toBe(200);
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

describe('mode enforce: Access identity AND the admin key are both required', () => {
  beforeEach(() => setMode('enforce'));

  test('valid Access token + valid key -> 200, and the operator is attached to the request', async () => {
    const r = await call({ headers: { 'x-admin-key': KEY, 'cf-access-jwt-assertion': await mint() } });
    expect(r.res.statusCode).toBe(200);
    expect(r.req.adminIdentity).toMatchObject({ kind: 'user', id: 'finance@example.com' });
    expect(auditActions()).toEqual([]);
  });

  test('no Access token -> 401 ACCESS_REQUIRED even with the right key; the key check is never reached', async () => {
    const r = await call({ headers: { 'x-admin-key': KEY } });
    expect(r.res.statusCode).toBe(401);
    expect(r.res.body.error.code).toBe('ACCESS_REQUIRED');
    const events = auditActions();
    expect(events).toHaveLength(1); // the key gate was never reached, so no key-failure entry
    expect(events[0]).toMatchObject({ action: 'ADMIN_ACCESS_DENIED', endpoint: 'admin-router', requested: 'audit', mode: 'enforce', result: 'ACCESS_TOKEN_MISSING' });
  });

  test('valid Access token + wrong key -> 401 UNAUTHORIZED from the key gate (still two factors)', async () => {
    const r = await call({ headers: { 'x-admin-key': 'wrong-key-wrong-key', 'cf-access-jwt-assertion': await mint() } });
    expect(r.res.statusCode).toBe(401);
    expect(r.res.body.error.code).toBe('UNAUTHORIZED');
    expect(auditActions()).toHaveLength(1);
    expect(auditActions()[0]).toMatchObject({ action: 'ADMIN_AUTH_FAIL', requested: 'audit', endpoint: 'admin-router' });
    expect(accessEvents()).toEqual([]); // the identity check passed, so it logged nothing
  });

  test('a token for another application (wrong audience) is refused and the reason is not leaked', async () => {
    const r = await call({ headers: { 'x-admin-key': KEY, 'cf-access-jwt-assertion': await mint({ aud: [OTHER_AUD] }) } });
    expect(r.res.statusCode).toBe(401);
    expect(JSON.stringify(r.res.body)).not.toMatch(/audience|signature|expired|jwks/i);
    expect(accessEvents()[0]).toMatchObject({ action: 'ADMIN_ACCESS_DENIED', result: 'ACCESS_TOKEN_AUDIENCE' });
  });

  test('the admin API does NOT accept the Access cookie (header only), unlike review-queue', async () => {
    const r = await call({ headers: { 'x-admin-key': KEY, cookie: `CF_Authorization=${await mint()}` } });
    expect(r.res.statusCode).toBe(401);
    expect(r.res.body.error.code).toBe('ACCESS_REQUIRED');
  });

  test('Cloudflare key set unreachable -> 503 ACCESS_UNAVAILABLE, nothing proceeds', async () => {
    global.fetch = jest.fn(async () => { throw new Error('down'); });
    const r = await call({ headers: { 'x-admin-key': KEY, 'cf-access-jwt-assertion': await mint() } });
    expect(r.res.statusCode).toBe(503);
    expect(r.res.body.error.code).toBe('ACCESS_UNAVAILABLE');
  });

  test('a misconfigured enforce (no audience) denies with 503 rather than skipping the check', async () => {
    delete process.env.CF_ACCESS_AUD;
    const r = await call({ headers: { 'x-admin-key': KEY, 'cf-access-jwt-assertion': await mint() } });
    expect(r.res.statusCode).toBe(503);
    expect(accessEvents()[0]).toMatchObject({ action: 'ADMIN_ACCESS_DENIED', result: 'ACCESS_AUD_INVALID' });
  });

  test('a mistyped mode value denies (fails closed)', async () => {
    process.env.ADMIN_ACCESS_MODE = 'enfroce';
    const r = await call({ headers: { 'x-admin-key': KEY, 'cf-access-jwt-assertion': await mint() } });
    expect(r.res.statusCode).toBe(503);
  });
});

describe('mode audit: observe, never block', () => {
  beforeEach(() => setMode('audit'));

  test('no token -> still 200 with the key, and the would-be failure is recorded', async () => {
    const r = await call({ headers: { 'x-admin-key': KEY } });
    expect(r.res.statusCode).toBe(200);
    expect(accessEvents()[0]).toMatchObject({ action: 'ADMIN_ACCESS_AUDIT', mode: 'audit', result: 'ACCESS_TOKEN_MISSING', actor: null });
  });

  test('valid token -> 200, recorded with the operator, operator attached', async () => {
    const r = await call({ headers: { 'x-admin-key': KEY, 'cf-access-jwt-assertion': await mint() } });
    expect(r.res.statusCode).toBe(200);
    expect(accessEvents()[0]).toMatchObject({ action: 'ADMIN_ACCESS_AUDIT', result: 'ACCESS_OK', actor: 'user:finance@example.com' });
    expect(r.req.adminIdentity.id).toBe('finance@example.com');
  });

  test('the key is still required in audit mode', async () => {
    const r = await call({ headers: { 'cf-access-jwt-assertion': await mint() } });
    expect(r.res.statusCode).toBe(401);
    expect(r.res.body.error.code).toBe('UNAUTHORIZED');
  });
});

describe('every admin action is behind the gate (not just "audit")', () => {
  test.each(['pending', 'approve', 'reject', 'audit', 'razorpay-orders', 'product-orders', 'gumroad-sales'])('enforce, no token, action=%s -> 401 ACCESS_REQUIRED', async (action) => {
    setMode('enforce');
    const r = await call({ headers: { 'x-admin-key': KEY }, query: { action } });
    expect(r.res.statusCode).toBe(401);
    expect(r.res.body.error.code).toBe('ACCESS_REQUIRED');
  });
});

describe('operator attribution on the payment decisions (contract)', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'admin.js'), 'utf8');
  const block = (event) => {
    const start = source.indexOf(`auditLog('${event}'`);
    return start === -1 ? '' : source.slice(start, source.indexOf('});', start));
  };

  test('PAYMENT_APPROVED and PAYMENT_REJECTED entries carry the verified operator', () => {
    expect(block('PAYMENT_APPROVED')).toContain('actor: adminAccess.actorLabel(req.adminIdentity)');
    expect(block('PAYMENT_REJECTED')).toContain('actor: adminAccess.actorLabel(req.adminIdentity)');
  });

  test('the Access gate runs before the key gate in the router', () => {
    expect(source.indexOf('adminAccess.gate(')).toBeGreaterThan(0);
    expect(source.indexOf('adminAccess.gate(')).toBeLessThan(source.indexOf('sec.verifyAdminKey(req)'));
  });
});
