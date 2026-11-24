'use strict';
/**
 * Cloudflare Access on action=review-queue of api/v1/detections/performance.js.
 *
 * This action shares its URL path with customer actions, so an Access application cannot isolate it by
 * path: the Worker verifies the Access token itself, accepting the header OR the CF_Authorization cookie
 * set at sign-in. The admin key remains a required second factor.
 */
process.env.ADMIN_SECRET_KEY = 'test-admin-key-0123456789abcdef';

jest.mock('../../_lib/redis', () => {
  // Explicit spies for what the assertions read; every other Redis call (customer authentication, analytics
  // counters) resolves to null so the unrelated customer path can run.
  const explicit = { zadd: jest.fn(async () => 1), pipeline: jest.fn(async () => []) };
  return new Proxy(explicit, {
    get: (target, prop) => (prop in target ? target[prop] : typeof prop === 'symbol' || prop === '__esModule' ? undefined : (target[prop] = jest.fn(async () => null))),
  });
});
jest.mock('../../_lib/middleware', () => {
  const actual = jest.requireActual('../../_lib/middleware');
  return { ...actual, authenticate: jest.fn(actual.authenticate) };
});
jest.mock('../../_lib/security', () => {
  const actual = jest.requireActual('../../_lib/security');
  return { ...actual, globalIpRateLimit: jest.fn(async () => true), adminIpRateLimit: jest.fn(async () => true) };
});
jest.mock('../../_lib/d1', () => {
  const { createFakeD1 } = require('../../_lib/__fixtures__/fake-d1');
  return createFakeD1();
});
jest.mock('../../_lib/detection-performance-engine');

const { webcrypto } = require('node:crypto');
const redis = require('../../_lib/redis');
const access = require('../../_lib/admin-access');
const performanceEngine = require('../../_lib/detection-performance-engine');
const handler = require('../detections/performance');

const subtle = webcrypto.subtle;
const TEAM = 'acme-sec';
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = 'e'.repeat(64);
const KEY = process.env.ADMIN_SECRET_KEY;
const b64u = (v) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');

let signer;
async function mint(payload = {}) {
  const nowS = Math.floor(Date.now() / 1000);
  const input = `${b64u({ alg: 'RS256', kid: 'perf-kid', typ: 'JWT' })}.${b64u({ iss: ISS, aud: [AUD], exp: nowS + 3600, iat: nowS - 5, email: 'analyst@example.com', ...payload })}`;
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
async function reviewQueue(headers = {}) {
  const req = { method: 'GET', query: { action: 'review-queue' }, headers: { 'content-type': 'application/json', ...headers }, url: '/api/v1/detections/performance' };
  const res = mockRes();
  await handler(req, res);
  return res;
}
const auditActions = () => redis.zadd.mock.calls.map((c) => JSON.parse(c[2]));
function setMode(mode) {
  process.env.CF_ACCESS_TEAM_DOMAIN = TEAM;
  process.env.CF_ACCESS_AUD = AUD;
  if (mode === undefined) delete process.env.ADMIN_ACCESS_MODE; else process.env.ADMIN_ACCESS_MODE = mode;
}

beforeAll(async () => {
  const pair = await subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const jwk = await subtle.exportKey('jwk', pair.publicKey);
  signer = { privateKey: pair.privateKey, jwk: { ...jwk, kid: 'perf-kid', alg: 'RS256', use: 'sig' } };
}, 60000);

beforeEach(() => {
  access.resetForTest();
  redis.zadd.mockClear();
  performanceEngine.computeReviewQueue = jest.fn().mockResolvedValue([{ detection_id: 'det_1', priority_tier: 'CRITICAL' }]);
  global.fetch = jest.fn(async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ keys: [signer.jwk] }) }));
});
afterAll(() => {
  delete process.env.ADMIN_ACCESS_MODE;
  delete process.env.CF_ACCESS_TEAM_DOMAIN;
  delete process.env.CF_ACCESS_AUD;
});

describe('review-queue with Access off (default)', () => {
  test('unchanged: the key alone is enough, no Access verification happens', async () => {
    setMode(undefined);
    const res = await reviewQueue({ 'x-admin-key': KEY });
    expect(res.statusCode).toBe(200);
    expect(global.fetch).not.toHaveBeenCalled();
  });
});

describe('review-queue with Access enforced', () => {
  beforeEach(() => setMode('enforce'));

  test('no token -> 401 ACCESS_REQUIRED even with the key; the queue is never computed', async () => {
    const res = await reviewQueue({ 'x-admin-key': KEY });
    expect(res.statusCode).toBe(401);
    expect(res.body.error.code).toBe('ACCESS_REQUIRED');
    expect(performanceEngine.computeReviewQueue).not.toHaveBeenCalled();
    expect(auditActions()[0]).toMatchObject({ action: 'ADMIN_ACCESS_DENIED', endpoint: 'detections/performance', requested: 'review-queue', result: 'ACCESS_TOKEN_MISSING' });
  });

  test('token in the Cf-Access-Jwt-Assertion header + key -> 200', async () => {
    const res = await reviewQueue({ 'x-admin-key': KEY, 'cf-access-jwt-assertion': await mint() });
    expect(res.statusCode).toBe(200);
    expect(res.body.queue[0].priority_tier).toBe('CRITICAL');
  });

  test('token only in the CF_Authorization cookie (the browser page flow) + key -> 200', async () => {
    const res = await reviewQueue({ 'x-admin-key': KEY, cookie: `theme=dark; CF_Authorization=${await mint()}` });
    expect(res.statusCode).toBe(200);
  });

  test('valid token + wrong key -> 401 from the key gate, recorded as ADMIN_AUTH_FAIL (not under the requested action)', async () => {
    const res = await reviewQueue({ 'x-admin-key': 'wrong-key-wrong-key', 'cf-access-jwt-assertion': await mint() });
    expect(res.statusCode).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
    expect(auditActions()).toHaveLength(1);
    expect(auditActions()[0]).toMatchObject({ action: 'ADMIN_AUTH_FAIL', requested: 'review-queue', endpoint: 'detections/performance' });
  });

  test('a forged cookie (signed by another key) is refused', async () => {
    const other = await subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
    const nowS = Math.floor(Date.now() / 1000);
    const input = `${b64u({ alg: 'RS256', kid: 'perf-kid' })}.${b64u({ iss: ISS, aud: [AUD], exp: nowS + 3600, email: 'attacker@evil.com' })}`;
    const sig = Buffer.from(await subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, other.privateKey, Buffer.from(input))).toString('base64url');
    const res = await reviewQueue({ 'x-admin-key': KEY, cookie: `CF_Authorization=${input}.${sig}` });
    expect(res.statusCode).toBe(401);
    expect(res.body.error.code).toBe('ACCESS_REQUIRED');
  });

  test('customer actions of the same endpoint are unaffected by the admin gate', async () => {
    const req = { method: 'GET', query: { action: 'quality' }, headers: {}, url: '/api/v1/detections/performance' };
    const res = mockRes();
    await handler(req, res);
    expect(res.body.error.code).not.toBe('ACCESS_REQUIRED'); // still the customer authentication path
    expect(global.fetch).not.toHaveBeenCalled();
  });
});
