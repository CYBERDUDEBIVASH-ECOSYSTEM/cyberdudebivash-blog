'use strict';
/**
 * The consolidated admin router (api/v1/admin.js) validated `action` BEFORE the Cloudflare Access gate and the X-Admin-Key check, so an
 * anonymous GET /api/v1/admin (no action) was answered with 400 MISSING_ACTION and the complete list of admin operations, including the
 * payment ones (razorpay-orders, product-orders, gumroad-sales). Measured on the live site before this change. Nothing could be executed
 * without the key, so this is reconnaissance only, but an unauthenticated caller must learn nothing about the admin surface.
 *
 * Real handler, real X-Admin-Key gate; only Redis, the request guard and the IP rate limiter are replaced (same harness as
 * admin-access.integration.test.js).
 */
process.env.ADMIN_SECRET_KEY = 'test-admin-key-0123456789abcdef';
delete process.env.ADMIN_ACCESS_MODE;

jest.mock('../../_lib/redis', () => ({
  zrevrange: jest.fn(async () => []),
  zadd: jest.fn(async () => 1),
  pipeline: jest.fn(async () => []),
}));
jest.mock('../../_lib/security', () => {
  const actual = jest.requireActual('../../_lib/security');
  return { ...actual, guardRequest: jest.fn(async () => true), adminIpRateLimit: jest.fn(async () => true) };
});

const redis = require('../../_lib/redis');
const handler = require('../admin');

const KEY = process.env.ADMIN_SECRET_KEY;
const ACTION_NAMES = ['pending', 'approve', 'reject', 'audit', 'razorpay-orders', 'product-orders', 'gumroad-sales'];

function mockRes() {
  const res = { statusCode: null, body: null, headers: {} };
  res.setHeader = jest.fn((k, v) => { res.headers[k] = v; });
  res.status = jest.fn((s) => { res.statusCode = s; return res; });
  res.json = jest.fn((b) => { res.body = b; return res; });
  res.end = jest.fn(() => res);
  return res;
}
async function call({ headers = {}, query = {}, method = 'GET' } = {}) {
  const req = { method, query, headers: { 'content-type': 'application/json', ...headers }, url: '/api/v1/admin' };
  const res = mockRes();
  await handler(req, res);
  return res;
}
const leaksActionNames = (res) => ACTION_NAMES.filter((n) => JSON.stringify(res.body || {}).includes(n));
const auditActions = () => redis.zadd.mock.calls.map((c) => JSON.parse(c[2]));

beforeEach(() => { jest.clearAllMocks(); });

describe('REGRESSION: an unauthenticated caller learns no admin action names', () => {
  it('no key, no action: 401 and none of the action names in the body', async () => {
    const res = await call();
    expect(res.statusCode).toBe(401);
    expect(res.body.error.code).toBe('UNAUTHORIZED');
    expect(leaksActionNames(res)).toEqual([]);
  });

  it('wrong key, no action: 401 and none of the action names in the body', async () => {
    const res = await call({ headers: { 'x-admin-key': 'not-the-key' } });
    expect(res.statusCode).toBe(401);
    expect(leaksActionNames(res)).toEqual([]);
  });

  it('empty and whitespace actions are treated as missing, not echoed', async () => {
    for (const action of ['', '   ', undefined]) {
      const res = await call({ query: { action } });
      expect(res.statusCode).toBe(401);
      expect(leaksActionNames(res)).toEqual([]);
    }
  });

  it('an unknown action without a key is 401 and does not echo the action or the list', async () => {
    const res = await call({ query: { action: 'definitely-not-real' } });
    expect(res.statusCode).toBe(401);
    expect(JSON.stringify(res.body)).not.toContain('definitely-not-real');
    expect(leaksActionNames(res)).toEqual([]);
  });

  it('the failed probe is still audited (ADMIN_AUTH_FAIL)', async () => {
    await call({ headers: { 'user-agent': 'scanner/1.0' } });
    expect(auditActions().some((e) => e.action === 'ADMIN_AUTH_FAIL' && e.endpoint === 'admin-router')).toBe(true);
  });
});

describe('authenticated operators are unaffected', () => {
  it('valid key, no action: 400 MISSING_ACTION with the valid list (behaviour preserved for operators)', async () => {
    const res = await call({ headers: { 'x-admin-key': KEY } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('MISSING_ACTION');
    expect(leaksActionNames(res).sort()).toEqual([...ACTION_NAMES].sort());
  });

  it('valid key, unknown action: 400 INVALID_ACTION (unchanged)', async () => {
    const res = await call({ headers: { 'x-admin-key': KEY }, query: { action: 'nope' } });
    expect(res.statusCode).toBe(400);
    expect(res.body.error.code).toBe('INVALID_ACTION');
  });

  it('valid key, valid action: the route runs', async () => {
    const res = await call({ headers: { 'x-admin-key': KEY }, query: { action: 'audit' } });
    expect(res.statusCode).toBe(200);
  });
});

describe('source contract', () => {
  it('the MISSING_ACTION response comes after the key check in the router', () => {
    const src = require('node:fs').readFileSync(require('node:path').join(__dirname, '..', 'admin.js'), 'utf8');
    const auth = src.indexOf('sec.verifyAdminKey(req)');
    const missing = src.indexOf("'MISSING_ACTION'");
    expect(auth).toBeGreaterThan(0);
    expect(missing).toBeGreaterThan(auth);
  });
});
