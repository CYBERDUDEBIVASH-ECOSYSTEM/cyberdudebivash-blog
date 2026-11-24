'use strict';
/**
 * auditLog(event, data) in api/_lib/payment-utils.js: the event name is authoritative.
 *
 * Defect (found 2026-11-25): the entry was built as { action: event, ts, ...data }, so a data key called
 * "action" REPLACED the event name. Three production call sites do that:
 *   - ADMIN_AUTH_FAIL in api/v1/admin.js                 (action = the admin action asked for)
 *   - ADMIN_AUTH_FAIL in api/v1/detections/performance.js (action = "review-queue")
 *   - SUBSCRIPTION_MANAGED in api/v1/billing-legacy.js    (action = pause / resume / cancel)
 * Those entries were stored as {action:"approve"} / {action:"cancel"}, so a search of the audit log by event
 * name (the admin audit view's filter) could not find failed admin logins or subscription changes.
 */
jest.mock('../redis', () => ({
  zadd: jest.fn(async () => 1),
  pipeline: jest.fn(async () => []),
}));

const redis = require('../redis');
const { auditLog } = require('../payment-utils');

const lastEntry = () => JSON.parse(redis.zadd.mock.calls.at(-1)[2]);

beforeEach(() => {
  redis.zadd.mockClear();
  redis.pipeline.mockClear();
  redis.zadd.mockImplementation(async () => 1);
});

describe('the event name always wins', () => {
  test('ADMIN_AUTH_FAIL from the admin router keeps its name; the requested admin action is preserved', async () => {
    await auditLog('ADMIN_AUTH_FAIL', { ip: '203.0.113.7', action: 'approve', endpoint: 'admin-router', ua: 'curl/8' });
    expect(lastEntry()).toMatchObject({ action: 'ADMIN_AUTH_FAIL', requested: 'approve', ip: '203.0.113.7', endpoint: 'admin-router', ua: 'curl/8' });
  });

  test('ADMIN_AUTH_FAIL from the review queue', async () => {
    await auditLog('ADMIN_AUTH_FAIL', { ip: '203.0.113.7', action: 'review-queue', endpoint: 'detections/performance' });
    expect(lastEntry()).toMatchObject({ action: 'ADMIN_AUTH_FAIL', requested: 'review-queue', endpoint: 'detections/performance' });
  });

  test.each(['pause', 'resume', 'cancel'])('SUBSCRIPTION_MANAGED keeps its name for a "%s"; the operation is preserved', async (operation) => {
    await auditLog('SUBSCRIPTION_MANAGED', { email: 'a@b.co', subscriptionId: 'sub_1', action: operation, ip: '203.0.113.9' });
    expect(lastEntry()).toMatchObject({ action: 'SUBSCRIPTION_MANAGED', requested: operation, email: 'a@b.co', subscriptionId: 'sub_1', ip: '203.0.113.9' });
  });

  test('no data value can ever replace the event name, whatever its type', async () => {
    for (const hostile of ['PAYMENT_APPROVED', '', 0, false, null, { nested: true }, ['x']]) {
      await auditLog('DUPLICATE_TXN', { action: hostile });
      expect(lastEntry().action).toBe('DUPLICATE_TXN');
      expect(lastEntry().requested).toEqual(hostile); // and the value is kept, falsy ones included
    }
  });

  test('a caller that already supplies "requested" loses nothing: the colliding value goes to "requestedAction"', async () => {
    await auditLog('X_EVENT', { action: 'cancel', requested: 'explicit' });
    expect(lastEntry()).toMatchObject({ action: 'X_EVENT', requested: 'explicit', requestedAction: 'cancel' });
  });
});

describe('entries without a colliding key are byte-for-byte what they were', () => {
  test('keys and order: action, ts, then the data (no "requested", no extra fields)', async () => {
    await auditLog('PAYMENT_APPROVED', { transactionId: 't1', email: 'a@b.co', amount: 100 });
    const raw = redis.zadd.mock.calls.at(-1)[2];
    expect(Object.keys(JSON.parse(raw))).toEqual(['action', 'ts', 'transactionId', 'email', 'amount']);
  });

  test('missing, null or empty data still WRITES a valid entry (a swallowed crash would write nothing)', async () => {
    for (const args of [[], [undefined], [null], [{}]]) {
      redis.zadd.mockClear();
      await auditLog('RATE_LIMIT_HIT', ...args);
      expect(redis.zadd).toHaveBeenCalledTimes(1); // a new entry, not a leftover from the previous call
      expect(Object.keys(lastEntry())).toEqual(['action', 'ts']);
    }
  });

  test('an explicit undefined action is not recorded as "requested"', async () => {
    await auditLog('X_EVENT', { action: undefined, ip: '1.1.1.1' });
    expect(Object.keys(lastEntry())).toEqual(['action', 'ts', 'ip']);
  });

  test('the entry is written to the audit sorted set and the log is trimmed, as before', async () => {
    await auditLog('X_EVENT', { ip: '1.1.1.1' });
    expect(redis.zadd).toHaveBeenCalledWith('audit:payment:log', expect.any(Number), expect.any(String));
    expect(redis.pipeline).toHaveBeenCalledTimes(1);
    expect(redis.pipeline.mock.calls[0][0][0][0]).toBe('ZREMRANGEBYRANK');
  });
});

describe('failure contract is unchanged: an audit failure never breaks the caller', () => {
  test('a throwing store resolves quietly', async () => {
    redis.zadd.mockImplementation(async () => { throw new Error('redis down'); });
    await expect(auditLog('X_EVENT', { action: 'approve' })).resolves.toBeUndefined();
  });
});
