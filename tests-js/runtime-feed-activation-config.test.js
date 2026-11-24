'use strict';
// Option A PR-4 (activation): pins the ONLY Wrangler changes that switch the runtime feed on.
// A loose value here is a billing and safety event, not a style choice:
//   - `run_worker_first: true` or any wildcard would bill a Worker request for EVERY static asset;
//   - a binding to the premium bucket would expose paid artifacts to the public read-through;
//   - a binding name that differs from what the Worker reads would silently leave the feature off.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { serveFeed, FEEDS } = require('../workers/lib/runtime-feed');

const text = fs.readFileSync(path.resolve(__dirname, '../wrangler.jsonc'), 'utf8');
// Same comment-stripping the other Wrangler tests use (full-line // comments only).
const cfg = JSON.parse(text.replace(/^\s*\/\/.*$/gm, ''));
const EXPECTED_PATHS = ['/live-intel.json', '/api/intel/live.json', '/rss.xml'];

test('run_worker_first is exactly the three literal feed paths: no boolean, no wildcard, no negation', () => {
  const rwf = cfg.assets.run_worker_first;
  assert.ok(Array.isArray(rwf), 'must be an array, never `true`');
  assert.deepEqual([...rwf].sort(), [...EXPECTED_PATHS].sort());
  for (const p of rwf) {
    assert.match(p, /^\/[A-Za-z0-9._\/-]+$/, 'literal path only: ' + p);
    assert.ok(!/[*!?#]/.test(p), 'no wildcard, negation or query: ' + p);
  }
  assert.equal(new Set(rwf).size, rwf.length, 'no duplicates');
});

test('the Wrangler paths and the Worker allowlist are the same set (single source of truth)', () => {
  assert.deepEqual([...cfg.assets.run_worker_first].sort(), Object.keys(FEEDS).sort());
});

test('no other asset setting changed: the static build is served exactly as before', () => {
  assert.deepEqual(Object.keys(cfg.assets).sort(), ['binding', 'directory', 'html_handling', 'run_worker_first']);
  assert.equal(cfg.assets.directory, './dist-public');
  assert.equal(cfg.assets.binding, 'ASSETS', 'the Worker falls through to env.ASSETS');
  assert.equal(cfg.assets.html_handling, 'none');
});

test('RUNTIME_FEED is a dedicated bucket and can never be the premium (paid) bucket', () => {
  const bindings = cfg.r2_buckets;
  const runtime = bindings.filter((b) => b.binding === 'RUNTIME_FEED');
  assert.equal(runtime.length, 1);
  assert.equal(runtime[0].bucket_name, 'soc-runtime-feed');
  assert.ok(!/premium/i.test(runtime[0].bucket_name));
  // The paid-artifact binding is untouched, and no two bindings share a bucket.
  assert.deepEqual(bindings.find((b) => b.binding === 'PREMIUM_REPORTS'), { binding: 'PREMIUM_REPORTS', bucket_name: 'sentinel-apex-premium-reports' });
  assert.equal(new Set(bindings.map((b) => b.bucket_name)).size, bindings.length);
  assert.deepEqual(bindings.map((b) => b.binding).sort(), ['PREMIUM_REPORTS', 'RUNTIME_FEED']);
});

test('the binding name in Wrangler is the property the Worker actually reads', async () => {
  const name = cfg.r2_buckets.find((b) => b.bucket_name === 'soc-runtime-feed').binding;
  const body = '{"a":1}';
  const bytes = Buffer.from(body);
  const object = {
    size: bytes.length,
    customMetadata: { sha256: require('node:crypto').createHash('sha256').update(body).digest('hex'), 'generated-at': '2026-11-24T15:58:00Z' },
    body: new Response(bytes).body,
  };
  const env = { [name]: { async get() { return object; } } };
  const r = await serveFeed(new Request('https://soc.cyberdudebivash.in/live-intel.json'), env, '/live-intel.json', null, Date.parse('2026-11-24T16:00:00Z'));
  assert.ok(r, 'the Worker must find the bucket under the Wrangler binding name');
  assert.equal(r.headers.get('x-feed-source'), 'runtime-r2');
});

test('nothing else that bills changed: no new paid add-on, same cron cadence, bounded logging', () => {
  for (const addon of ['ai', 'vectorize', 'queues', 'durable_objects', 'hyperdrive', 'browser', 'images']) assert.equal(cfg[addon], undefined, addon);
  assert.deepEqual(cfg.triggers.crons, ['*/30 * * * *']);
  assert.ok(cfg.observability.head_sampling_rate > 0 && cfg.observability.head_sampling_rate <= 0.1);
  assert.deepEqual(cfg.routes.map((r) => r.pattern).sort(), ['blog.cyberdudebivash.in', 'soc.cyberdudebivash.in']);
});
