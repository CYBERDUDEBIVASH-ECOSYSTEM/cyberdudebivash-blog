'use strict';
// Option A publisher side: scripts/publish-runtime-feed.cjs + scripts/lib/r2-sigv4.cjs.
// A mock S3 server RE-VERIFIES every request signature from the bytes that actually
// arrived on the wire, so a mismatch between "what was signed" and "what was sent"
// (path/query encoding, headers) fails here instead of as a 403 in production.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const cp = require('node:child_process');
const { sign, sha256Hex } = require('../scripts/lib/r2-sigv4.cjs');
const { main, PREFIX } = require('../scripts/publish-runtime-feed.cjs');

const NOW = '2026-11-24T16:00:00.000Z';
const iso = (ms) => new Date(ms).toISOString();
const SECRET = 'SECRET-KEY-must-never-be-printed-0123456789';
const ACCESS = 'AKIATESTACCESSKEY0001';
const md5 = (b) => crypto.createHash('md5').update(b).digest('hex');

// ---------- SigV4 known-answer vectors (independent of this implementation) ----------
test('SigV4: AWS test-suite vector "get-vanilla" and the AWS docs IAM ListUsers example match exactly', () => {
  const date = new Date('2015-08-30T12:36:00Z');
  const k = { accessKeyId: 'AKIDEXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', region: 'us-east-1', date, includeContentSha: false, payloadHash: sha256Hex('') };
  assert.equal(sign({ ...k, method: 'GET', host: 'example.amazonaws.com', path: '/', service: 'service' }).signature,
    '5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31');
  assert.equal(sign({ ...k, method: 'GET', host: 'iam.amazonaws.com', path: '/', service: 'iam',
    query: { Action: 'ListUsers', Version: '2010-05-08' }, headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' } }).signature,
  '5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7');
});

// ---------- mock S3 ----------
function mockS3({ failures = {} } = {}) {
  const store = new Map(); const log = []; const secretLog = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const u = new URL(req.url, 'http://x');
      const rawPath = u.pathname.split('/').map(decodeURIComponent).join('/');
      const query = Object.fromEntries(u.searchParams.entries());
      // Re-verify the signature from what actually arrived.
      const auth = req.headers.authorization || '';
      const m = /^AWS4-HMAC-SHA256 Credential=([^/]+)\/(\d{8})\/auto\/s3\/aws4_request, SignedHeaders=([^,]+), Signature=([a-f0-9]{64})$/.exec(auth);
      let okSig = false;
      if (m && m[1] === ACCESS) {
        const hdrs = {};
        for (const n of m[3].split(';')) if (!['host', 'x-amz-date', 'x-amz-content-sha256'].includes(n)) hdrs[n] = req.headers[n];
        const d = req.headers['x-amz-date'];
        const date = new Date(Date.UTC(+d.slice(0, 4), +d.slice(4, 6) - 1, +d.slice(6, 8), +d.slice(9, 11), +d.slice(11, 13), +d.slice(13, 15)));
        const again = sign({ method: req.method, host: req.headers.host, path: rawPath, query, headers: hdrs,
          payloadHash: req.headers['x-amz-content-sha256'], accessKeyId: ACCESS, secretAccessKey: SECRET, date });
        okSig = again.signature === m[4] && sha256Hex(body) === req.headers['x-amz-content-sha256'];
      }
      secretLog.push(auth);
      const [, bucket, ...rest] = rawPath.split('/');
      const key = rest.join('/');
      const entry = { method: req.method, key, query };
      log.push(entry);
      if (!okSig) { res.writeHead(403); return res.end('SignatureDoesNotMatch'); }
      const inject = failures[req.method + ' ' + key];
      if (inject && inject.times > 0) { inject.times--; res.writeHead(inject.status); return res.end('injected'); }
      if (bucket !== 'soc-runtime-feed') { res.writeHead(404); return res.end('NoSuchBucket'); }
      if (req.method === 'PUT') {
        const meta = {};
        for (const [h, v] of Object.entries(req.headers)) if (h.startsWith('x-amz-meta-')) meta[h] = v;
        store.set(key, { body, meta, etag: md5(body) });
        res.writeHead(200, { ETag: '"' + md5(body) + '"' }); return res.end();
      }
      if (req.method === 'HEAD' || (req.method === 'GET' && key)) {
        const o = store.get(key);
        if (!key) { res.writeHead(200); return res.end(); }
        if (!o) { res.writeHead(404); return res.end(); }
        res.writeHead(200, { ETag: '"' + o.etag + '"', ...o.meta });
        return res.end(req.method === 'GET' ? o.body : undefined);
      }
      if (req.method === 'GET' && !key && query['list-type'] === '2') {
        const keys = [...store.keys()].filter((k) => k.startsWith(query.prefix || '')).sort();
        const start = query['continuation-token'] ? keys.findIndex((k) => k > query['continuation-token']) : 0;
        const max = Math.min(Number(query['max-keys'] || 1000), 2); // tiny pages to exercise pagination
        const page = start < 0 ? [] : keys.slice(start, start + max);
        const trunc = start >= 0 && start + max < keys.length;
        const xml = '<ListBucketResult>' + page.map((k) => '<Contents><Key>' + k + '</Key><ETag>&quot;' + store.get(k).etag + '&quot;</ETag></Contents>').join('')
          + '<IsTruncated>' + trunc + '</IsTruncated>' + (trunc ? '<NextContinuationToken>' + page[page.length - 1] + '</NextContinuationToken>' : '') + '</ListBucketResult>';
        res.writeHead(200, { 'content-type': 'application/xml' }); return res.end(xml);
      }
      res.writeHead(400); res.end();
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    store, log, secretLog, port: server.address().port, close: () => new Promise((r) => server.close(r)),
    count: (method) => log.filter((e) => e.method === method).length,
  })));
}

// ---------- fixtures ----------
function feedJson(stampMs, n = 12, extra = {}) {
  return JSON.stringify({ generatedAt: iso(stampMs), metadata: { lastPipelineRun: iso(stampMs) }, totalPublished: n,
    items: Array.from({ length: n }, (_, i) => ({ id: 'i' + i })), ...extra });
}
function apiJson(stampMs) { return JSON.stringify({ generated: iso(stampMs), lastReportGeneratedAt: iso(stampMs), total_published: 12, items: Array.from({ length: 12 }, (_, i) => ({ id: 'i' + i })) }); }
function rss(stampMs, valid = true) { return '<?xml version="1.0"?><rss version="2.0"><channel><lastBuildDate>' + new Date(stampMs).toUTCString() + '</lastBuildDate></channel>' + (valid ? '</rss>' : ''); }
function git(root, ...a) { return cp.execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', ...a], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }
function repo({ stamp = Date.parse(NOW) - 120000, dossiers = ['cve-2026-1.html', 'cve-2026-2.html', 'cve-2026-3.html'], commitsOf = null } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rtfeed-'));
  git(root, 'init', '-q', '-b', 'main');
  fs.mkdirSync(path.join(root, 'api/intel'), { recursive: true }); fs.mkdirSync(path.join(root, 'posts'));
  fs.writeFileSync(path.join(root, 'live-intel.json'), feedJson(stamp));
  fs.writeFileSync(path.join(root, 'api/intel/live.json'), apiJson(stamp));
  fs.writeFileSync(path.join(root, 'rss.xml'), rss(stamp));
  git(root, 'add', '-A'); git(root, 'commit', '-q', '-m', 'base');
  (commitsOf || dossiers.map((d) => [d])).forEach((group, i) => {
    for (const d of group) fs.writeFileSync(path.join(root, 'posts', d), '<!doctype html><title>' + d + ' ' + i + '</title>');
    git(root, 'add', '-A'); git(root, 'commit', '-q', '-m', 'c' + i);
  });
  return root;
}
const envFor = (port, over = {}) => ({ R2_ENDPOINT: 'http://127.0.0.1:' + port, R2_BUCKET: 'soc-runtime-feed', R2_ACCESS_KEY_ID: ACCESS, R2_SECRET_ACCESS_KEY: SECRET, ...over });
// These fixtures are not the repository, so they inject an identity transform. The production
// default (the canonical public-build transform) is exercised in
// runtime-feed-publisher-canonical.test.js against the real repository files.
const RAW = (root, rel) => fs.readFileSync(path.join(root, rel));
async function run(argv, env, deps = { publicBytes: RAW }) {
  const out = []; const err = []; const l = console.log; const e = console.error;
  console.log = (...a) => out.push(a.join(' ')); console.error = (...a) => err.push(a.join(' '));
  try { const r = await main(argv, env, deps); return { code: r.code, out: out.join('\n'), err: err.join('\n'), json: out.length ? safeJson(out[out.length - 1]) : null }; }
  finally { console.log = l; console.error = e; }
}
const safeJson = (s) => { try { return JSON.parse(s); } catch (_) { return null; } };
const base = (root, extra = []) => ['--root', root, '--now', NOW, ...extra];

// ---------- configuration / safety ----------
test('config validation: missing env, bad bucket, premium bucket, unknown or malformed args are refused with exit 1', async () => {
  const s = await mockS3(); const root = repo();
  try {
    for (const [argv, env, what] of [
      [base(root), envFor(s.port, { R2_BUCKET: undefined }), 'missing bucket'],
      [base(root), envFor(s.port, { R2_ACCESS_KEY_ID: '' }), 'missing key id'],
      [base(root), envFor(s.port, { R2_SECRET_ACCESS_KEY: undefined }), 'missing secret'],
      [base(root), envFor(s.port, { R2_BUCKET: 'Bad_Bucket!' }), 'invalid bucket'],
      [base(root), envFor(s.port, { R2_BUCKET: 'sentinel-apex-premium-reports' }), 'premium bucket must be refused'],
      [base(root, ['--bogus']), envFor(s.port), 'unknown arg'],
      [base(root, ['--max-puts', '0']), envFor(s.port), 'zero cap'],
      [base(root, ['--daily-cap', 'abc']), envFor(s.port), 'non-numeric cap'],
      [['--root'], envFor(s.port), 'missing value'],
      [base(root), { R2_BUCKET: 'soc-runtime-feed', R2_ACCESS_KEY_ID: ACCESS, R2_SECRET_ACCESS_KEY: SECRET, R2_ACCOUNT_ID: 'short' }, 'bad account id with no endpoint'],
    ]) { assert.equal((await run(argv, env)).code, 1, what); }
    assert.equal(s.log.length, 0, 'no request may be sent for invalid configuration');
  } finally { await s.close(); }
});

test('--check performs one signed read-only request: OK with valid credentials, failure with wrong ones', async () => {
  const s = await mockS3(); const root = repo();
  try {
    const ok = await run(base(root, ['--check']), envFor(s.port));
    assert.equal(ok.code, 0); assert.equal(ok.json.status, 'R2_AUTH_OK');
    assert.deepEqual(s.log.map((e) => e.method), ['HEAD']);
    const bad = await run(base(root, ['--check']), envFor(s.port, { R2_SECRET_ACCESS_KEY: 'wrong-secret-value' }));
    assert.equal(bad.code, 1); assert.equal(bad.json.status, 'R2_AUTH_FAILED');
  } finally { await s.close(); }
});

// ---------- happy path, dedupe, monotonic ----------
test('first run uploads 3 feeds + dossiers with correct metadata, every signature verified on the wire; second run uploads nothing', async () => {
  const s = await mockS3(); const root = repo();
  try {
    const first = await run(base(root), envFor(s.port));
    assert.equal(first.code, 0, first.err + first.out);
    assert.equal(first.json.putCount, 6); assert.deepEqual(first.json.failed, []);
    const keys = [...s.store.keys()].sort();
    assert.ok(keys.includes(PREFIX + 'live-intel.json') && keys.includes(PREFIX + 'api/intel/live.json') && keys.includes(PREFIX + 'rss.xml'));
    assert.equal(keys.filter((k) => k.startsWith(PREFIX + 'posts/')).length, 3);
    const li = s.store.get(PREFIX + 'live-intel.json');
    assert.equal(li.meta['x-amz-meta-sha256'], sha256Hex(fs.readFileSync(path.join(root, 'live-intel.json'))));
    assert.equal(li.meta['x-amz-meta-generated-at'], iso(Date.parse(NOW) - 120000));
    assert.equal(s.store.get(PREFIX + 'rss.xml').meta['x-amz-meta-generated-at'], iso(Date.parse(NOW) - 120000).replace(/\.\d{3}Z$/, '.000Z'));
    assert.ok(s.store.has(PREFIX + '_counters/2026-11-24.json'), 'daily counter persisted');
    const putsBefore = s.count('PUT');
    const second = await run(base(root), envFor(s.port));
    assert.equal(second.code, 0); assert.equal(second.json.putCount, 0);
    assert.equal(s.count('PUT') - putsBefore, 1, 'only the counter is rewritten when nothing changed');
    assert.equal(second.json.skipped.feed_unchanged, 3); assert.equal(second.json.skipped.dossier_unchanged, 3);
  } finally { await s.close(); }
});

test('monotonic: a feed older than the remote object is never written (safe under reordered runs)', async () => {
  const s = await mockS3(); const newer = repo({ stamp: Date.parse(NOW) - 60000 }); const older = repo({ stamp: Date.parse(NOW) - 3600000 });
  try {
    assert.equal((await run(base(newer), envFor(s.port))).code, 0);
    const before = s.store.get(PREFIX + 'live-intel.json').meta['x-amz-meta-generated-at'];
    const r = await run(base(older), envFor(s.port));
    assert.equal(r.json.skipped.feed_older_than_remote, 3);
    assert.equal(s.store.get(PREFIX + 'live-intel.json').meta['x-amz-meta-generated-at'], before);
  } finally { await s.close(); }
});

test('dossier dedupe is by MD5 vs the LIST: changing one dossier uploads exactly one object; a populated LIST is paginated', async () => {
  const s = await mockS3(); const root = repo({ dossiers: ['a-1.html', 'b-2.html', 'c-3.html', 'd-4.html', 'e-5.html'] });
  try {
    await run(base(root), envFor(s.port));                       // seed the bucket (LIST sees an empty prefix)
    fs.writeFileSync(path.join(root, 'posts', 'c-3.html'), '<!doctype html><title>changed</title>');
    git(root, 'add', '-A'); git(root, 'commit', '-q', '-m', 'edit');
    const mark = s.log.length; const putsBefore = s.count('PUT');
    const r = await run(base(root, ['--since-commits', '50']), envFor(s.port));
    const lists = s.log.slice(mark).filter((e) => e.method === 'GET' && e.query['list-type']).length;
    assert.ok(lists >= 3, 'five stored dossiers at two per page require 3 LIST calls, got ' + lists);
    assert.deepEqual(r.json.put, [PREFIX + 'posts/c-3.html']);
    assert.equal(s.count('PUT') - putsBefore, 2, 'the changed dossier + the counter');
  } finally { await s.close(); }
});

// ---------- cost controls ----------
test('per-run cap: feeds are always first, dossiers are truncated newest-first, nothing exceeds --max-puts', async () => {
  const s = await mockS3(); const root = repo({ dossiers: Array.from({ length: 10 }, (_, i) => 'd-' + String(i).padStart(2, '0') + '.html') });
  try {
    const r = await run(base(root, ['--max-puts', '5', '--since-commits', '50']), envFor(s.port));
    assert.equal(r.json.putCount, 5); assert.equal(r.json.capped, true);
    assert.equal(r.json.put.filter((k) => /\/posts\//.test(k)).length, 2);
    assert.deepEqual(r.json.put.filter((k) => /\/posts\//.test(k)), [PREFIX + 'posts/d-09.html', PREFIX + 'posts/d-08.html'], 'newest first');
    assert.equal(r.code, 0);
  } finally { await s.close(); }
});

test('daily cap: a reached cap writes nothing (exit 3); a nearly-reached cap writes only what fits and never exceeds the cap', async () => {
  const s = await mockS3(); const root = repo({ dossiers: Array.from({ length: 6 }, (_, i) => 'x-' + i + '.html') });
  try {
    const seed = (ops) => s.store.set(PREFIX + '_counters/2026-11-24.json', { body: Buffer.from(JSON.stringify({ ops })), meta: {}, etag: 'x' });
    seed(2999);
    const stop = await run(base(root, ['--daily-cap', '3000']), envFor(s.port));
    assert.equal(stop.code, 3); assert.equal(s.count('PUT'), 0, 'no writes at all when the cap is already reached');
    seed(2990);   // budget 10 - reserve 3 = 7 ops: 3 feeds + 1 LIST + room for exactly 2 dossier PUTs (each needs room for a retry)
    const part = await run(base(root, ['--daily-cap', '3000', '--since-commits', '50']), envFor(s.port));
    assert.equal(part.json.putCount, 5, '3 feeds + 2 dossiers fit, the other 4 dossiers do not; got ' + part.json.putCount);
    assert.equal(part.json.capped, true);
    assert.ok(part.json.dailyOpsUsed <= 3000, 'persisted total must never exceed the cap: ' + part.json.dailyOpsUsed);
  } finally { await s.close(); }
});

test('RETRIES CANNOT OVERSHOOT THE DAILY CAP: even when every write fails with 503 the persisted total stays within the cap', async () => {
  const fail = {};
  const s0 = await mockS3(); const root = repo({ dossiers: Array.from({ length: 8 }, (_, i) => 'r-' + i + '.html') });
  const keys = [PREFIX + 'live-intel.json', PREFIX + 'api/intel/live.json', PREFIX + 'rss.xml', ...Array.from({ length: 8 }, (_, i) => PREFIX + 'posts/r-' + i + '.html')];
  await s0.close();
  for (const k of keys) fail['PUT ' + k] = { times: 99, status: 503 };
  const s = await mockS3({ failures: fail });
  try {
    s.store.set(PREFIX + '_counters/2026-11-24.json', { body: Buffer.from(JSON.stringify({ ops: 2980 })), meta: {}, etag: 'x' });
    const r = await run(base(root, ['--daily-cap', '3000', '--since-commits', '50']), envFor(s.port));
    assert.equal(r.code, 2, 'failures are reported');
    assert.ok(r.json.dailyOpsUsed <= 3000, 'persisted ops ' + r.json.dailyOpsUsed + ' must not exceed the cap of 3000');
    const counter = JSON.parse(s.store.get(PREFIX + '_counters/2026-11-24.json').body.toString());
    assert.ok(counter.ops <= 3000);
    assert.ok(s.count('PUT') <= 2 * (3000 - 2980), 'attempted writes are bounded by the remaining budget, got ' + s.count('PUT'));
  } finally { await s.close(); }
});

test('the counter accounts for EVERY attempt including retries and the LIST, and rolls over per UTC day', async () => {
  const s = await mockS3({ failures: { ['PUT ' + PREFIX + 'rss.xml']: { times: 1, status: 503 } } }); const root = repo({ dossiers: ['a-1.html'] });
  try {
    const r = await run(base(root), envFor(s.port));
    assert.equal(r.code, 0);
    assert.equal(s.count('PUT'), 6, '3 feeds + 1 retry + 1 dossier + the counter');
    const counter = JSON.parse(s.store.get(PREFIX + '_counters/2026-11-24.json').body.toString());
    const lists = s.log.filter((e) => e.method === 'GET' && e.query['list-type']).length;
    assert.equal(counter.ops, s.count('PUT') + lists, 'counter == every Class A attempt actually made (PUTs incl. the retry and the counter itself, plus LISTs)');
    assert.equal(counter.ops, r.json.classAOps);
    const next = await run(['--root', root, '--now', '2026-11-25T01:00:00.000Z'], envFor(s.port));
    assert.ok(s.store.has(PREFIX + '_counters/2026-11-25.json'), 'a new UTC day starts a new counter');
    assert.ok(next.json.dailyOpsUsed < 20);
  } finally { await s.close(); }
});

// ---------- validation: invalid inputs are never uploaded ----------
test('invalid feeds are never uploaded (too few items, bad/future timestamp, malformed rss) but valid ones still are', async () => {
  const s = await mockS3(); const root = repo();
  try {
    fs.writeFileSync(path.join(root, 'live-intel.json'), feedJson(Date.parse(NOW), 3));            // < 10 items
    fs.writeFileSync(path.join(root, 'api/intel/live.json'), apiJson(Date.parse(NOW) + 3600000));   // future
    fs.writeFileSync(path.join(root, 'rss.xml'), rss(Date.parse(NOW), false));                      // truncated
    const r = await run(base(root), envFor(s.port));
    assert.equal(r.code, 2);
    assert.equal(r.json.failed.length, 3);
    assert.ok(r.json.failed.some((x) => x.startsWith('FEED_ITEMS_INVALID')));
    assert.ok(r.json.failed.some((x) => x.startsWith('FEED_TIMESTAMP_FUTURE')));
    assert.ok(r.json.failed.some((x) => x.startsWith('RSS_SHAPE_INVALID')));
    for (const k of ['live-intel.json', 'api/intel/live.json', 'rss.xml']) assert.equal(s.store.has(PREFIX + k), false, k);
    fs.writeFileSync(path.join(root, 'live-intel.json'), '{not json');
    assert.ok((await run(base(root), envFor(s.port))).json.failed.some((x) => x.startsWith('FEED_JSON_INVALID')));
    fs.writeFileSync(path.join(root, 'live-intel.json'), JSON.stringify({ items: Array.from({ length: 12 }, () => ({})) }));
    assert.ok((await run(base(root), envFor(s.port))).json.failed.some((x) => x.startsWith('FEED_TIMESTAMP_INVALID')));
  } finally { await s.close(); }
});

test('dossier validation: only posts/<valid-slug>.html within the size limit is ever uploaded', async () => {
  const s = await mockS3(); const root = repo({ dossiers: ['ok-1.html'] });
  try {
    fs.writeFileSync(path.join(root, 'posts', 'UPPER.html'), 'x');
    fs.writeFileSync(path.join(root, 'posts', 'note.txt'), 'x');
    fs.writeFileSync(path.join(root, 'posts', 'big-1.html'), Buffer.alloc(384 * 1024 + 1, 'a'));
    fs.writeFileSync(path.join(root, 'posts', 'empty-1.html'), '');
    fs.writeFileSync(path.join(root, 'posts', 'a'.repeat(121) + '.html'), 'x');
    fs.mkdirSync(path.join(root, 'posts', 'sub')); fs.writeFileSync(path.join(root, 'posts', 'sub', 'nested-1.html'), 'x');
    fs.writeFileSync(path.join(root, 'other.html'), 'x');
    git(root, 'add', '-A'); git(root, 'commit', '-q', '-m', 'mix');
    const r = await run(base(root, ['--since-commits', '5']), envFor(s.port));
    assert.deepEqual([...s.store.keys()].filter((k) => k.includes('/posts/')).sort(), [PREFIX + 'posts/ok-1.html']);
    assert.equal(r.code, 0);
  } finally { await s.close(); }
});

test('dry-run writes nothing (no PUT, no counter) but still plans the work', async () => {
  const s = await mockS3(); const root = repo();
  try {
    const r = await run(base(root, ['--dry-run']), envFor(s.port));
    assert.equal(r.code, 0); assert.equal(s.count('PUT'), 0); assert.ok(r.json.put.length >= 3);
    assert.equal(s.store.size, 0);
  } finally { await s.close(); }
});

// ---------- failure handling ----------
test('transient 503 is retried once and succeeds; a persistent failure is reported (exit 2) without aborting the other uploads', async () => {
  const flaky = await mockS3({ failures: { ['PUT ' + PREFIX + 'live-intel.json']: { times: 1, status: 503 } } }); const root = repo({ dossiers: [] });
  try { const r = await run(base(root), envFor(flaky.port)); assert.equal(r.code, 0); assert.ok(flaky.store.has(PREFIX + 'live-intel.json')); } finally { await flaky.close(); }
  const dead = await mockS3({ failures: { ['PUT ' + PREFIX + 'live-intel.json']: { times: 99, status: 503 } } });
  try {
    const r = await run(base(root), envFor(dead.port));
    assert.equal(r.code, 2); assert.ok(r.json.failed.some((x) => x.startsWith('live-intel.json')));
    assert.ok(dead.store.has(PREFIX + 'rss.xml'), 'other feeds still uploaded');
    assert.equal(dead.log.filter((e) => e.method === 'PUT' && e.key === PREFIX + 'live-intel.json').length, 2, 'exactly one retry');
  } finally { await dead.close(); }
});

test('an unreadable daily counter aborts BEFORE any write (never write blind); a failed LIST skips dossiers but keeps feeds', async () => {
  const bad = await mockS3({ failures: { ['GET ' + PREFIX + '_counters/2026-11-24.json']: { times: 9, status: 500 } } }); const root = repo();
  try { const r = await run(base(root), envFor(bad.port)); assert.equal(r.code, 1); assert.equal(bad.count('PUT'), 0); } finally { await bad.close(); }
  const nolist = await mockS3({ failures: { ['GET ']: { times: 9, status: 500 } } });
  try {
    const r = await run(base(root), envFor(nolist.port));
    assert.equal(r.code, 2); assert.ok(r.json.failed.some((x) => x.startsWith('LIST:')));
    assert.ok(nolist.store.has(PREFIX + 'live-intel.json') && !nolist.store.has(PREFIX + 'posts/cve-2026-1.html'));
  } finally { await nolist.close(); }
});

test('secrets never appear in output, and the signature of every request verified server-side', async () => {
  const s = await mockS3(); const root = repo();
  try {
    const r = await run(base(root), envFor(s.port));
    assert.ok(!(r.out + r.err).includes(SECRET)); assert.ok(!(r.out + r.err).includes(ACCESS));
    assert.ok(s.log.length > 0 && s.secretLog.every((a) => a.startsWith('AWS4-HMAC-SHA256 ')));
    assert.ok(!s.secretLog.some((a) => a.includes(SECRET)), 'secret is only ever used to derive a signature');
    const wrong = await run(base(root), envFor(s.port, { R2_SECRET_ACCESS_KEY: 'a-different-secret' }));
    assert.notEqual(wrong.code, 0, 'a wrong secret must be rejected by the verifying server');
  } finally { await s.close(); }
});

// ---------- gaps found by mutation testing ----------
test('a NON-5xx, non-404 counter read (403/400) also aborts before any write: never write blind', async () => {
  const root = repo();
  for (const status of [403, 400, 401, 429]) {
    const s = await mockS3({ failures: { ['GET ' + PREFIX + '_counters/2026-11-24.json']: { times: 9, status } } });
    try {
      const r = await run(base(root), envFor(s.port));
      assert.equal(r.code, 1, 'status ' + status); assert.equal(s.count('PUT'), 0, 'status ' + status + ' must not lead to a write');
      assert.match(r.err, /COUNTER_READ_FAILED/);
    } finally { await s.close(); }
  }
});

test('signer canonicalisation: RFC 3986 path/query encoding, sorted query, header normalisation', () => {
  const { canonicalUri, canonicalQuery, uriEncode } = require('../scripts/lib/r2-sigv4.cjs');
  assert.equal(canonicalUri('/bucket/a b/c+d!*\'().html'), '/bucket/a%20b/c%2Bd%21%2A%27%28%29.html');
  assert.equal(canonicalUri('/bucket/runtime/v1/posts/cve-2026-1.html'), '/bucket/runtime/v1/posts/cve-2026-1.html', 'production keys are unchanged');
  assert.equal(canonicalUri('/b/%2F'), '/b/%252F', 'a literal percent is encoded, never double-decoded');
  assert.equal(canonicalQuery({ prefix: 'runtime/v1/posts/', 'list-type': '2', 'max-keys': '1000' }), 'list-type=2&max-keys=1000&prefix=runtime%2Fv1%2Fposts%2F');
  assert.equal(canonicalQuery({}), ''); assert.equal(canonicalQuery(undefined), '');
  assert.equal(uriEncode('~-._'), '~-._', 'unreserved characters are never encoded');
  // header values are trimmed and inner whitespace collapsed before signing
  const a = sign({ method: 'PUT', host: 'h', path: '/b/k', headers: { 'X-Amz-Meta-A': '  a   b ' }, payloadHash: sha256Hex(''), accessKeyId: 'K', secretAccessKey: 'S', date: new Date('2026-11-24T00:00:00Z') });
  const b = sign({ method: 'PUT', host: 'h', path: '/b/k', headers: { 'x-amz-meta-a': 'a b' }, payloadHash: sha256Hex(''), accessKeyId: 'K', secretAccessKey: 'S', date: new Date('2026-11-24T00:00:00Z') });
  assert.equal(a.signature, b.signature);
});
