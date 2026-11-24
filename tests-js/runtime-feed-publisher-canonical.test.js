'use strict';
// Option A publisher: it must upload exactly what the public build would serve, never raw source.
//
// Why this exists: the Cloudflare build (scripts/build-cloudflare-assets.js copyFileForPublicBuild)
// applies certified transforms to every public file: approved CVSS corrections on the JSON feeds,
// the RSS origin rewrite, and the HTML claim/structure/SEO transforms. Uploading raw source to the
// runtime bucket would serve content that no release gate certified, and it would make the public
// feed differ from the built asset the post-deploy gates compare against.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const cp = require('node:child_process');
const build = require('../scripts/build-cloudflare-assets.js');
const { main, canonicalPublicBytes, PREFIX } = require('../scripts/publish-runtime-feed.cjs');

const ROOT = path.resolve(__dirname, '..');
const NOW = '2026-11-24T16:00:00.000Z';
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const md5 = (b) => crypto.createHash('md5').update(b).digest('hex');
const iso = (ms) => new Date(ms).toISOString();

// ---------- the real repository files ----------
test('the three feeds are uploaded as the public build would serve them (independent oracle)', () => {
  const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
  assert.equal(canonicalPublicBytes(ROOT, 'live-intel.json').toString('utf8'), build.correctPublicIntelJson(read('live-intel.json')));
  assert.equal(canonicalPublicBytes(ROOT, 'api/intel/live.json').toString('utf8'), build.correctPublicIntelJson(read('api/intel/live.json')));
  assert.equal(canonicalPublicBytes(ROOT, 'rss.xml').toString('utf8'), build.rewritePublicRssMetadata(read('rss.xml')));
});

test('raw source is NOT what the public serves: the canonical bytes differ for the API feed, the RSS feed and every dossier checked', (t) => {
  const rawApi = fs.readFileSync(path.join(ROOT, 'api/intel/live.json'));
  const rawRss = fs.readFileSync(path.join(ROOT, 'rss.xml'));
  // Data-dependent: the CVSS correction only changes bytes when a served score needs correcting.
  if (build.correctPublicIntelJson(rawApi.toString('utf8')) === rawApi.toString('utf8')) t.diagnostic('api feed currently needs no CVSS correction');
  else assert.notDeepEqual(canonicalPublicBytes(ROOT, 'api/intel/live.json'), rawApi);
  if (build.rewritePublicRssMetadata(rawRss.toString('utf8')) === rawRss.toString('utf8')) t.diagnostic('rss currently needs no origin rewrite');
  else assert.notDeepEqual(canonicalPublicBytes(ROOT, 'rss.xml'), rawRss);
  const posts = fs.readdirSync(path.join(ROOT, 'posts')).filter((f) => /^[a-z0-9][a-z0-9-]{0,119}\.html$/.test(f)).sort().slice(-3);
  assert.ok(posts.length > 0, 'the repository has dossiers to check');
  for (const f of posts) {
    const rel = 'posts/' + f;
    assert.notDeepEqual(canonicalPublicBytes(ROOT, rel), fs.readFileSync(path.join(ROOT, rel)), rel + ' must carry the public-build transforms');
  }
});

test('COST CONTROL: the canonical bytes are deterministic, so unchanged files never trigger a re-upload', () => {
  const posts = fs.readdirSync(path.join(ROOT, 'posts')).filter((f) => /^[a-z0-9][a-z0-9-]{0,119}\.html$/.test(f)).sort().slice(-3).map((f) => 'posts/' + f);
  for (const rel of ['live-intel.json', 'api/intel/live.json', 'rss.xml', ...posts]) {
    assert.equal(sha(canonicalPublicBytes(ROOT, rel)), sha(canonicalPublicBytes(ROOT, rel)), rel);
  }
});

test('fail closed: a different root is refused (the build would pick the wrong transforms), and nothing is left in the temp dir', () => {
  const other = fs.mkdtempSync(path.join(os.tmpdir(), 'rtcanon-root-'));
  fs.writeFileSync(path.join(other, 'live-intel.json'), '{}');
  assert.throws(() => canonicalPublicBytes(other, 'live-intel.json'), /PUBLIC_BUILD_ROOT_MISMATCH/);
  const before = fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('rtfeed-')).length;
  canonicalPublicBytes(ROOT, 'live-intel.json');
  assert.equal(fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('rtfeed-')).length, before, 'temp directory must be removed');
});

// ---------- wiring in main() with an in-memory R2 ----------
function fakeR2() {
  const store = new Map(); const puts = [];
  const makeClient = () => ({
    call: async (method, key, query, headers, body) => {
      if (method === 'PUT') { store.set(key, { body, headers }); puts.push(key); return { status: 200, headers: {}, body: Buffer.alloc(0) }; }
      if (method === 'GET' && !key && query['list-type'] === '2') {
        const xml = '<ListBucketResult>' + [...store.keys()].filter((k) => k.startsWith(query.prefix || ''))
          .map((k) => '<Contents><Key>' + k + '</Key><ETag>&quot;' + md5(store.get(k).body) + '&quot;</ETag></Contents>').join('') + '<IsTruncated>false</IsTruncated></ListBucketResult>';
        return { status: 200, headers: {}, body: Buffer.from(xml) };
      }
      const o = store.get(key);
      if (!o) return { status: 404, headers: {}, body: Buffer.alloc(0) };
      return { status: 200, headers: { 'x-amz-meta-sha256': o.headers['x-amz-meta-sha256'], 'x-amz-meta-generated-at': o.headers['x-amz-meta-generated-at'] }, body: method === 'GET' ? o.body : Buffer.alloc(0) };
    },
  });
  return { store, puts, makeClient };
}
const ENV = { R2_ENDPOINT: 'http://127.0.0.1:1', R2_BUCKET: 'soc-runtime-feed', R2_ACCESS_KEY_ID: 'AKIATEST', R2_SECRET_ACCESS_KEY: 'secret-never-printed' };
function git(root, ...a) { return cp.execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', ...a], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }); }
function fixture() {
  const stamp = Date.parse(NOW) - 120000;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rtcanon-'));
  git(root, 'init', '-q', '-b', 'main');
  fs.mkdirSync(path.join(root, 'api/intel'), { recursive: true }); fs.mkdirSync(path.join(root, 'posts'));
  const items = Array.from({ length: 12 }, (_, i) => ({ id: 'i' + i }));
  fs.writeFileSync(path.join(root, 'live-intel.json'), JSON.stringify({ generatedAt: iso(stamp), metadata: { lastPipelineRun: iso(stamp) }, totalPublished: 12, items }));
  fs.writeFileSync(path.join(root, 'api/intel/live.json'), JSON.stringify({ generated: iso(stamp), total_published: 12, items }));
  fs.writeFileSync(path.join(root, 'rss.xml'), '<?xml version="1.0"?><rss version="2.0"><channel><lastBuildDate>' + new Date(stamp).toUTCString() + '</lastBuildDate></channel></rss>');
  git(root, 'add', '-A'); git(root, 'commit', '-q', '-m', 'base');
  for (const d of ['ok-1.html', 'bad-2.html', 'ok-3.html']) { fs.writeFileSync(path.join(root, 'posts', d), '<!doctype html><title>' + d + '</title>'); git(root, 'add', '-A'); git(root, 'commit', '-q', '-m', d); }
  return root;
}
async function run(root, deps) {
  const out = []; const l = console.log; const e = console.error;
  console.log = (...a) => out.push(a.join(' ')); console.error = () => {};
  try { const r = await main(['--root', root, '--now', NOW], ENV, deps); return { code: r.code, json: JSON.parse(out[out.length - 1]) }; }
  finally { console.log = l; console.error = e; }
}
// A transform that visibly changes every file (so raw and served bytes can never be confused).
const MARK = (root, rel) => {
  const raw = fs.readFileSync(path.join(root, rel), 'utf8');
  if (rel.endsWith('.json')) return Buffer.from(raw.replace(/"i(\d+)"/g, '"served-i$1"'));
  if (rel.endsWith('.xml')) return Buffer.from(raw.replace('<channel>', '<channel><!--served-->'));
  return Buffer.from(raw + '<!--served-->');
};

test('what is uploaded, and the sha256 metadata the gates will later verify, are the SERVED bytes, never the raw file', async () => {
  const root = fixture(); const r2 = fakeR2();
  const res = await run(root, { makeClient: r2.makeClient, publicBytes: MARK });
  assert.equal(res.code, 0, JSON.stringify(res.json)); assert.deepEqual(res.json.failed, []);
  for (const rel of ['live-intel.json', 'api/intel/live.json', 'rss.xml']) {
    const o = r2.store.get(PREFIX + rel);
    assert.ok(o, rel + ' uploaded');
    assert.notDeepEqual(o.body, fs.readFileSync(path.join(root, rel)), rel + ' must not be the raw file');
    assert.deepEqual(o.body, MARK(root, rel));
    assert.equal(o.headers['x-amz-meta-sha256'], sha(o.body), rel + ' metadata sha256 must describe the served bytes');
  }
  for (const d of ['ok-1.html', 'bad-2.html', 'ok-3.html']) assert.deepEqual(r2.store.get(PREFIX + 'posts/' + d).body, MARK(root, 'posts/' + d));
});

test('the PRODUCTION DEFAULT is the canonical transform, not raw: with no injected transform a foreign root uploads nothing and is reported', async () => {
  const root = fixture(); const r2 = fakeR2();
  const res = await run(root, { makeClient: r2.makeClient }); // no publicBytes injected
  assert.equal(res.code, 2);
  assert.equal(r2.puts.filter((k) => !k.includes('_counters')).length, 0, 'nothing may be uploaded when the canonical transform cannot run');
  assert.ok(res.json.failed.some((x) => x.startsWith('FEED_TRANSFORM_FAILED:live-intel.json')));
  assert.ok(res.json.failed.some((x) => x.startsWith('DOSSIER_TRANSFORM_FAILED:posts/ok-1.html')));
});

test('a feed whose transform fails is skipped and reported; the other feeds still publish', async () => {
  const root = fixture(); const r2 = fakeR2();
  const res = await run(root, { makeClient: r2.makeClient, publicBytes: (rt, rel) => { if (rel === 'api/intel/live.json') throw new Error('boom'); return MARK(rt, rel); } });
  assert.equal(res.code, 2);
  assert.ok(res.json.failed.includes('FEED_TRANSFORM_FAILED:api/intel/live.json'));
  assert.equal(r2.store.has(PREFIX + 'api/intel/live.json'), false);
  assert.equal(r2.store.has(PREFIX + 'live-intel.json'), true);
  assert.equal(r2.store.has(PREFIX + 'rss.xml'), true);
});

test('a dossier the public build rejects is never uploaded and is reported (exit 2); other dossiers still publish', async () => {
  const root = fixture(); const r2 = fakeR2();
  const res = await run(root, { makeClient: r2.makeClient, publicBytes: (rt, rel) => { if (rel === 'posts/bad-2.html') throw new Error('claims'); return MARK(rt, rel); } });
  assert.equal(res.code, 2);
  assert.ok(res.json.failed.includes('DOSSIER_TRANSFORM_FAILED:posts/bad-2.html'));
  assert.equal(res.json.skipped.dossier_transform_failed, 1);
  assert.equal(r2.store.has(PREFIX + 'posts/bad-2.html'), false);
  assert.equal(r2.store.has(PREFIX + 'posts/ok-1.html'), true);
  assert.equal(r2.store.has(PREFIX + 'posts/ok-3.html'), true);
});

test('a transform that returns something other than a Buffer is treated as a failure, never uploaded', async () => {
  const root = fixture(); const r2 = fakeR2();
  const res = await run(root, { makeClient: r2.makeClient, publicBytes: (rt, rel) => (rel === 'rss.xml' || rel === 'posts/ok-1.html' ? 'a string' : MARK(rt, rel)) });
  assert.equal(res.code, 2);
  assert.ok(res.json.failed.includes('FEED_TRANSFORM_FAILED:rss.xml'));
  assert.ok(res.json.failed.includes('DOSSIER_TRANSFORM_FAILED:posts/ok-1.html'));
  assert.equal(r2.store.has(PREFIX + 'rss.xml'), false);
  assert.equal(r2.store.has(PREFIX + 'posts/ok-1.html'), false);
});

test('validation runs on the SERVED bytes: a transform that corrupts a feed is caught, not uploaded', async () => {
  const root = fixture(); const r2 = fakeR2();
  const res = await run(root, { makeClient: r2.makeClient, publicBytes: (rt, rel) => (rel === 'live-intel.json' ? Buffer.from('{not json') : MARK(rt, rel)) });
  assert.equal(res.code, 2);
  assert.ok(res.json.failed.some((x) => x.startsWith('FEED_JSON_INVALID:live-intel.json')));
  assert.equal(r2.store.has(PREFIX + 'live-intel.json'), false);
});

test('a dossier deleted after the commit that added it is skipped quietly (not a transform failure)', async () => {
  const root = fixture(); const r2 = fakeR2();
  fs.rmSync(path.join(root, 'posts', 'ok-1.html'));
  const res = await run(root, { makeClient: r2.makeClient, publicBytes: MARK });
  assert.equal(res.code, 0, JSON.stringify(res.json));
  assert.equal(res.json.skipped.dossier_transform_failed, undefined);
  assert.equal(r2.store.has(PREFIX + 'posts/ok-1.html'), false);
});
