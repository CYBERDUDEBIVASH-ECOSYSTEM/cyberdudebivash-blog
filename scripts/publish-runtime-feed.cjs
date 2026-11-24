#!/usr/bin/env node
'use strict';
/**
 * SOC runtime feed publisher ("Option A", publisher side).
 *
 * Copies the three public feeds and recently added dossiers from the checked-out
 * repository to a DEDICATED R2 bucket (runtime/v1/ prefix) that the Worker reads
 * (workers/lib/runtime-feed.js). Git remains the system of record; R2 is a
 * derived serving store. It never writes to git and never touches any other
 * bucket, and it holds no credentials beyond one bucket-scoped R2 token.
 *
 * COST CONTROLS (September's overage was 3M R2 Class A operations):
 *  - dedupe: unchanged feeds (sha256) and dossiers (MD5 vs ETag from ONE list) are skipped;
 *  - monotonic: a feed is never overwritten by an older one (safe under reordering);
 *  - per-run cap (--max-puts) and a persisted DAILY cap (--daily-cap) of Class A
 *    operations; feeds are prioritised, dossiers are truncated newest-first;
 *  - at most one retry per request, and every attempt is counted against the cap.
 *
 * Exit codes: 0 ok (including nothing to do) | 1 config/validation error |
 *             2 partial failure | 3 daily cap reached.
 * Output: one JSON summary line; secrets are never printed.
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
const https = require('node:https');
const cp = require('node:child_process');
const os = require('node:os');
const { sign, sha256Hex, canonicalUri, canonicalQuery } = require('./lib/r2-sigv4.cjs');

const PREFIX = 'runtime/v1/';
const FEED_MAX_BYTES = 8 * 1024 * 1024;
const DOSSIER_MAX_BYTES = 384 * 1024;
const FUTURE_SKEW_MS = 5 * 60 * 1000;
const SLUG = /^posts\/([a-z0-9][a-z0-9-]{0,119}\.html)$/;
const toIso = (v) => { const t = Date.parse(v); return Number.isFinite(t) ? new Date(t).toISOString() : null; };

const FEEDS = Object.freeze([
  { rel: 'live-intel.json', key: PREFIX + 'live-intel.json', type: 'application/json; charset=utf-8',
    stamp: (d) => (d && d.metadata && (d.metadata.lastPipelineRun || d.metadata.generated)) || (d && d.generatedAt) },
  { rel: 'api/intel/live.json', key: PREFIX + 'api/intel/live.json', type: 'application/json; charset=utf-8',
    stamp: (d) => (d && (d.generated || d.lastReportGeneratedAt)) },
  { rel: 'rss.xml', key: PREFIX + 'rss.xml', type: 'application/rss+xml; charset=utf-8', xml: true },
]);

/**
 * The bytes the public site is certified to serve for a source file: exactly what the
 * Cloudflare build writes to dist-public (CVSS corrections on feeds, RSS origin rewrite,
 * HTML claim/structure/SEO transforms). Single source of truth: this calls the build's own
 * copyFileForPublicBuild, it never re-implements it. Uploading RAW source instead would
 * serve uncorrected, unvalidated content that no release gate certified.
 * Fail-closed: any exception means the file is not uploaded.
 */
function canonicalPublicBytes(root, rel) {
  const build = require('./build-cloudflare-assets.js');
  // The build derives repo-relative paths from its own ROOT; a different root would silently
  // select the wrong transforms, so refuse instead of guessing.
  if (path.resolve(root) !== path.resolve(build.ROOT)) throw new Error('PUBLIC_BUILD_ROOT_MISMATCH');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'rtfeed-'));
  try {
    const dest = path.join(tmp, path.basename(rel));
    build.copyFileForPublicBuild(path.join(root, rel), dest);
    return fs.readFileSync(dest);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}

/** Read + validate one feed file. Returns {bytes, sha256, generatedAt} or throws Error(code). */
function loadFeed(root, feed, nowMs, publicBytes = canonicalPublicBytes) {
  let bytes;
  try { bytes = publicBytes(root, feed.rel); } catch (_) { throw new Error('FEED_TRANSFORM_FAILED:' + feed.rel); }
  if (!Buffer.isBuffer(bytes)) throw new Error('FEED_TRANSFORM_FAILED:' + feed.rel);
  if (!bytes.length || bytes.length > FEED_MAX_BYTES) throw new Error('FEED_SIZE_INVALID:' + feed.rel);
  let stamp;
  if (feed.xml) {
    const text = bytes.toString('utf8');
    if (!/<rss[\s>]/.test(text) || !/<\/rss>\s*$/.test(text)) throw new Error('RSS_SHAPE_INVALID');
    const m = /<lastBuildDate>([^<]+)<\/lastBuildDate>/.exec(text);
    stamp = m && m[1];
  } else {
    let data;
    try { data = JSON.parse(bytes.toString('utf8')); } catch (_) { throw new Error('FEED_JSON_INVALID:' + feed.rel); }
    if (!data || !Array.isArray(data.items) || data.items.length < 10) throw new Error('FEED_ITEMS_INVALID:' + feed.rel);
    stamp = feed.stamp(data);
  }
  const generatedAt = typeof stamp === 'string' ? toIso(stamp) : null;
  if (!generatedAt) throw new Error('FEED_TIMESTAMP_INVALID:' + feed.rel);
  if (Date.parse(generatedAt) > nowMs + FUTURE_SKEW_MS) throw new Error('FEED_TIMESTAMP_FUTURE:' + feed.rel);
  return { bytes, sha256: sha256Hex(bytes), generatedAt };
}

/** Dossiers added/modified in the last N commits (newest first), validated. */
function recentDossiers(root, commits, publicBytes = canonicalPublicBytes, onSkip = () => {}) {
  let out = '';
  try {
    out = cp.execFileSync('git', ['log', '-n', String(commits), '--name-only', '--diff-filter=AM', '--format=', '--', 'posts'],
      { cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] });
  } catch (_) { return []; }
  const seen = new Set(); const list = [];
  for (const line of out.split('\n')) {
    const rel = line.trim();
    const m = SLUG.exec(rel);
    if (!m || seen.has(rel)) continue;
    seen.add(rel);
    // A file removed since the commit that added it is simply gone, not a failure.
    if (!fs.existsSync(path.join(root, rel))) continue;
    let bytes;
    try { bytes = publicBytes(root, rel); } catch (_) { onSkip('dossier_transform_failed', rel); continue; }
    if (!Buffer.isBuffer(bytes)) { onSkip('dossier_transform_failed', rel); continue; }
    if (!bytes.length || bytes.length > DOSSIER_MAX_BYTES) continue;
    list.push({ rel, key: PREFIX + rel, bytes, sha256: sha256Hex(bytes), md5: crypto.createHash('md5').update(bytes).digest('hex') });
  }
  return list;
}

function makeClient(env, state) {
  const bucket = env.R2_BUCKET;
  const base = new URL(env.R2_ENDPOINT || ('https://' + env.R2_ACCOUNT_ID + '.r2.cloudflarestorage.com'));
  const lib = base.protocol === 'http:' ? http : https;
  async function once(method, key, query, headers, body) {
    const reqPath = '/' + bucket + (key ? '/' + key : '');
    const payload = body || Buffer.alloc(0);
    const signed = sign({
      method, host: base.host, path: reqPath, query, headers, payloadHash: sha256Hex(payload),
      accessKeyId: env.R2_ACCESS_KEY_ID, secretAccessKey: env.R2_SECRET_ACCESS_KEY, region: 'auto', service: 's3',
      date: new Date(state.clockMs()),
    });
    // The wire path/query MUST be byte-identical to what was signed: reuse the signer's encoders.
    const qs = canonicalQuery(query);
    return new Promise((resolve, reject) => {
      const req = lib.request({
        method, hostname: base.hostname, port: base.port || undefined, timeout: 20000,
        path: canonicalUri(reqPath) + (qs ? '?' + qs : ''),
        headers: { ...signed.headers, 'content-length': payload.length },
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      });
      req.on('timeout', () => req.destroy(new Error('TIMEOUT')));
      req.on('error', reject);
      req.end(payload);
    });
  }
  /** One retry on transport error / 5xx; every ATTEMPT counts as a Class A/B operation. */
  async function call(method, key, query, headers, body, classA) {
    let last;
    for (let attempt = 0; attempt < 2; attempt++) {
      state.ops += classA ? 1 : 0; state.reads += classA ? 0 : 1;
      try {
        const res = await once(method, key, query, headers, body);
        if (res.status < 500) return res;
        last = new Error('HTTP_' + res.status);
      } catch (e) { last = e; }
    }
    throw last;
  }
  return { call };
}

async function main(argv, env, deps = {}) {
  const args = { root: process.cwd(), dryRun: false, check: false, maxPuts: 400, dailyCap: 3000, commits: 12, now: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--dry-run') args.dryRun = true;
    else if (a === '--check') args.check = true;
    else if (['--root', '--max-puts', '--daily-cap', '--since-commits', '--now'].includes(a)) {
      const v = argv[++i];
      if (v === undefined) return fail(1, 'MISSING_VALUE ' + a);
      if (a === '--root') args.root = path.resolve(v);
      else if (a === '--now') args.now = v;
      else {
        const n = Number(v);
        if (!Number.isInteger(n) || n < 1 || n > 100000) return fail(1, 'INVALID_NUMBER ' + a);
        if (a === '--max-puts') args.maxPuts = n; else if (a === '--daily-cap') args.dailyCap = n; else args.commits = n;
      }
    } else return fail(1, 'UNKNOWN_ARGUMENT ' + a);
  }
  for (const k of ['R2_BUCKET', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY']) if (!env[k]) return fail(1, 'MISSING_ENV ' + k);
  if (!env.R2_ENDPOINT && !/^[a-f0-9]{32}$/i.test(env.R2_ACCOUNT_ID || '')) return fail(1, 'MISSING_OR_INVALID_ENV R2_ACCOUNT_ID');
  if (!/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(env.R2_BUCKET)) return fail(1, 'INVALID_BUCKET_NAME');
  if (/premium/i.test(env.R2_BUCKET)) return fail(1, 'REFUSING_PREMIUM_BUCKET'); // never the paid-artifact bucket

  const started = Date.now();
  const baseMs = args.now ? Date.parse(args.now) : started;
  const state = { ops: 0, reads: 0, clockMs: () => baseMs + (Date.now() - started) };
  const client = (deps.makeClient || makeClient)(env, state);
  const nowMs = baseMs;
  const publicBytes = deps.publicBytes || canonicalPublicBytes; // tests may inject; production is always canonical

  if (args.check) {
    try {
      const r = await client.call('HEAD', '', {}, {}, null, false);
      console.log(JSON.stringify({ event: 'runtime-feed-check', status: r.status === 200 ? 'R2_AUTH_OK' : 'R2_AUTH_FAILED', http: r.status }));
      return { code: r.status === 200 ? 0 : 1 };
    } catch (e) { return fail(1, 'R2_UNREACHABLE ' + e.message); }
  }

  const summary = { event: 'runtime-feed-publish', dryRun: args.dryRun, put: [], skipped: {}, failed: [], capped: false };
  const skip = (reason) => { summary.skipped[reason] = (summary.skipped[reason] || 0) + 1; };

  // 1. Local, validated inputs. Any invalid feed is skipped, never uploaded.
  const feeds = [];
  for (const feed of FEEDS) {
    try { feeds.push({ feed, ...loadFeed(args.root, feed, nowMs, publicBytes) }); }
    catch (e) { summary.failed.push(e.message); }
  }
  // A dossier the public build would reject is never uploaded, and it is reported (exit 2), not hidden.
  const dossiers = recentDossiers(args.root, args.commits, publicBytes, (reason, rel) => {
    skip(reason);
    if (rel) summary.failed.push('DOSSIER_TRANSFORM_FAILED:' + rel);
  });

  // 2. Daily cap (persisted). A read error other than 404 aborts: never write blind.
  const day = new Date(nowMs).toISOString().slice(0, 10);
  const counterKey = PREFIX + '_counters/' + day + '.json';
  let used = 0;
  try {
    const r = await client.call('GET', counterKey, {}, {}, null, false);
    if (r.status === 200) { const c = JSON.parse(r.body.toString('utf8')); used = Number.isInteger(c.ops) && c.ops >= 0 ? c.ops : args.dailyCap; }
    else if (r.status !== 404) return fail(1, 'COUNTER_READ_FAILED http=' + r.status);
  } catch (e) { return fail(1, 'COUNTER_READ_FAILED ' + e.message); }
  // EXACT accounting: budget is derived from the real operation count (every attempt, retries
  // included), never from a per-success decrement, so retries cannot overshoot the daily cap.
  const reserve = 3; // the final counter PUT (+ one retry) must always fit
  const left = () => args.dailyCap - used - state.ops - reserve;
  if (left() < feeds.length) { console.log(JSON.stringify({ ...summary, capped: true, dailyOpsUsed: used })); return { code: 3 }; }

  const put = async (key, bytes, type, meta) => {
    const r = await client.call('PUT', key, {}, { 'content-type': type, ...meta }, bytes, true);
    if (r.status !== 200) throw new Error('PUT_HTTP_' + r.status);
  };
  const head = async (key) => {
    const r = await client.call('HEAD', key, {}, {}, null, false);
    return r.status === 200 ? r.headers : null;
  };

  // 3. Feeds first (highest value): dedupe by sha256, never move backwards in time.
  for (const f of feeds) {
    try {
      const existing = await head(f.feed.key);
      if (existing && existing['x-amz-meta-sha256'] === f.sha256) { skip('feed_unchanged'); continue; }
      const theirs = existing && existing['x-amz-meta-generated-at'];
      if (theirs && Date.parse(theirs) > Date.parse(f.generatedAt)) { skip('feed_older_than_remote'); continue; }
      if (args.dryRun) { summary.put.push(f.feed.key); continue; }
      if (summary.put.length >= args.maxPuts || left() < 2) { summary.capped = true; continue; } // room for the PUT and one retry
      await put(f.feed.key, f.bytes, f.feed.type, { 'x-amz-meta-sha256': f.sha256, 'x-amz-meta-generated-at': f.generatedAt });
      summary.put.push(f.feed.key);
    } catch (e) { summary.failed.push(f.feed.rel + ':' + e.message); }
  }

  // 4. Dossiers: ONE list call (Class A), compare MD5 with ETag, upload only new/changed, newest first.
  if (dossiers.length) {
    const etags = new Map();
    try {
      let token = null;
      do {
        const q = { 'list-type': '2', prefix: PREFIX + 'posts/', 'max-keys': '1000' };
        if (token) q['continuation-token'] = token;
        const r = await client.call('GET', '', q, {}, null, true);
        if (r.status !== 200) throw new Error('LIST_HTTP_' + r.status);
        const xml = r.body.toString('utf8');
        // One <Contents> block per object; R2 returns the ETag as &quot;md5&quot; (plain MD5 for single-part PUTs).
        for (const block of xml.split('<Contents>').slice(1)) {
          const k = /<Key>([^<]+)<\/Key>/.exec(block);
          const e = /<ETag>([^<]+)<\/ETag>/.exec(block);
          if (k && e) etags.set(k[1], e[1].replace(/&quot;|"/g, '').toLowerCase());
        }
        const next = /<NextContinuationToken>([^<]+)<\/NextContinuationToken>/.exec(xml);
        token = /<IsTruncated>true<\/IsTruncated>/.test(xml) && next ? next[1] : null;
      } while (token);
    } catch (e) { summary.failed.push('LIST:' + e.message); }
    if (!summary.failed.some((x) => x.startsWith('LIST:'))) {
      for (const d of dossiers) {
        if (etags.get(d.key) === d.md5) { skip('dossier_unchanged'); continue; }
        if (args.dryRun) { summary.put.push(d.key); continue; }
        if (summary.put.length >= args.maxPuts || left() < 2) { summary.capped = true; skip('dossier_capped'); continue; }
        try {
          await put(d.key, d.bytes, 'text/html; charset=utf-8', { 'x-amz-meta-sha256': d.sha256 });
          summary.put.push(d.key);
        } catch (e) { summary.failed.push(d.rel + ':' + e.message); }
      }
    }
  }

  // 5. Persist the daily counter (counts every attempt made this run, including itself).
  if (!args.dryRun) {
    const ops = used + state.ops + 1;
    try { await put(counterKey, Buffer.from(JSON.stringify({ day, ops, updatedAt: new Date(state.clockMs()).toISOString() })), 'application/json', {}); }
    catch (e) { summary.failed.push('COUNTER_WRITE:' + e.message); }
    summary.dailyOpsUsed = ops;
  }
  summary.classAOps = state.ops; summary.classBOps = state.reads; summary.putCount = summary.put.length;
  console.log(JSON.stringify(summary));
  return { code: summary.failed.length ? 2 : 0, summary };
}

function fail(code, message) { console.error('ERROR: ' + message); return { code }; }

if (require.main === module) {
  main(process.argv.slice(2), process.env).then((r) => { process.exitCode = r.code; })
    .catch((e) => { console.error('ERROR: ' + (e && e.message)); process.exitCode = 1; });
}
module.exports = { main, loadFeed, recentDossiers, canonicalPublicBytes, FEEDS, PREFIX };
