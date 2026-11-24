'use strict';
// Option A PR-3: the release/monitor gates accept a BOUNDED propagation lag, but only for a
// response that proves it was served from the runtime R2 bucket. Everything else must be judged
// by the unchanged strict rules, so these tests pin both directions: what is newly allowed, and
// that every other path is exactly as strict as before.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  RUNTIME_PROPAGATION_GRACE_MINUTES, STAMP, verifyRuntimeProvenance, provenanceLabel,
} = require('../scripts/lib/runtime-feed-provenance.cjs');
const parity = require('../scripts/certify-soc-public-feed-parity.cjs');
const s2n = require('../scripts/certify-soc-s2n-api-release.cjs');
const { FEEDS } = require('../scripts/publish-runtime-feed.cjs');

const MIN = 60000;
const iso = (ms) => new Date(ms).toISOString();
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const JSON_HDR = { 'content-type': 'application/json' };

/** A Response that claims runtime provenance. `over` overrides or removes (null) any header. */
function runtimeResponse(obj, { generatedAt, over = {} } = {}) {
  const body = Buffer.from(typeof obj === 'string' ? obj : JSON.stringify(obj));
  const headers = { ...JSON_HDR, 'x-feed-source': 'runtime-r2', 'x-feed-sha256': sha(body), 'x-feed-generated-at': generatedAt, ...over };
  for (const k of Object.keys(headers)) if (headers[k] === null || headers[k] === undefined) delete headers[k];
  return new Response(body, { status: 200, headers });
}
const staticResponse = (obj) => new Response(JSON.stringify(obj), { status: 200, headers: JSON_HDR });

// ======================= the provenance helper =======================
const NOW = Date.parse('2026-11-24T17:10:00.000Z');
function liveDoc(stampMs, total = 8261) {
  return { generatedAt: iso(stampMs), metadata: { lastPipelineRun: iso(stampMs) }, totalPublished: total, items: Array.from({ length: 12 }, (_, i) => ({ id: 'i' + i })) };
}
function headersFor(doc, stampMs, over = {}) {
  const bytes = Buffer.from(JSON.stringify(doc));
  const h = new Headers({ 'x-feed-source': 'runtime-r2', 'x-feed-sha256': sha(bytes), 'x-feed-generated-at': iso(stampMs), ...over });
  return { bytes, headers: h };
}

test('provenance: accepted only when source, recomputed sha256, generated-at instant and age all hold', () => {
  const doc = liveDoc(NOW - 5 * MIN);
  const { bytes, headers } = headersFor(doc, NOW - 5 * MIN);
  const r = verifyRuntimeProvenance({ kind: 'live-intel', headers, bytes, data: doc, nowMs: NOW });
  assert.deepEqual(r, { claimed: true, ok: true, generatedMs: NOW - 5 * MIN });
  const api = { generated: iso(NOW - 5 * MIN), total_published: 8261, items: [{ id: 'a' }] };
  const h2 = headersFor(api, NOW - 5 * MIN);
  assert.equal(verifyRuntimeProvenance({ kind: 'api', headers: h2.headers, bytes: h2.bytes, data: api, nowMs: NOW }).ok, true);
  assert.equal(provenanceLabel(r), 'runtime-r2');
});

test('provenance: each failing condition individually is rejected with its own reason', () => {
  const doc = liveDoc(NOW - 5 * MIN);
  const ok = headersFor(doc, NOW - 5 * MIN);
  const run = (over, extra = {}) => {
    const h = headersFor(doc, NOW - 5 * MIN, over);
    return verifyRuntimeProvenance({ kind: 'live-intel', headers: h.headers, bytes: h.bytes, data: doc, nowMs: NOW, ...extra });
  };
  const cases = [
    ['no runtime header at all', () => verifyRuntimeProvenance({ kind: 'live-intel', headers: new Headers(), bytes: ok.bytes, data: doc, nowMs: NOW }), false, 'NO_RUNTIME_HEADER'],
    ['source is not runtime-r2', () => run({ 'x-feed-source': 'static' }), true, 'RUNTIME_SOURCE_UNKNOWN'],
    ['sha256 missing', () => verifyRuntimeProvenance({ kind: 'live-intel', headers: new Headers({ 'x-feed-source': 'runtime-r2', 'x-feed-generated-at': iso(NOW - 5 * MIN) }), bytes: ok.bytes, data: doc, nowMs: NOW }), true, 'RUNTIME_SHA256_INVALID'],
    ['sha256 upper-case', () => run({ 'x-feed-sha256': ok.headers.get('x-feed-sha256').toUpperCase() }), true, 'RUNTIME_SHA256_INVALID'],
    ['sha256 does not match the received body', () => run({ 'x-feed-sha256': sha('other body') }), true, 'RUNTIME_SHA256_MISMATCH'],
    ['generated-at missing', () => verifyRuntimeProvenance({ kind: 'live-intel', headers: new Headers({ 'x-feed-source': 'runtime-r2', 'x-feed-sha256': ok.headers.get('x-feed-sha256') }), bytes: ok.bytes, data: doc, nowMs: NOW }), true, 'RUNTIME_GENERATED_AT_MISSING'],
    ['generated-at is a different instant than the feed own timestamp', () => run({ 'x-feed-generated-at': iso(NOW - 4 * MIN) }), true, 'RUNTIME_GENERATED_AT_MISMATCH'],
    ['generated-at more than 5 min in the future', () => { const d = liveDoc(NOW + 6 * MIN); const h = headersFor(d, NOW + 6 * MIN); return verifyRuntimeProvenance({ kind: 'live-intel', headers: h.headers, bytes: h.bytes, data: d, nowMs: NOW }); }, true, 'RUNTIME_GENERATED_AT_FUTURE'],
    ['older than 180 minutes', () => { const d = liveDoc(NOW - 181 * MIN); const h = headersFor(d, NOW - 181 * MIN); return verifyRuntimeProvenance({ kind: 'live-intel', headers: h.headers, bytes: h.bytes, data: d, nowMs: NOW }); }, true, 'RUNTIME_GENERATED_AT_STALE'],
    ['empty body', () => verifyRuntimeProvenance({ kind: 'live-intel', headers: ok.headers, bytes: Buffer.alloc(0), data: doc, nowMs: NOW }), true, 'RUNTIME_BYTES_UNAVAILABLE'],
    ['unknown kind', () => run({}, { kind: 'rss' }), true, 'RUNTIME_KIND_UNKNOWN'],
  ];
  for (const [what, fn, claimed, reason] of cases) {
    const r = fn();
    assert.equal(r.ok, false, what); assert.equal(r.claimed, claimed, what); assert.equal(r.reason, reason, what);
  }
  // Boundaries: exactly 180 min is still accepted, exactly 5 min in the future is accepted.
  const edge = liveDoc(NOW - 180 * MIN); const e = headersFor(edge, NOW - 180 * MIN);
  assert.equal(verifyRuntimeProvenance({ kind: 'live-intel', headers: e.headers, bytes: e.bytes, data: edge, nowMs: NOW }).ok, true);
  const fut = liveDoc(NOW + 5 * MIN); const f = headersFor(fut, NOW + 5 * MIN);
  assert.equal(verifyRuntimeProvenance({ kind: 'live-intel', headers: f.headers, bytes: f.bytes, data: fut, nowMs: NOW }).ok, true);
  assert.equal(provenanceLabel({ claimed: true, ok: false, reason: 'X' }), 'runtime-r2-REJECTED:X');
  assert.equal(provenanceLabel(null), 'static');
});

test('the timestamp precedence the gates verify is pinned to the publisher own definition (cannot drift apart)', () => {
  const docs = {
    'live-intel': [
      { metadata: { lastPipelineRun: 'A', generated: 'B' }, generatedAt: 'C' },
      { metadata: { generated: 'B' }, generatedAt: 'C' },
      { generatedAt: 'C' }, { metadata: {} }, {}, null,
    ],
    api: [
      { generated: 'A', lastReportGeneratedAt: 'B' }, { lastReportGeneratedAt: 'B' }, {}, null,
    ],
  };
  const byRel = { 'live-intel': 'live-intel.json', api: 'api/intel/live.json' };
  for (const [kind, list] of Object.entries(docs)) {
    const feed = FEEDS.find((f) => f.rel === byRel[kind]);
    for (const d of list) assert.equal(STAMP[kind](d) || undefined, feed.stamp(d) || undefined, kind + ' ' + JSON.stringify(d));
  }
});

// ======================= parity gate (certify-soc-public-feed-parity) =======================
const SRC_STAMP = NOW - 5 * MIN;
const source = liveDoc(SRC_STAMP, 8261);
const byUrl = (map) => async (url) => map[url]();
const both = (make) => byUrl({ [parity.TARGETS.soc]: make, [parity.TARGETS.blog]: make });
async function runParity(make, extra = {}) {
  return parity.check({ expected: source, nowMs: NOW, fetchImpl: both(make), ...extra });
}
const lagging = (lagMs, total = 8260) => () => { const d = liveDoc(SRC_STAMP - lagMs, total); return runtimeResponse(d, { generatedAt: iso(SRC_STAMP - lagMs) }); };

test('parity: a PROVEN runtime response up to 10 minutes behind the source (and a lower corpus) passes; the same bytes without proof still fail', async () => {
  const ok = await runParity(lagging(7 * MIN));
  assert.equal(ok.status, 'PASS', JSON.stringify(ok.results));
  assert.deepEqual(ok.results.map((r) => r.provenance), ['runtime-r2', 'runtime-r2']);
  const strict = await runParity(() => staticResponse(liveDoc(SRC_STAMP - 7 * MIN, 8260)));
  assert.equal(strict.status, 'FAIL');
  assert.equal(strict.results[0].reason, 'PUBLIC_SOURCE_DEPLOYMENT_DRIFT');
  assert.equal(strict.results[0].provenance, 'static');
});

test('parity: the grace boundary is exactly 10 minutes (10:00 passes, 10:01 fails)', async () => {
  assert.equal(RUNTIME_PROPAGATION_GRACE_MINUTES, 10);
  assert.equal((await runParity(lagging(10 * MIN))).status, 'PASS');
  const over = await runParity(lagging(10 * MIN + 1000));
  assert.equal(over.status, 'FAIL'); assert.equal(over.results[0].reason, 'PUBLIC_SOURCE_DEPLOYMENT_DRIFT');
});

test('parity: spoofed or inconsistent provenance gets NO grace (each condition individually) and is labelled REJECTED', async () => {
  const lag = 7 * MIN; const stamp = SRC_STAMP - lag;
  const doc = () => liveDoc(stamp, 8260);
  const variants = {
    'wrong sha256': () => runtimeResponse(doc(), { generatedAt: iso(stamp), over: { 'x-feed-sha256': sha('x') } }),
    'generated-at is another instant': () => runtimeResponse(doc(), { generatedAt: iso(stamp + MIN) }),
    'generated-at missing': () => runtimeResponse(doc(), { generatedAt: iso(stamp), over: { 'x-feed-generated-at': null } }),
    'source header wrong': () => runtimeResponse(doc(), { generatedAt: iso(stamp), over: { 'x-feed-source': 'cache' } }),
    'sha256 header missing': () => runtimeResponse(doc(), { generatedAt: iso(stamp), over: { 'x-feed-sha256': null } }),
  };
  for (const [what, make] of Object.entries(variants)) {
    const out = await runParity(make);
    assert.equal(out.status, 'FAIL', what);
    assert.equal(out.results[0].reason, 'PUBLIC_SOURCE_DEPLOYMENT_DRIFT', what);
    if (what !== 'source header wrong') assert.match(out.results[0].provenance, /^runtime-r2-REJECTED:/, what);
  }
});

test('parity: the grace is one-directional and never hides a corpus problem at the same instant or ahead', async () => {
  // Older feed claiming a LARGER corpus is contradictory.
  const inconsistent = await runParity(lagging(3 * MIN, 8262));
  assert.equal(inconsistent.status, 'FAIL'); assert.equal(inconsistent.results[0].reason, 'PUBLIC_RUNTIME_CORPUS_INCONSISTENT');
  // Same instant as the source but fewer reports: strict, even with provenance.
  const same = await runParity(lagging(0, 8260));
  assert.equal(same.status, 'FAIL'); assert.equal(same.results[0].reason, 'PUBLIC_CORPUS_BEHIND_SOURCE');
  // Ahead of the source but fewer reports: strict.
  const ahead = await runParity(lagging(-1 * MIN, 8260));
  assert.equal(ahead.status, 'FAIL'); assert.equal(ahead.results[0].reason, 'PUBLIC_CORPUS_BEHIND_SOURCE');
  // A provenanced response that is older than 180 minutes is stale, whatever it claims.
  const old = await runParity(() => { const d = liveDoc(NOW - 200 * MIN, 8000); return runtimeResponse(d, { generatedAt: iso(NOW - 200 * MIN) }); });
  assert.equal(old.status, 'FAIL'); assert.equal(old.results[0].reason, 'PUBLIC_PIPELINE_STALE');
});

test('parity --release-asset: identical bytes pass; different bytes pass ONLY if proven runtime output strictly newer than the build', async () => {
  const buildDoc = liveDoc(SRC_STAMP, 8261); const buildBytes = Buffer.from(JSON.stringify(buildDoc));
  const run = (make) => parity.check({ expected: buildDoc, expectedBytes: buildBytes, nowMs: NOW, fetchImpl: both(make) });
  assert.equal((await run(() => new Response(buildBytes, { status: 200, headers: JSON_HDR }))).status, 'PASS');
  // Newer runtime object (a later publisher run), other bytes, valid proof.
  const newer = await run(() => runtimeResponse(liveDoc(SRC_STAMP + 2 * MIN, 8262), { generatedAt: iso(SRC_STAMP + 2 * MIN) }));
  assert.equal(newer.status, 'PASS', JSON.stringify(newer.results));
  assert.equal(newer.results[0].reason, 'PUBLIC_RUNTIME_FEED_NEWER_THAN_BUILD_VERIFIED');
  // Same pipeline instant, different bytes: drift, even with valid proof.
  const altered = { ...buildDoc, items: [...buildDoc.items.slice(0, 11), { id: 'tampered' }] };
  const tampered = await run(() => runtimeResponse(altered, { generatedAt: iso(SRC_STAMP) }));
  assert.equal(tampered.status, 'FAIL'); assert.equal(tampered.results[0].reason, 'PUBLIC_ASSET_SHA256_MISMATCH');
  // Older runtime object within the grace: not newer than the build, so bytes must match exactly.
  const older = await run(lagging(4 * MIN, 8260));
  assert.equal(older.status, 'FAIL'); assert.equal(older.results[0].reason, 'PUBLIC_ASSET_SHA256_MISMATCH');
  // Newer but WITHOUT proof: no exception.
  const noProof = await run(() => staticResponse(liveDoc(SRC_STAMP + 2 * MIN, 8262)));
  assert.equal(noProof.status, 'FAIL'); assert.equal(noProof.results[0].reason, 'PUBLIC_ASSET_SHA256_MISMATCH');
});

test('parity: static behaviour is unchanged (no headers anywhere): same verdicts as before PR-3', async () => {
  assert.equal((await runParity(() => staticResponse(liveDoc(SRC_STAMP, 8261)))).status, 'PASS');
  assert.equal((await runParity(() => staticResponse(liveDoc(SRC_STAMP - 5 * MIN, 8261)))).status, 'PASS'); // 5:00 is the old tolerance
  assert.equal((await runParity(() => staticResponse(liveDoc(SRC_STAMP - 5 * MIN - 1000, 8261)))).results[0].reason, 'PUBLIC_SOURCE_DEPLOYMENT_DRIFT');
  assert.equal((await runParity(() => staticResponse(liveDoc(SRC_STAMP, 8260)))).results[0].reason, 'PUBLIC_CORPUS_BEHIND_SOURCE');
});

// ======================= S2N gate (certify-soc-s2n-api-release) =======================
const T = Date.parse('2026-10-26T13:15:00.000Z');
const MOMENT = Date.parse('2026-10-26T12:30:00.000Z');
function s2nFixture() {
  const ids = Array.from({ length: 12 }, (_, i) => ({ id: 'CVE-2026-' + String(10000 + i) }));
  const m = iso(MOMENT);
  return {
    state: { lastRun: m, lastReportGeneratedAt: m, totalPublished: 6548, published: [], lastIngestion: { reportsGenerated: 15 } },
    rootSource: { generatedAt: m, totalPublished: 6548, metadata: { lastPipelineRun: m, lastReportGeneratedAt: m }, items: ids },
    apiSource: { generated: m, lastReportGeneratedAt: m, total_published: 6548, items: ids },
  };
}
const apiAt = (x, deltaMs, total, mutate) => {
  const d = { ...structuredClone(x.apiSource), generated: iso(MOMENT + deltaMs), total_published: total };
  if (mutate) mutate(d);
  return d;
};
const monitor = (x, make) => s2n.monitorPublic({ sourceApi: x.apiSource, sourceRoot: x.rootSource, sourceState: x.state, nowMs: T,
  fetchImpl: byUrl({ [s2n.TARGETS.soc]: make, [s2n.TARGETS.blog]: make }) });
const rtApi = (x, deltaMs, total, mutate, over) => () => runtimeResponse(apiAt(x, deltaMs, total, mutate), { generatedAt: iso(MOMENT + deltaMs), over });
const swapLastId = (d) => { d.items[11] = { id: 'CVE-2026-09999' }; };

test('s2n monitor: a PROVEN runtime response behind the source (lower total, different last report) passes inside the window; unproven does not', async () => {
  const x = s2nFixture();
  const ok = await monitor(x, rtApi(x, -7 * MIN, 6547, swapLastId));
  assert.equal(ok.status, 'PASS', JSON.stringify(ok.results));
  assert.equal(ok.results[0].reason, 'PUBLIC_S2N_API_RUNTIME_WITHIN_PROPAGATION_WINDOW');
  assert.equal(ok.results[0].provenance, 'runtime-r2');
  assert.equal(ok.releaseAssetByteParityCertified, false);
  const plain = await monitor(x, () => staticResponse(apiAt(x, -7 * MIN, 6547, swapLastId)));
  assert.equal(plain.status, 'FAIL'); assert.equal(plain.results[0].reason, 'PUBLIC_S2N_API_BEHIND_SOURCE');
});

test('s2n monitor: exact boundaries (behind 10:00 passes, 10:01 fails; ahead 5:00 passes, 5:01 fails)', async () => {
  const x = s2nFixture();
  assert.equal((await monitor(x, rtApi(x, -10 * MIN, 6547, swapLastId))).status, 'PASS');
  const behind = await monitor(x, rtApi(x, -10 * MIN - 1000, 6547, swapLastId));
  assert.equal(behind.status, 'FAIL'); assert.equal(behind.results[0].reason, 'PUBLIC_S2N_API_BEHIND_SOURCE');
  assert.equal((await monitor(x, rtApi(x, 5 * MIN, 6549, swapLastId))).status, 'PASS');
  const ahead = await monitor(x, rtApi(x, 5 * MIN + 1000, 6549, swapLastId));
  assert.equal(ahead.status, 'FAIL'); assert.equal(ahead.results[0].reason, 'PUBLIC_S2N_API_REPORT_IDENTITY_DRIFT');
});

test('s2n monitor: equality is waived ONLY at a different instant; at the same instant totals and IDs stay exact', async () => {
  const x = s2nFixture();
  const total = await monitor(x, rtApi(x, 0, 6547));
  assert.equal(total.status, 'FAIL'); assert.equal(total.results[0].reason, 'PUBLIC_S2N_API_LEDGER_MISMATCH');
  const ids = await monitor(x, rtApi(x, 0, 6548, swapLastId));
  assert.equal(ids.status, 'FAIL'); assert.equal(ids.results[0].reason, 'PUBLIC_S2N_API_REPORT_IDENTITY_DRIFT');
  assert.equal((await monitor(x, rtApi(x, 0, 6548))).results[0].reason, 'PUBLIC_S2N_API_SOURCE_PARITY');
});

test('s2n monitor: the corpus must move in the direction of time (older cannot be larger, newer cannot be smaller)', async () => {
  const x = s2nFixture();
  const older = await monitor(x, rtApi(x, -3 * MIN, 6549));
  assert.equal(older.status, 'FAIL'); assert.equal(older.results[0].reason, 'PUBLIC_S2N_API_RUNTIME_LEDGER_INCONSISTENT');
  const newer = await monitor(x, rtApi(x, 2 * MIN, 6547));
  assert.equal(newer.status, 'FAIL'); assert.equal(newer.results[0].reason, 'PUBLIC_S2N_API_RUNTIME_LEDGER_INCONSISTENT');
});

test('s2n monitor: spoofed provenance gets no waiver; duplicate or invalid IDs and staleness still fail', async () => {
  const x = s2nFixture();
  const badSha = await monitor(x, rtApi(x, -7 * MIN, 6547, swapLastId, { 'x-feed-sha256': sha('x') }));
  assert.equal(badSha.status, 'FAIL'); assert.equal(badSha.results[0].reason, 'PUBLIC_S2N_API_BEHIND_SOURCE');
  assert.match(badSha.results[0].provenance, /^runtime-r2-REJECTED:RUNTIME_SHA256_MISMATCH/);
  const wrongStamp = await monitor(x, rtApi(x, -7 * MIN, 6547, swapLastId, { 'x-feed-generated-at': iso(MOMENT - 6 * MIN) }));
  assert.equal(wrongStamp.results[0].reason, 'PUBLIC_S2N_API_BEHIND_SOURCE');
  const dup = await monitor(x, rtApi(x, -7 * MIN, 6547, (d) => { d.items[11] = { ...d.items[0] }; }));
  assert.equal(dup.status, 'FAIL'); assert.equal(dup.results[0].reason, 'PUBLIC_S2N_API_INVALID');
  // Provenanced but older than 180 minutes relative to now: stale.
  const stale = await s2n.monitorPublic({ sourceApi: x.apiSource, sourceRoot: x.rootSource, sourceState: x.state, nowMs: T,
    fetchImpl: byUrl({ [s2n.TARGETS.soc]: rtApi(x, -200 * MIN, 6000), [s2n.TARGETS.blog]: rtApi(x, -200 * MIN, 6000) }) });
  assert.equal(stale.results[0].reason, 'PUBLIC_S2N_API_STALE');
});

test('s2n monitor: static behaviour is unchanged (no headers): exact same verdicts as before PR-3', async () => {
  const x = s2nFixture();
  assert.equal((await monitor(x, () => staticResponse(x.apiSource))).status, 'PASS');
  assert.equal((await monitor(x, () => staticResponse(apiAt(x, -5 * MIN, 6548)))).status, 'PASS'); // 5:00 behind with equal ledger: old tolerance
  assert.equal((await monitor(x, () => staticResponse(apiAt(x, -5 * MIN - 1000, 6548)))).results[0].reason, 'PUBLIC_S2N_API_BEHIND_SOURCE');
  assert.equal((await monitor(x, () => staticResponse(apiAt(x, 0, 6547)))).results[0].reason, 'PUBLIC_S2N_API_LEDGER_MISMATCH');
});

test('s2n --release-asset: identical bytes pass; other bytes pass ONLY as proven runtime output strictly newer than the asset', async () => {
  const x = s2nFixture();
  const asset = Buffer.from(JSON.stringify(x.apiSource));
  const run = (make) => s2n.verifyPublic({ assetBytes: asset, nowMs: T, fetchImpl: byUrl({ [s2n.TARGETS.soc]: make, [s2n.TARGETS.blog]: make }) });
  assert.equal((await run(() => new Response(asset, { status: 200, headers: JSON_HDR }))).status, 'PASS');
  const newer = await run(rtApi(x, 2 * MIN, 6549));
  assert.equal(newer.status, 'PASS', JSON.stringify(newer.results));
  assert.equal(newer.results[0].reason, 'PUBLIC_S2N_API_RUNTIME_NEWER_THAN_ASSET');
  for (const [what, make] of Object.entries({
    'same instant, other bytes (tampered)': rtApi(x, 0, 6548, swapLastId),
    'older than the asset': rtApi(x, -3 * MIN, 6547),
    'newer but without proof': () => staticResponse(apiAt(x, 2 * MIN, 6549)),
    'newer with a bad hash': rtApi(x, 2 * MIN, 6549, undefined, { 'x-feed-sha256': sha('x') }),
  })) {
    const out = await run(make);
    assert.equal(out.status, 'FAIL', what); assert.equal(out.results[0].reason, 'PUBLIC_S2N_API_SHA256_MISMATCH', what);
  }
});
