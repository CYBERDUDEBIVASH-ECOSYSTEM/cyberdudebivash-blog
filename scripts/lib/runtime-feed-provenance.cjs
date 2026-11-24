'use strict';
/**
 * Provenance of a public feed response that the Worker served from the runtime R2 bucket
 * (workers/lib/runtime-feed.js, Option A). Pure functions, no network.
 *
 * WHY: once the feeds are served from R2 they can legitimately LAG the checked-in source by
 * the publisher + cache propagation time (a few minutes). The static-deploy gates tolerate
 * almost none of that, so without a bounded allowance they would flap on every publisher
 * commit. The allowance is granted ONLY to a response that proves where it came from; every
 * other response is judged by the unchanged strict rules.
 *
 * A response is "runtime-provenanced" only if ALL of these hold:
 *   1. X-Feed-Source is exactly "runtime-r2";
 *   2. X-Feed-Sha256 is 64 lowercase hex AND equals the sha256 of the body bytes the gate
 *      actually received (recomputed here, never trusted);
 *   3. X-Feed-Generated-At is the SAME INSTANT as the feed's own pipeline timestamp, using the
 *      same precedence the publisher uses (scripts/publish-runtime-feed.cjs FEEDS[].stamp);
 *   4. that instant is not more than 5 minutes in the future and not older than 180 minutes.
 * Anything else (no header, wrong hash, mismatching timestamp, too old) is NOT provenanced.
 */
const crypto = require('node:crypto');

/** Public (runtime) may lag the source checkout by at most this long. */
const RUNTIME_PROPAGATION_GRACE_MINUTES = 10;
/** Public may lead an older source checkout by at most this long (the pre-existing static tolerance). */
const RUNTIME_AHEAD_MINUTES = 5;
const MAX_AGE_MINUTES = 180;

// Same precedence as FEEDS[].stamp in scripts/publish-runtime-feed.cjs. Keep in lockstep:
// tests-js/runtime-feed-provenance.test.js pins this against the publisher's own definition.
const STAMP = Object.freeze({
  'live-intel': (d) => (d && d.metadata && (d.metadata.lastPipelineRun || d.metadata.generated)) || (d && d.generatedAt),
  'api': (d) => (d && (d.generated || d.lastReportGeneratedAt)),
});

const sha256Hex = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const toMs = (v) => (typeof v === 'string' ? Date.parse(v) : NaN);
const header = (headers, name) => (headers && typeof headers.get === 'function' ? headers.get(name) : null);

/**
 * @param {{kind:'live-intel'|'api', headers:{get:Function}, bytes:Buffer, data:object, nowMs:number}} o
 * @returns {{claimed:boolean, ok:boolean, reason?:string, generatedMs?:number}}
 *   claimed: the response asserts runtime provenance (X-Feed-Source present). ok: it is proven.
 */
function verifyRuntimeProvenance({ kind, headers, bytes, data, nowMs } = {}) {
  const source = header(headers, 'x-feed-source');
  if (source === null || source === undefined) return { claimed: false, ok: false, reason: 'NO_RUNTIME_HEADER' };
  const fail = (reason) => ({ claimed: true, ok: false, reason });
  if (source !== 'runtime-r2') return fail('RUNTIME_SOURCE_UNKNOWN');
  if (!STAMP[kind]) return fail('RUNTIME_KIND_UNKNOWN');
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) return fail('RUNTIME_BYTES_UNAVAILABLE');
  const claimedSha = header(headers, 'x-feed-sha256');
  if (typeof claimedSha !== 'string' || !/^[0-9a-f]{64}$/.test(claimedSha)) return fail('RUNTIME_SHA256_INVALID');
  if (claimedSha !== sha256Hex(bytes)) return fail('RUNTIME_SHA256_MISMATCH');
  const generatedMs = toMs(header(headers, 'x-feed-generated-at'));
  if (!Number.isFinite(generatedMs)) return fail('RUNTIME_GENERATED_AT_MISSING');
  const own = toMs(STAMP[kind](data));
  if (!Number.isFinite(own) || own !== generatedMs) return fail('RUNTIME_GENERATED_AT_MISMATCH');
  if (!Number.isFinite(nowMs)) return fail('RUNTIME_NOW_UNAVAILABLE');
  if (generatedMs > nowMs + RUNTIME_AHEAD_MINUTES * 60000) return fail('RUNTIME_GENERATED_AT_FUTURE');
  if (nowMs - generatedMs > MAX_AGE_MINUTES * 60000) return fail('RUNTIME_GENERATED_AT_STALE');
  return { claimed: true, ok: true, generatedMs };
}

/** Short label for result objects and logs (never contains header values). */
const provenanceLabel = (p) => (p && p.ok ? 'runtime-r2' : p && p.claimed ? 'runtime-r2-REJECTED:' + p.reason : 'static');

module.exports = {
  RUNTIME_PROPAGATION_GRACE_MINUTES, RUNTIME_AHEAD_MINUTES, MAX_AGE_MINUTES,
  STAMP, verifyRuntimeProvenance, provenanceLabel,
};
