'use strict';
// Pins the safety properties of .github/workflows/soc-runtime-feed-publisher.yml.
// The most important one: this workflow can NEVER move main, so it cannot
// invalidate the 5-way SHA pin of a production release, and it NEVER holds the
// Cloudflare deploy token.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const yaml = require('js-yaml');

const FILE = path.join(__dirname, '..', '.github', 'workflows', 'soc-runtime-feed-publisher.yml');
const text = fs.readFileSync(FILE, 'utf8');
const wf = yaml.load(text);
const job = wf.jobs.publish;
const steps = job.steps;
const runs = steps.map((s) => s.run || '').join('\n');

test('master switch: skipped unless SOC_RUNTIME_FEED_ENABLED is exactly "true", and main-only', () => {
  assert.match(job.if, /github\.ref == 'refs\/heads\/main'/);
  assert.match(job.if, /vars\.SOC_RUNTIME_FEED_ENABLED == 'true'/);
});

test('READ-ONLY toward git: contents:read only, no commit/push/tag/gh/wrangler anywhere', () => {
  assert.deepEqual(wf.permissions, { contents: 'read' });
  assert.equal(job.permissions, undefined, 'no job-level permission escalation');
  for (const forbidden of [/git\s+push/, /git\s+commit/, /git\s+tag/, /\bgh\s+/, /wrangler/, /git\s+config/, /GITHUB_TOKEN/]) {
    assert.ok(!forbidden.test(runs), 'forbidden in run steps: ' + forbidden);
  }
  assert.ok(!/contents:\s*write/.test(text));
});

test('credentials: ONLY the bucket-scoped R2 key pair + the (non-secret) account id; never the deploy token', () => {
  const secrets = [...new Set([...text.matchAll(/secrets\.([A-Z0-9_]+)/g)].map((m) => m[1]))].sort();
  assert.deepEqual(secrets, ['CLOUDFLARE_ACCOUNT_ID', 'SOC_RUNTIME_FEED_R2_ACCESS_KEY_ID', 'SOC_RUNTIME_FEED_R2_SECRET_ACCESS_KEY']);
  assert.ok(!/CLOUDFLARE_API_TOKEN/.test(text), 'the deploy/API token must never be available to this workflow');
  assert.ok(!/CDB_CF_ACCOUNT_BUDGET_ATTESTATION|CDB_SOC_APPROVED_RELEASE_SHA/.test(text), 'release/budget secrets are never exposed here');
});

test('every third-party action is pinned to a 40-hex commit SHA and the job is bounded', () => {
  const uses = steps.map((s) => s.uses).filter(Boolean);
  assert.ok(uses.length >= 2);
  for (const u of uses) assert.match(u, /@[0-9a-f]{40}$/, u);
  assert.equal(typeof job['timeout-minutes'], 'number'); assert.ok(job['timeout-minutes'] <= 15);
});

test('triggers: push to main limited to the served files, a schedule safety net, and a manual dispatch that defaults to DRY RUN', () => {
  const on = wf.on || wf[true];
  assert.deepEqual(on.push.branches, ['main']);
  assert.deepEqual([...on.push.paths].sort(), ['api/intel/live.json', 'live-intel.json', 'posts/**', 'rss.xml']);
  assert.equal(on.schedule.length, 1);
  assert.equal(on.workflow_dispatch.inputs.dry_run.default, 'true');
  assert.equal(on.workflow_dispatch.inputs.check_only.default, 'false');
  assert.ok(!('pull_request' in on) && !('pull_request_target' in on) && !('workflow_run' in on), 'never reachable from PR/forks');
});

test('serialised, never cancelled mid-upload', () => {
  assert.equal(wf.concurrency.group, 'soc-runtime-feed-publisher');
  assert.equal(wf.concurrency['cancel-in-progress'], false);
});

test('manual inputs are never interpolated into shell: they reach the script only through env and are validated first', () => {
  for (const s of steps) if (s.run) assert.ok(!/\$\{\{\s*(github\.event\.inputs|inputs)\./.test(s.run), 'inputs interpolated into run: ' + s.name);
  const validate = steps.find((s) => /Validate manual inputs/.test(s.name));
  assert.ok(validate && /\^\[0-9\]\{1,3\}\$/.test(validate.run), 'since_commits is validated numerically before use');
  const publish = steps.find((s) => /Publish feeds/.test(s.name));
  assert.match(publish.run, /--since-commits "\$INPUT_SINCE_COMMITS"/);
  assert.match(publish.run, /--max-puts 400/); assert.match(publish.run, /--daily-cap 3000/);
});

test('the check-only path performs no writes (only --check) and the publish step is mutually exclusive with it', () => {
  const check = steps.find((s) => /Verify R2 credentials/.test(s.name));
  assert.match(check.run, /publish-runtime-feed\.cjs --check/);
  assert.match(check.if, /check_only == 'true'/);
  const publish = steps.find((s) => /Publish feeds/.test(s.name));
  assert.match(publish.if, /check_only != 'true'/);
});
