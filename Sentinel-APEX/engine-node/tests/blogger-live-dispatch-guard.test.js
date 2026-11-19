'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const guard = path.join(root, 'scripts/blogger-live-dispatch-guard.sh');

function verify(event, dryRun, count, ready, canary, sourceUrl = '', sourceHash = '') {
  const env = {
    ...process.env,
    GITHUB_EVENT_NAME: event,
    CDB_BLOGGER_DRY_RUN_INPUT: dryRun,
    MAX_POSTS_PER_RUN: count,
    CDB_BLOGGER_OAUTH_READY: ready,
    CDB_BLOGGER_CANARY_APPROVED: canary,
    CDB_BLOGGER_CANARY_SOURCE_URL: sourceUrl,
    CDB_BLOGGER_CANARY_SOURCE_HASH: sourceHash,
  };
  const result = spawnSync('bash', [guard], { cwd: root, env, encoding: 'utf8', timeout: 5000 });
  assert.equal(result.signal, null);
  return { code: result.status, text: result.stdout + result.stderr };
}

test('manual one-post dry run needs no readiness or publication authorization', () => {
  let x = verify('workflow_dispatch', 'true', '1', '', 'false');
  assert.equal(x.code, 0, x.text);
  assert.match(x.text, /READ_ONLY_DRY_RUN/);
});

test('manual single-post LIVE canary is blocked without explicit approval', () => {
  let x = verify('workflow_dispatch', 'false', '1', '', 'false');
  assert.equal(x.code, 2, x.text);
  assert.match(x.text, /requires live_canary_approved=true/);
});

test('approved one-post canary is possible without enabling recurring writes', () => {
  let x = verify('workflow_dispatch', 'false', '1', '', 'true',
    'https://blog.talosintelligence.com/analyzed-report/', '0123456789abcdef');
  assert.equal(x.code, 0, x.text);
  assert.match(x.text, /EXPLICIT_ONE_POST_CANARY/);
});

test('manual one-post live cannot proceed without source pin or with invalid pin', () => {
  assert.equal(verify('workflow_dispatch', 'false', '1', '', 'true').code, 2);
  assert.equal(verify('workflow_dispatch', 'false', '1', '', 'true', 'http://example.test/story', '0123456789abcdef').code, 2);
  assert.equal(verify('workflow_dispatch', 'false', '1', '', 'true', 'https://example.test/story', 'BADHASH').code, 2);
});

test('manual bulk LIVE dispatch cannot bypass missing readiness variable', () => {
  for (const count of ['2', '3', '4']) {
    let x = verify('workflow_dispatch', 'false', count, '', 'true');
    assert.equal(x.code, 2, x.text);
  }
});

test('approved readiness retains existing bounded four-post recovery', () => {
  let x = verify('workflow_dispatch', 'false', '4', 'true', 'false');
  assert.equal(x.code, 0, x.text);
  assert.match(x.text, /READY_MULTI_POST_BATCH/);
});

test('automated push and scheduled writes require readiness true', () => {
  for (const event of ['schedule', 'push']) {
    assert.equal(verify(event, 'true', '4', '', 'false').code, 2);
    assert.equal(verify(event, 'true', '4', 'true', 'false').code, 0);
  }
});

test('ambiguous input, unbounded posts, unknown event fail closed', () => {
  assert.equal(verify('workflow_dispatch', 'unexpected', '1', 'true', 'true').code, 2);
  assert.equal(verify('workflow_dispatch', 'false', '5', 'true', 'true').code, 2);
  assert.equal(verify('workflow_dispatch', 'false', '0', 'true', 'true').code, 2);
  assert.equal(verify('workflow_dispatch', 'false', 'four', 'true', 'true').code, 2);
  assert.equal(verify('unrecognized', 'false', '1', 'true', 'true').code, 2);
});

test('guard can be sourced without mutating caller shell options', () => {
  const script = [
    'set +e', 'set +u', 'set +o pipefail',
    '. scripts/blogger-live-dispatch-guard.sh',
    'case "$-" in *e*) echo UNSAFE_ERREXIT;; *) echo ERREXIT_UNCHANGED;; esac',
    'case "$-" in *u*) echo UNSAFE_NOUNSET;; *) echo NOUNSET_UNCHANGED;; esac',
  ].join('\n');
  const env = { ...process.env, GITHUB_EVENT_NAME: 'workflow_dispatch',
    CDB_BLOGGER_DRY_RUN_INPUT: 'true', MAX_POSTS_PER_RUN: '1' };
  const x = spawnSync('bash', ['-c', script], { cwd: root, env, encoding: 'utf8' });
  assert.equal(x.status, 0, x.stderr);
  assert.match(x.stdout, /ERREXIT_UNCHANGED/);
  assert.match(x.stdout, /NOUNSET_UNCHANGED/);
});

test('workflow applies guard before paid-dependency setup and again before publishing', () => {
  const workflow = fs.readFileSync(path.join(root,'.github/workflows/blogger-syndication.yml'), 'utf8');
  assert.ok(workflow.includes('live_canary_approved:'));
  assert.ok(workflow.includes("CDB_BLOGGER_OAUTH_READY: ${{ vars.BLOGGER_OAUTH_READY }}"));
  assert.ok(workflow.includes("CDB_BLOGGER_CANARY_APPROVED: ${{ github.event.inputs.live_canary_approved || 'false' }}"));
  assert.ok(workflow.includes('canary_source_url:'));
  assert.ok(workflow.includes('canary_source_hash:'));
  assert.ok(workflow.includes("CDB_BLOGGER_CANARY_SOURCE_URL: ${{ github.event.inputs.canary_source_url || '' }}"));
  assert.ok(workflow.includes("CDB_BLOGGER_CANARY_SOURCE_HASH: ${{ github.event.inputs.canary_source_hash || '' }}"));
  const early = workflow.indexOf('run: bash scripts/blogger-live-dispatch-guard.sh');
  const install = workflow.indexOf('name: "📦 Install Dependencies"');
  const final = workflow.indexOf('. ./scripts/blogger-live-dispatch-guard.sh');
  const python = workflow.indexOf('python -m automation.premium_main');
  assert.ok(early > 0 && early < install);
  assert.ok(final > early && final < python);
  assert.ok(workflow.includes("vars.BLOGGER_OAUTH_READY == 'true'"));
  const monitor = fs.readFileSync(path.join(root,'.github/workflows/freshness-check.yml'), 'utf8');
  assert.ok(monitor.includes('id: blogger_readiness'));
  assert.ok(monitor.includes('BLOGGER_READY: ${{ vars.BLOGGER_OAUTH_READY }}'));
  assert.ok(monitor.includes('BLOGGER_SCHEDULE_GATE=$STATUS'));
  assert.ok(monitor.includes('Blogger schedule gate : ${{ steps.blogger_readiness.outputs.status'));
});
