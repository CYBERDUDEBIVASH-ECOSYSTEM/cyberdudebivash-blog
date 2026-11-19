'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const script = path.join(root, 'scripts', 'blogger-one-post-canary-egress.sh');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/blogger-syndication.yml'), 'utf8');

function runGuard(event, dryRun, maxPosts) {
  const env = {
    ...process.env,
    GITHUB_EVENT_NAME: event,
    CDB_BLOGGER_DRY_RUN_INPUT: dryRun,
    MAX_POSTS_PER_RUN: maxPosts,
    TWITTER_API_KEY: 'test-key',
    TWITTER_API_SECRET: 'test-secret',
    TWITTER_ACCESS_TOKEN: 'test-access',
    TWITTER_ACCESS_SECRET: 'test-access-secret',
  };
  const bash = [
    'source scripts/blogger-one-post-canary-egress.sh',
    'for name in TWITTER_API_KEY TWITTER_API_SECRET TWITTER_ACCESS_TOKEN TWITTER_ACCESS_SECRET; do',
    '  if printenv "$name" >/dev/null 2>&1; then printf "PRESENT "; else printf "UNSET "; fi',
    'done',
  ].join('\n');
  const child = spawnSync('bash', ['-e', '-u', '-o', 'pipefail', '-c', bash],
    { cwd: root, env, encoding: 'utf8', timeout: 5000 });
  assert.equal(child.status, 0, child.stderr);
  return child.stdout;
}

test('manual one-post live canary suppresses X credentials in same shell', () => {
  const stdout = runGuard('workflow_dispatch', 'false', '1');
  assert.match(stdout, /P0_ONE_POST_CANARY_X_AMPLIFICATION=DISABLED/);
  assert.match(stdout, /UNSET UNSET UNSET UNSET\s*$/);
});

test('manual dry run preserves normal environment (no live side effects)', () => {
  const stdout = runGuard('workflow_dispatch', 'true', '1');
  assert.doesNotMatch(stdout, /AMPLIFICATION=DISABLED/);
  assert.match(stdout, /PRESENT PRESENT PRESENT PRESENT\s*$/);
});

test('scheduled live publisher remains unchanged', () => {
  const stdout = runGuard('schedule', 'true', '4');
  assert.doesNotMatch(stdout, /AMPLIFICATION=DISABLED/);
  assert.match(stdout, /PRESENT PRESENT PRESENT PRESENT\s*$/);
});

test('multi-post manual recovery does not masquerade as a one-post canary', () => {
  const stdout = runGuard('workflow_dispatch', 'false', '4');
  assert.doesNotMatch(stdout, /AMPLIFICATION=DISABLED/);
  assert.match(stdout, /PRESENT PRESENT PRESENT PRESENT\s*$/);
});

test('GitHub workflow sources egress guard before Python publisher', () => {
  const source = fs.readFileSync(script, 'utf8');
  const sourceLine = '. ./scripts/blogger-one-post-canary-egress.sh';
  const guardIndex = workflow.indexOf(sourceLine);
  const publisherIndex = workflow.indexOf('python -m automation.premium_main');
  assert.ok(guardIndex > 0 && publisherIndex > guardIndex);
  assert.ok(workflow.includes("CDB_BLOGGER_DRY_RUN_INPUT: ${{ github.event.inputs.dry_run || 'true' }}"));
  assert.match(source, /unset TWITTER_API_KEY TWITTER_API_SECRET/);
  assert.match(source, /unset TWITTER_ACCESS_TOKEN TWITTER_ACCESS_SECRET/);
  assert.match(workflow, /vars\.BLOGGER_OAUTH_READY == 'true'/);
});
