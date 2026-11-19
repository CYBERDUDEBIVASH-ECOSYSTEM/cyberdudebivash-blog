'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const yaml = require('js-yaml');

const root = path.resolve(__dirname, '../../..');
const source = fs.readFileSync(
  path.join(root, '.github/workflows/blogger-syndication.yml'), 'utf8'
);

// js-yaml's default strict mapping mode rejects duplicate YAML keys, unlike
// string-based CI assertions which missed the production GitHub 422 parse error.
const expected = Object.freeze({
  CDB_BLOGGER_OAUTH_READY: "${{ vars.BLOGGER_OAUTH_READY }}",
  CDB_BLOGGER_CANARY_APPROVED: "${{ github.event.inputs.live_canary_approved || 'false' }}",
  CDB_BLOGGER_DRY_RUN_INPUT: "${{ github.event.inputs.dry_run || 'true' }}",
  MAX_POSTS_PER_RUN: "${{ github.event.inputs.max_posts || '4' }}",
});

test('Blogger Actions YAML parses strictly with no duplicate env mappings', () => {
  const doc = yaml.load(source);
  assert.equal(typeof doc, 'object');
  assert.equal(doc.jobs?.syndicate?.['if']?.includes("vars.BLOGGER_OAUTH_READY == 'true'"), true);
});

test('pre-install and pre-publish guards receive exactly the same authorization inputs', () => {
  const doc = yaml.load(source);
  const steps = doc.jobs.syndicate.steps;
  const preflight = steps.find(s => s.name === 'P0 authorize Blogger dispatch before installing dependencies');
  const publisher = steps.find(s => s.id === 'syndication_pipeline');
  assert.ok(preflight, 'early authorization step missing');
  assert.ok(publisher, 'publisher step missing');
  for (const [key, value] of Object.entries(expected)) {
    assert.equal(preflight.env?.[key], value, 'preflight ' + key);
    assert.equal(publisher.env?.[key], value, 'publisher ' + key);
  }
  assert.match(preflight.run, /bash scripts\/blogger-live-dispatch-guard\.sh/);
  assert.match(publisher.run, /\. \.\/scripts\/blogger-live-dispatch-guard\.sh/);
  assert.ok(steps.indexOf(preflight) < steps.indexOf(publisher));
});

test('manual canary is opt-in, dry-run default stays safe', () => {
  const doc = yaml.load(source);
  const inputs = doc.on.workflow_dispatch.inputs;
  assert.equal(inputs.live_canary_approved.default, 'false');
  assert.equal(inputs.dry_run.default, 'true');
  assert.equal(inputs.max_posts.default, '1');
});

test('parser rejects duplicate mapping keys like the observed GitHub HTTP 422', () => {
  const invalid = 'env:\n  CDB_BLOGGER_OAUTH_READY: first\n  CDB_BLOGGER_OAUTH_READY: second\n';
  assert.throws(() => yaml.load(invalid), /duplicated mapping key/i);
});
