'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const policy = require('../scripts/production-drift-policy.cjs');

const root = path.resolve(__dirname, '..');
const file = 'automation/tests/test_search_recovery_publication_limits.py';
const unexpected = 'automation/tests/test_search_recovery_publication_limits_override.py';
const deploy = fs.readFileSync(path.join(root, '.github/workflows/cloudflare-production-deploy.yml'), 'utf8');
const patterns = policy.deployPaths(deploy);
const BASE = 'a'.repeat(40), HEAD = 'b'.repeat(40);
function compare(files) {
  return {
    status: 'ahead', base_commit: {sha: BASE}, merge_base_commit: {sha: BASE},
    ahead_by: 1, behind_by: 0, total_commits: 1, commits: [{sha: HEAD}],
    files: files.map(filename => ({filename, status: 'modified'}))
  };
}

test('reviewed Blogger publication-limit regression stays operational and manual-release gated', () => {
  const source = fs.readFileSync(path.join(root, file), 'utf8');
  assert.match(source, /factory\.FACTORY_WRITE_BURST == 4/);
  assert.match(source, /default: "1"/);
  assert.match(source, /default: "true"/);
  assert.match(source, /github\.event\.inputs\.max_posts \|\| '4'/);
  assert.equal(policy.isKnownBenignPath(file), false);
  assert.equal(policy.isReviewedOperationalPath(file), true);
  const result = policy.classify(compare([file]), BASE, HEAD, patterns);
  assert.equal(result.state, 'manual_release_required');
  assert.deepEqual(result.unknown, []);
  assert.deepEqual(result.benign, []);
  assert.ok([...result.operational, ...result.production].includes(file));
});

test('unreviewed adjacent automation tests stay blocked; no broad test glob is allowed', () => {
  assert.equal(policy.isReviewedOperationalPath(unexpected), false);
  const result = policy.classify(compare([file, unexpected]), BASE, HEAD, patterns);
  assert.equal(result.state, 'blocked');
  assert.deepEqual(result.unknown, [unexpected]);
  assert.ok([...result.operational, ...result.production].includes(file));
});

test('renaming an approved operational test into docs cannot bypass review', () => {
  const sample = compare([]);
  sample.files = [{filename: 'docs/retired-blogger-test.md', previous_filename: file, status: 'renamed'}];
  const result = policy.classify(sample, BASE, HEAD, patterns);
  assert.equal(result.state, 'manual_release_required');
  assert.ok([...result.operational, ...result.production].includes(file));
});

test('policy explicitly lists only the reviewed Blogger contract test', () => {
  const source = fs.readFileSync(path.join(root, 'scripts/production-drift-policy.cjs'), 'utf8');
  assert.equal(source.split("'"+file+"'").length-1, 1);
  assert.doesNotMatch(source, /'automation\/tests\/\*\*'/);
});
