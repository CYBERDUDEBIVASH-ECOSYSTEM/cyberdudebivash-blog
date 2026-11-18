'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const policy = require('../scripts/production-drift-policy.cjs');

const root = path.resolve(__dirname, '..');
const source = 'automation/cti_original_source_freshness.py';
const d1 = 'api/_lib/__tests__/d1-worker-native-fail-closed.test.js';
const unreviewed = 'automation/cti_original_source_freshness_unverified.py';
const deploy = fs.readFileSync(path.join(root,'.github/workflows/cloudflare-production-deploy.yml'),'utf8');
const patterns = policy.deployPaths(deploy);
const BASE = 'a'.repeat(40), HEAD = 'b'.repeat(40);
function compare(files) {
  return {
    status: 'ahead', base_commit: {sha:BASE},merge_base_commit:{sha:BASE},
    ahead_by:1, behind_by:0, total_commits:1, commits:[{sha:HEAD}],
    files:files.map(filename=>({filename,status:'modified'}))
  };
}

test('original source-date validator is reviewed operational, not benign',()=>{
  const code = fs.readFileSync(path.join(root,source),'utf8');
  assert.match(code, /SOURCE PUBLICATION DATE/);
  assert.match(code, /_MAX_POST_BYTES\s*=\s*256\s*\*\s*1024/);
  assert.match(code, /return False/);
  assert.equal(policy.isKnownBenignPath(source),false);
  assert.equal(policy.isReviewedOperationalPath(source),true);
  const result=policy.classify(compare([source]),BASE,HEAD,patterns);
  assert.equal(result.state,'manual_release_required');
  assert.deepEqual(result.unknown,[]);
  assert.ok([...result.operational,...result.production].includes(source));
});

test('previously reviewed D1 fail-closed test must remain operational',()=>{
  assert.equal(policy.isReviewedOperationalPath(d1),true);
  const result=policy.classify(compare([source,d1]),BASE,HEAD,patterns);
  assert.equal(result.state,'manual_release_required');
  assert.deepEqual(result.unknown,[]);
  assert.ok([...result.operational,...result.production].includes(d1));
});

test('unreviewed neighboring source remains BLOCKED',()=>{
  assert.equal(policy.isReviewedOperationalPath(unreviewed),false);
  const result=policy.classify(compare([source,unreviewed]),BASE,HEAD,patterns);
  assert.equal(result.state,'blocked');
  assert.deepEqual(result.unknown,[unreviewed]);
});

test('source rename cannot escape reviewed operational gate via benign docs',()=>{
  const c=compare([]);
  c.files=[{filename:'docs/stale-source-date.md',previous_filename:source,status:'renamed'}];
  const result=policy.classify(c,BASE,HEAD,patterns);
  assert.equal(result.state,'manual_release_required');
  assert.ok([...result.operational,...result.production].includes(source));
});

test('policy admits only the exact original-source module without wildcard',()=>{
  const body=fs.readFileSync(path.join(root,'scripts/production-drift-policy.cjs'),'utf8');
  assert.equal(body.split("'"+source+"'").length-1,1);
  assert.doesNotMatch(body,/^\s*'automation\/\*\*'/m);
});
