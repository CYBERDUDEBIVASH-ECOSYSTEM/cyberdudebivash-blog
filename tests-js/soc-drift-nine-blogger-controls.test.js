'use strict';
// P0 #433/#434: exact source-reviewed paths reported unknown by drift run
// #44573375309. Classification is OPERATIONAL and never an edge release GO.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const drift = require('../scripts/production-drift-policy.cjs');

const ROOT = path.resolve(__dirname, '..');
const DEPLOY = fs.readFileSync(path.join(ROOT,'.github/workflows/cloudflare-production-deploy.yml'),'utf8');
const PATTERNS = drift.deployPaths(DEPLOY);
const BASE = 'a'.repeat(40), HEAD = 'b'.repeat(40);
const FILES = Object.freeze([
  '.github/workflows/blogger-provider-delivery-readonly.yml',
  'automation/canary_review_preview.py',
  'automation/canary_source_identity.py',
  'automation/editorial_quarantine.py',
  'automation/premium_factory_throughput.py',
  'automation/publication_scheduler.py',
  'scripts/blogger-live-dispatch-guard.sh',
  'scripts/blogger-one-post-canary-egress.sh',
  'scripts/blogger_provider_delivery_audit.py'
]);
const compare = names => ({
  status: 'ahead',base_commit:{sha:BASE},merge_base_commit:{sha:BASE},
  ahead_by:1,behind_by:0,total_commits:1,commits:[{sha:HEAD}],
  files:names.map(filename => ({filename,status:'modified'}))
});

test('nine inspected Blogger controls are exact and release-critical, not benign', () => {
  assert.equal(FILES.length,9);
  assert.equal(new Set(FILES).size,9);
  for (const file of FILES) {
    assert.ok(fs.existsSync(path.join(ROOT,file)),file);
    assert.equal(drift.isReviewedOperationalPath(file),true,file);
    assert.equal(drift.isKnownBenignPath(file),false,file);
    const result=drift.classify(compare([file]),BASE,HEAD,PATTERNS);
    assert.equal(result.state,'manual_release_required',file);
    assert.deepEqual(result.unknown,[],file);
    assert.deepEqual(result.benign,[],file);
    assert.deepEqual(result.operational,[file],file);
    assert.deepEqual(result.production,[],file);
  }
});

test('all nine together only remove UNKNOWN blocking, never manually approved release requirement', () => {
  const result=drift.classify(compare(FILES),BASE,HEAD,PATTERNS);
  assert.equal(result.state,'manual_release_required');
  assert.deepEqual(result.unknown,[]);
  assert.deepEqual(result.operational,[...FILES].sort());
  assert.match(drift.renderDriftSummary(HEAD,BASE,result),
    /Manual release and independent postdeploy certification required/);
});

test('unreviewed sibling sources, new workflows and untrusted scripts remain BLOCKED', () => {
  const unreviewed=[
    '.github/workflows/blogger-provider-delivery-write.yml',
    'automation/canary_review_preview_unsafe.py',
    'automation/canary_source_identity_override.py',
    'automation/editorial_quarantine_bypass.py',
    'automation/premium_factory_throughput_v2.py',
    'automation/publication_scheduler_override.py',
    'scripts/blogger-live-dispatch-guard-bypass.sh',
    'scripts/blogger-one-post-canary-egress-unsafe.sh',
    'scripts/blogger_provider_delivery_audit_v2.py'
  ];
  for (const unknown of unreviewed) {
    assert.equal(drift.isReviewedOperationalPath(unknown),false,unknown);
    const result=drift.classify(compare([...FILES,unknown]),BASE,HEAD,PATTERNS);
    assert.equal(result.state,'blocked',unknown);
    assert.deepEqual(result.unknown,[unknown],unknown);
  }
});

test('renaming any of these sensitive files into docs cannot turn it benign', () => {
  for (const file of FILES) {
    const named=compare([]);
    named.files=[{filename:'docs/retired-'+path.basename(file)+'.md',
      previous_filename:file,status:'renamed'}];
    const result=drift.classify(named,BASE,HEAD,PATTERNS);
    assert.equal(result.state,'manual_release_required',file);
    assert.ok(result.operational.includes(file),file);
  }
});

test('classification is exact, no automation or workflow wildcard, no auto deployment', () => {
  const code=fs.readFileSync(path.join(ROOT,'scripts/production-drift-policy.cjs'),'utf8');
  for (const file of FILES) {
    assert.equal(code.split("'"+file+"'").length-1,1,file);
  }
  assert.doesNotMatch(code,/^\s*'(?:automation|scripts|\.github\/workflows)\/\*\*?'/m);
  assert.match(DEPLOY,/if: \$\{\{ github\.event_name == 'workflow_dispatch' && github\.ref == 'refs\/heads\/main' \}\}/);
});
