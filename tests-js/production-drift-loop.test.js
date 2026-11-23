'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..');
const drift = fs.readFileSync(path.join(root, '.github/workflows/production-drift-reconcile.yml'), 'utf8');
const deploy = fs.readFileSync(path.join(root, '.github/workflows/cloudflare-production-deploy.yml'), 'utf8');

test('read-only drift reconciler blocks a failed manual deployment and cannot retry', () => {
  const policy = fs.readFileSync(path.join(root, 'scripts/production-drift-policy.cjs'),'utf8');
  assert.match(policy, /latest\.conclusion !== 'success'/);
  assert.match(policy, /last manual production certification failed/);
  assert.match(policy, /state: 'blocked'/);
  assert.doesNotMatch(drift, /\/dispatches|actions: write/);
  assert.match(drift, /node scripts\/production-drift-policy\.cjs/);
});

test('only explicit operator dispatch can enter the production deployment job', () => {
  assert.match(deploy, /jobs:\s*\n  deploy:[\s\S]{0,350}?if: \$\{\{ github\.event_name == 'workflow_dispatch' && github\.ref == 'refs\/heads\/main' \}\}/);
  assert.match(deploy, /environment: production/);
  assert.match(drift, /permissions:\s*\n  contents: read\n  actions: read/);
  assert.doesNotMatch(drift, /curl[^\n]*-X POST|actions: write/);
});

test('route-marker certification still executes after real deployment', () => {
  assert.match(deploy, /- name: "Certify SOC 2 \+ CTI homepage command center"/);
  assert.match(deploy, /customer_route_check\s+"\/api-dashboard\.html"\s+"API Dashboard — SENTINEL APEX"/);
  assert.match(deploy, /grep -Fq "\$marker" "\$file"/);
  assert.match(deploy, /::error::Customer route \$route failed marker/);
});

test('build and authorization gates must precede read-only domain validation and Worker deploy', () => {
  const build = deploy.indexOf('name: "Build allowlisted production assets"');
  const preflight = deploy.indexOf('name: "Predeploy customer route certification parity — rendered build"');
  const credentials = deploy.indexOf('name: "Require deployment credentials"');
  const domain = deploy.indexOf('name: "P0 precondition — verify established Worker Custom Domain without DNS writes"');
  const legacyDns = deploy.indexOf('name: "P0 precondition — verify no legacy DNS origin before Wrangler mutation"');
  const production = deploy.indexOf('name: "Deploy Worker assets to the existing, approved domain"');
  const post = deploy.indexOf('name: "P0 postcondition — verify existing domain mapping unchanged"');
  const legacyDnsPost = deploy.indexOf('name: "Verify Vercel DNS retirement"');
  const live = deploy.indexOf('name: "Certify live Hybrid SOC + CTI production surfaces"');
  assert.ok(build > 0 && preflight > build && credentials > preflight &&
    domain > credentials && legacyDns > domain && production > legacyDns &&
    post > production && legacyDnsPost > post && live > legacyDnsPost);
  assert.match(deploy, /node scripts\/preflight-customer-route-markers\.cjs dist-public/);
  assert.doesNotMatch(deploy, /curl[^\n]+-X (?:DELETE|POST)[^\n]+dns_records/);
});

test('P0 drift reconciliation runs after failed or cancelled publisher completion, not only successful runs',()=>{
  // Publisher legitimately commits newly generated reports BEFORE its final
  // source-yield truth gate. If that gate fails, a success-only workflow_run
  // condition used to silently skip the immediate drift assessment.
  assert.match(drift,/workflow_run:\s*\n\s*workflows:/);
  assert.match(drift,/types:\s*\[completed\]/);
  assert.match(drift,/branches:\s*\[main\]/);
  const job=drift.split('\n  reconcile:')[1]?.split('\n    steps:')[0];
  assert(job,'bounded drift reconciliation job must exist');
  assert.match(job,/github\.event\.workflow_run\.conclusion != 'skipped'/,
    'skipped publisher jobs do not consume a second runner');
  assert.doesNotMatch(job,/conclusion == 'success'|conclusion != 'failure'/,
    'failed or cancelled producer runs must still reach read-only drift inventory');
  assert.match(drift,/permissions:\s*\n  contents: read\n  actions: read/);
  assert.doesNotMatch(drift,/npx wrangler deploy|\/dispatches|actions: write/);
});

test('P0 drift checks every producer completion and has one daily low-cost backstop',()=>{
  assert.match(drift,/workflow_run:\s*\n\s*workflows:/);
  assert.match(drift,/types:\s*\[completed\]/);
  assert.match(drift,/cron: ['"]41 4 \* \* \*['"]/);
  assert.doesNotMatch(drift,/cron: ['"]11,41 \* \* \* \*['"]/);
  assert.match(drift,/cancel-in-progress: true/,
    'monitor concurrency remains bounded and read-only');
});

test('P0 source certification is four times daily while customer freshness runs every 30 minutes',()=>{
  const health=fs.readFileSync(path.join(root,'.github/workflows/pipeline-health-certification.yml'),'utf8');
  const freshness=fs.readFileSync(path.join(root,'.github/workflows/freshness-check.yml'),'utf8');
  assert.match(health,/cron: ['"]49 2,8,14,20 \* \* \*['"]/);
  assert.match(freshness,/cron: ['"]13,43 \* \* \* \*['"]/);
  assert.match(health,/node scripts\/assess-pipeline-operational-health\.cjs/);
});


test('P0 approved freeze procedure remains a reviewed operational change, never benign',()=>{
  const policy = require('../scripts/production-drift-policy.cjs');
  assert.equal(policy.isReviewedOperationalPath('PRODUCTION_FREEZE_PROCEDURE.md'), true);
  assert.equal(policy.isKnownBenignPath('PRODUCTION_FREEZE_PROCEDURE.md'), false);
});


test('P0 drift subscribes to exactly the five real Git main writer workflows, never the RSS read-only validator',()=>{
  const part=drift.split('  workflow_run:')[1]?.split('    types: [completed]')[0];
  assert(part,'drift must declare completed workflow_run triggers');
  const names=[...part.matchAll(/^\s+-\s+"([^"]+)"\s*$/gm)].map(m=>m[1]);
  const writers=[
    'sentinel-apex.yml',
    'blogger-syndication.yml',
    'ai-security-intel.yml',
    'cve-pages.yml',
    'intelligence-hub.yml'
  ];
  const expected=writers.map(file=>{
    const content=fs.readFileSync(path.join(root,'.github/workflows',file),'utf8');
    const m=content.match(/^name:\s*["']?([^"'\n]+)["']?\s*$/m);
    assert(m,'missing workflow name for '+file);
    return m[1].trim();
  });
  assert.deepEqual([...names].sort(),[...expected].sort(),
    'any producer rename, missing trigger or read-only RSS trigger must fail closed');
  assert.equal(new Set(names).size,5,'no duplicate or unexpected drift-monitor triggers');
  const rss=fs.readFileSync(path.join(root,'.github/workflows/generate-rss.yml'),'utf8');
  assert.match(rss,/^permissions:\s*\n\s*contents: read/m);
  assert.doesNotMatch(rss,/\bgit push\b/);
});

test('P0 drift policy edits trigger workflow security CI and run full drift regression suite',()=>{
  const security=fs.readFileSync(path.join(root,'.github/workflows/workflow-security-gate.yml'),'utf8');
  const sections=security.split('  pull_request:');
  assert.equal(sections.length,2,'security workflow requires both push and PR triggers');
  for(const filename of ['scripts/production-drift-policy.cjs',
    'tests-js/production-drift-safety.test.js',
    'tests-js/production-drift-loop.test.js']){
    assert.ok(sections[0].includes("      - '"+filename+"'"),'push must watch '+filename);
    assert.ok(sections[1].split('  schedule:')[0].includes("      - '"+filename+"'"),
      'PR must watch '+filename);
  }
  assert.match(security,/node --test[^\n]*tests-js\/production-drift-safety\.test\.js/);
  assert.match(security,/permissions:\s*\n\s*contents: read/);
  assert.doesNotMatch(security,/pull_request_target:|write-all|npx wrangler deploy/);
});
