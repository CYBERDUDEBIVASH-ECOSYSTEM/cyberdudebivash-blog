'use strict';
// P0 #433: exact eight changed paths reported UNKNOWN by independently verified
// full-tree production drift. Their semantics were inspected before adding each
// to the OPERATIONAL inventory. Manual release and customer canary still required.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const policy=require('../scripts/production-drift-policy.cjs');
const ROOT=path.resolve(__dirname,'..');
const DEPLOY=fs.readFileSync(path.join(ROOT,'.github/workflows/cloudflare-production-deploy.yml'),'utf8');
const PATTERNS=policy.deployPaths(DEPLOY);
const BASE='a'.repeat(40),HEAD='b'.repeat(40);
const PATHS=Object.freeze([
  '.github/workflows/blogger-oauth-readonly-certification.yml',
  '.github/workflows/cve-pages.yml',
  '.github/workflows/generate-rss.yml',
  '.github/workflows/security-audit.yml',
  '.github/workflows/sentinel-branding-check.yml',
  'AGENTS.md',
  'scripts/p0-soc-cti-evidence-gate.cjs',
  'scripts/soc-live-homepage-certify.js'
]);
function compare(names){
  return {status:'ahead',base_commit:{sha:BASE},merge_base_commit:{sha:BASE},
    commits:[{sha:HEAD}],ahead_by:1,total_commits:1,behind_by:0,
    files:names.map(filename=>({filename,status:'modified'}))};
}
test('eight independently inspected paths require manual operator review, never benign/deploy',()=>{
  assert.equal(new Set(PATHS).size,8);
  for(const filename of PATHS){
    assert.equal(fs.existsSync(path.join(ROOT,filename)),true,filename);
    assert.equal(policy.isReviewedOperationalPath(filename),true,filename);
    assert.equal(policy.isKnownBenignPath(filename),false,filename);
    const result=policy.classify(compare([filename]),BASE,HEAD,PATTERNS);
    assert.equal(result.state,'manual_release_required',filename);
    assert.deepEqual(result.operational,[filename],filename);
    assert.deepEqual(result.benign,[],filename);
    assert.deepEqual(result.unknown,[],filename);
  }
  const result=policy.classify(compare([...PATHS,'workers/entry.js']),BASE,HEAD,PATTERNS);
  assert.equal(result.state,'manual_release_required');
  assert.deepEqual(result.operational,[...PATHS].sort());
  assert.deepEqual(result.unknown,[]);
  assert.deepEqual(result.production,['workers/entry.js']);
  assert.match(policy.renderDriftSummary(HEAD,BASE,result),
    /Manual release and independent postdeploy certification required/);
});
test('unreviewed sibling workflow/scripts/charter files still BLOCK the release',()=>{
  for(const stranger of [
    '.github/workflows/blogger-oauth-publish.yml',
    '.github/workflows/cve-pages-backdoor.yml',
    '.github/workflows/security-audit-bypass.yml',
    'AGENTS-override.md',
    'scripts/p0-soc-cti-evidence-gate-v2.cjs',
    'scripts/soc-live-homepage-certify-v2.js'
  ]){
    assert.equal(policy.isReviewedOperationalPath(stranger),false,stranger);
    const result=policy.classify(compare([...PATHS,stranger]),BASE,HEAD,PATTERNS);
    assert.equal(result.state,'blocked',stranger);
    assert.deepEqual(result.unknown,[stranger],stranger);
    assert.deepEqual(result.operational,[...PATHS].sort());
  }
});
test('renaming operational source cannot launder it into safe documentation',()=>{
  for(const original of PATHS){
    const input=compare([]);
    input.files=[{filename:'docs/archived-'+path.basename(original)+'.md',
      previous_filename:original,status:'renamed'}];
    const result=policy.classify(input,BASE,HEAD,PATTERNS);
    assert.equal(result.state,'manual_release_required',original);
    assert.ok(result.operational.includes(original),original);
  }
});
test('enumeration is exact; no workflow/script glob or unattended deploy authorization',()=>{
  const source=fs.readFileSync(path.join(ROOT,'scripts/production-drift-policy.cjs'),'utf8');
  for(const filename of PATHS){
    const count=source.split("'"+filename+"'").length-1;
    assert.equal(count,1,filename+' listed exactly once');
  }
  assert.doesNotMatch(source,/'(?:\.github\/workflows|scripts)\/\*\*?'/);
  assert.match(DEPLOY,/if: \$\{\{ github\.event_name == 'workflow_dispatch' && github\.ref == 'refs\/heads\/main' \}\}/);
});
