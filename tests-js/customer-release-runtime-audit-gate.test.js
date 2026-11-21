'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.join(__dirname,'..');
const certification=fs.readFileSync(path.join(root,'.github/workflows/customer-release-certification.yml'),'utf8');
const deploy=fs.readFileSync(path.join(root,'.github/workflows/cloudflare-production-deploy.yml'),'utf8');

test('P0 standard CI rejects moderate-or-higher production advisories before release',()=>{
  const ciAudit=fs.readFileSync(path.join(root,'.github/workflows/security-audit.yml'),'utf8');
  const expected='npm audit --omit=dev --audit-level=moderate';
  assert.equal(ciAudit.split(expected).length-1,1);
  assert.doesNotMatch(ciAudit,/npm audit --omit=dev --audit-level=critical/);
  const label='name: "🔒 npm audit — production moderate-or-higher vulnerabilities"';
  const start=ciAudit.indexOf(label);
  assert.ok(start>0,'production dependency audit step must exist');
  const end=ciAudit.indexOf('\n      - name:',start+1);
  const step=ciAudit.slice(start,end<0?undefined:end);
  assert.match(step,/set -euo pipefail/);
  assert.match(step,/\[ ! -f package.json \] \|\| \[ ! -f package-lock.json \]/);
  assert.match(step,/npm ci --ignore-scripts --no-fund --legacy-peer-deps/);
  assert.match(step,/npm audit --omit=dev --audit-level=moderate/);
  assert.doesNotMatch(step,/continue-on-error:|\|\|\s*true|npm audit fix|--force/);
  assert.match(ciAudit,/node --test tests-js\/customer-release-runtime-audit-gate.test.js/);
});

test('P0 commercial certification and manual deployment reject all moderate-or-higher runtime advisories',()=>{
  const expected='npm audit --omit=dev --audit-level=moderate';
  assert.equal(certification.split(expected).length-1,1);
  assert.match(deploy,/npm audit --omit=dev --audit-level=moderate/);
  assert.doesNotMatch(certification,/npm audit --omit=dev --audit-level=critical/);
});

test('customer release security audit runs immediately after locked install, before expensive suites and GO',()=>{
  const install=certification.indexOf('npm ci --legacy-peer-deps');
  const audit=certification.indexOf('npm audit --omit=dev --audit-level=moderate');
  const issue=certification.indexOf('name: "Block release while P0 customer incidents remain open"');
  const integration=certification.indexOf('name: "Run complete Blogger evidence/syndication suite"');
  const go=certification.indexOf('CUSTOMER_RELEASE_STATUS=GO');
  assert(install>=0&&audit>install&&issue>audit&&integration>audit&&go>integration);
  const gate=certification.slice(certification.lastIndexOf('      - name:',audit),certification.indexOf('      - name:',audit+1));
  assert.doesNotMatch(gate,/\|\|\s*true|continue-on-error:|--force|npm audit fix/);
});

test('release certification stays manual-only, read-only, and blocks unresolved customer incidents',()=>{
  assert.match(certification,/on:\s*\n  workflow_dispatch:\s*\n/);
  assert.doesNotMatch(certification,/\n  schedule:|\n  push:|\n  pull_request:/);
  assert.match(certification,/permissions:\s*\n  contents: read\n  issues: read/);
  assert.match(certification,/const blockers = \[222, 360, 418, 432, 433, 434, 494\]/);
  assert.match(certification,/node scripts\/certify-soc-public-feed-parity\.cjs/);
  assert.match(certification,/node scripts\/certify-soc-s2n-api-release\.cjs --monitor-public/);
});
