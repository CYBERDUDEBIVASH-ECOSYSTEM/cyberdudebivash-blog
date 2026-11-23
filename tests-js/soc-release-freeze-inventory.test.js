'use strict';
/**
 * Static release-freeze recovery inventory contract: no network, no CI dispatch,
 * no Cloudflare/GitHub writes. Prevents a future P0 owner runbook from disabling
 * read-only validation while leaving a real scheduled Git writer enabled.
 */
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.join(__dirname,'..');
const read=p=>fs.readFileSync(path.join(root,p),'utf8');
const repo='CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog';
const doc=read('PRODUCTION_FREEZE_PROCEDURE.md');
const WRITERS=[
  'sentinel-apex.yml',
  'blogger-syndication.yml',
  'ai-security-intel.yml',
  'cve-pages.yml',
  'intelligence-hub.yml'
];
test('five current repo content-writer workflows are documented and actually retain write authority',()=>{
  for(const name of WRITERS){
    const yaml=read('.github/workflows/'+name);
    assert.match(yaml,/\bcontents:\s*write\b/,name+' must still be a writer');
    assert.match(yaml,/(?:\bgit\s+push\b|\bbash scripts\/publish-intelligence-hub\.sh\b)/,name+' must have real Git writer');
    assert.ok(doc.includes('https://github.com/'+repo+'/actions/workflows/'+name),name+' must link to current repo');
  }
  assert.equal(WRITERS.length,5);
});
test('RSS workflow is read-only and MUST NOT be disabled as part of freeze',()=>{
  const yaml=read('.github/workflows/generate-rss.yml');
  assert.match(yaml,/\bcontents:\s*read\b/);
  assert.doesNotMatch(yaml,/\bcontents:\s*write\b/);
  assert.doesNotMatch(yaml,/\bgit\s+push\b|\bgit\s+commit\b/);
  assert.doesNotMatch(yaml,/^\s+cron:\s/m);
  assert.match(doc,/Do not disable[\s\S]{0,120}generate-rss\.yml/i);
});
test('freeze procedure binds the approved current organization and protected production deploy',()=>{
  assert.match(doc,/manual release/i);
  assert.match(doc,/CDB_SOC_APPROVED_RELEASE_SHA/);
  assert.match(doc,/cloudflare-account|Cloudflare.*account-wide/i);
  assert.match(doc,/zero additional metered/i);
  assert.match(doc,/workflow run cloudflare-production-deploy\.yml/);
  assert.match(doc,/CDB_SOC_APPROVED_RELEASE_SHA/);
  assert.match(doc,/\b180-minute feed bound/);
  assert.match(doc,/Do not.*DNS|No DNS cutover/i);
  assert.match(doc,/resume|re-enable/i);
  assert.match(doc,/P0 customer incident/i);
});
test('five-writer inventory matches the checked-in published schedules',()=>{
  const expectations=[
    [/cron:\s*["']3,33 \* \* \* \*["']/,'sentinel-apex.yml'],
    [/cron:\s*["']17 \* \* \* \*["']/,'blogger-syndication.yml'],
    [/cron:\s*["']7 \*\/2 \* \* \*["']/,'ai-security-intel.yml'],
    [/cron:\s*["']19 \*\/6 \* \* \*["']/,'cve-pages.yml'],
    [/cron:\s*["']47 \*\/6 \* \* \*["']/,'intelligence-hub.yml']
  ];
  for(const [regex,name] of expectations)assert.match(read('.github/workflows/'+name),regex);
});
test('operational acceptance still requires exact four-feed parity rather than a count-only comparison',()=>{
  for(const host of ['soc.cyberdudebivash.in','blog.cyberdudebivash.in']){
    for(const suffix of ['/live-intel.json','/api/intel/live.json'])
      assert.ok(doc.includes('https://'+host+suffix));
  }
  assert.match(doc,/exact built\s+bytes/i);
  assert.match(doc,/commercial managed-SOC/i);
  assert.match(doc,/four public feed endpoints/i);
});
