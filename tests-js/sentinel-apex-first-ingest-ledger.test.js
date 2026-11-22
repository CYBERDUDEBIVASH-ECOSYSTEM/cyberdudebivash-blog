'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {isFirstPlatformAddition,resolveFirstAddedAt}=require('../fetch-live-intel.js');

const now='2026-11-22T05:32:25.400Z';
const status=(id,feed,ledger,post)=>isFirstPlatformAddition({
  id,presentInFeed:feed,presentInPublishedLedger:ledger,postFileExists:post
});

test('historical published record evicted from 150-item rolling feed is never artificially re-ingested',()=>{
  // Reproduced in the 2026-11-22 05:32 source corpus for 15 ledger-known
  // advisories absent from the previous top-150 window.
  assert.equal(status('CVE-2026-77309',false,true,false),false);
  assert.equal(resolveFirstAddedAt(status('CVE-2026-77309',false,true,false),null,now),undefined);
});

test('existing archive post prevents false freshness when the published ledger entry has expired',()=>{
  assert.equal(status('CVE-2026-77309',false,false,true),false);
  assert.equal(resolveFirstAddedAt(status('CVE-2026-77309',false,false,true),null,now),undefined);
});

test('rolling feed retains originally recorded ingestion timestamp without refresh',()=>{
  assert.equal(status('CVE-2026-77309',true,true,true),false);
  assert.equal(resolveFirstAddedAt(false,{_addedAt:'2026-11-20T08:00:00.000Z'},now),'2026-11-20T08:00:00.000Z');
});

test('genuine first platform addition alone receives its current ingestion timestamp',()=>{
  assert.equal(status('new-first-party-evidence',false,false,false),true);
  assert.equal(resolveFirstAddedAt(true,null,now),now);
});

test('missing, ambiguous or invalid source history never promotes an item to fresh',()=>{
  assert.equal(isFirstPlatformAddition({id:'CVE-2026-77309'}),false);
  assert.equal(isFirstPlatformAddition({id:'' ,presentInFeed:false,presentInPublishedLedger:false,postFileExists:false}),false);
  assert.equal(isFirstPlatformAddition({id:null,presentInFeed:false,presentInPublishedLedger:false,postFileExists:false}),false);
  assert.equal(status('CVE-2026-77309',false,undefined,false),false);
  assert.equal(status('CVE-2026-77309',false,false,undefined),false);
  assert.equal(status('CVE-2026-77309',undefined,false,false),false);
});

test('actual publisher maps publication ledger and archive file into the provenance decision',()=>{
  const code=fs.readFileSync(path.join(__dirname,'../fetch-live-intel.js'),'utf8');
  assert.match(code,/presentInPublishedLedger:\s*previouslyPublishedIds\.has\(item\.id\)/);
  assert.match(code,/postFileExists:\s*fs\.existsSync\(path\.join\(CFG\.postsDir, `\$\{resolvedSlug\}\.html`\)\)/);
  assert.match(code,/if \(isNewToFeed\) genuinelyFirstAddedIds\.add\(item\.id\)/);
  assert.match(code,/const trulyNewCount = genuinelyFirstAddedIds\.size/);
  assert.match(code,/const addedAt = resolveFirstAddedAt\(isNewToFeed, existingItem, nowTs\)/);
});
