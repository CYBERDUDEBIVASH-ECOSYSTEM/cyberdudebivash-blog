'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/sentinel-apex.yml'), 'utf8');
const start = workflow.indexOf('      - name: "Ensure feed heartbeat (production stability)"');
const end = workflow.indexOf('      # A timed-out publisher may have partial', start);
assert.ok(start > 0 && end > start, 'heartbeat and subsequent integrity gate exist');
const block = workflow.slice(start, end);
const match = block.match(/node -e "([\s\S]*?)" 2>&1/);
assert.ok(match, 'extract actual Node heartbeat program from GitHub workflow');
const program = match[1];

function runHeartbeat(feed) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cdb-heartbeat-proof-'));
  try {
    const name = path.join(directory, 'live-intel.json');
    fs.writeFileSync(name, JSON.stringify(feed), 'utf8');
    const result = spawnSync(process.execPath, ['-e', program], {
      cwd: directory, encoding: 'utf8', timeout: 3000, env: process.env
    });
    assert.equal(result.error, undefined, result.error && result.error.message);
    assert.equal(result.status, 0, result.stdout + '\n' + result.stderr);
    return JSON.parse(fs.readFileSync(name, 'utf8'));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test('heartbeat never derives ingestion timestamp from source article publication date', () => {
  const feed = {
    generatedAt: '2026-11-12T08:00:00Z',
    lastUpdated: '2026-11-12T08:00:00Z',
    totalPublished: 100,
    metadata: { generated: '2026-11-12T08:00:00Z', version: '5.0' },
    stats: { critical: 2 },
    items: [
      { id: 'A', title: 'Original publication is not platform ingestion', pubDate: '2026-11-12T07:00:00Z' },
      { id: 'B', title: 'Legacy source with date-only publication', published: '2026-11-12' },
      { id: 'C', title: 'Verified first addition', _addedAt: '2026-11-12T05:00:00Z', pubDate: '2026-11-11' }
    ]
  };
  const out = runHeartbeat(feed);
  assert.deepEqual(out.items, feed.items, '_addedAt and source dates must be immutable');
  assert.equal(out.items[0]._addedAt, undefined);
  assert.equal(out.items[1]._addedAt, undefined);
  assert.equal(out.items[2]._addedAt, '2026-11-12T05:00:00Z');
});

test('heartbeat updates only operational liveness metadata, not report freshness evidence', () => {
  const feed = {
    generatedAt: '2026-10-23T04:58:15Z',
    lastUpdated: '2026-10-23T04:58:15Z',
    totalPublished: 6466,
    metadata: { generated: '2026-10-23T04:58:15Z' },
    items: [{ id: 'old', title: 'Archive', _addedAt: '2026-10-23T04:58:15Z' }]
  };
  const before = Date.now();
  const out = runHeartbeat(feed);
  const after = Date.now();
  assert.deepEqual(out.items, feed.items);
  assert.equal(out.generatedAt, feed.generatedAt);
  assert.equal(out.lastUpdated, feed.lastUpdated);
  assert.equal(out.metadata.generated, feed.metadata.generated);
  assert.equal(out.totalPublished, feed.totalPublished);
  assert.ok(Date.parse(out.metadata.lastPipelineRun) >= before - 1000);
  assert.ok(Date.parse(out.metadata.lastPipelineRun) <= after + 1000);
  assert.equal(out._heartbeat, out.metadata.lastPipelineRun);
  assert.match(workflow, /node scripts\/assert-publication-ledger\.cjs/);
  assert.match(workflow, /node scripts\/check-intel-source-yield\.cjs/);
});

test('heartbeat does not fabricate report freshness from missing platform timestamp', () => {
  assert.doesNotMatch(program, /item\._addedAt\s*=/);
  assert.doesNotMatch(program, /data\.generatedAt\s*=/);
  assert.doesNotMatch(program, /data\.lastUpdated\s*=/);
  assert.doesNotMatch(program, /data\.items\.forEach\s*\(/);
});

test('native generator timestamps true first additions, but never promotes known undated items', () => {
  const { resolveFirstAddedAt } = require('../fetch-live-intel.js');
  const now = '2026-11-12T17:24:00.000Z';
  assert.equal(resolveFirstAddedAt(true, null, now), now);
  assert.equal(resolveFirstAddedAt(false, { _addedAt: '2026-11-10T05:00:00Z' }, now), '2026-11-10T05:00:00Z');
  assert.equal(resolveFirstAddedAt(false, { pubDate: '2026-11-12' }, now), undefined);
  assert.equal(resolveFirstAddedAt(false, { published: '2026-11-12T16:00:00Z' }, now), undefined);
  assert.equal(resolveFirstAddedAt(false, { _addedAt: '' }, now), undefined);
  assert.equal(resolveFirstAddedAt(false, { _addedAt: null }, now), undefined);
  assert.equal(resolveFirstAddedAt(false, null, now), undefined);
});

test('the native rolling-feed merge invokes the provenance guard instead of falling back to now', () => {
  const engine = fs.readFileSync(path.join(root, 'fetch-live-intel.js'), 'utf8');
  assert.match(engine, /const addedAt = resolveFirstAddedAt\(isNewToFeed, existingItem, nowTs\)/);
  assert.doesNotMatch(engine, /const addedAt = isNewToFeed \? nowTs : \(existingItem\?\._addedAt \|\| nowTs\)/);
});

// P0 November 22 — cross-check the durable publication ledger and archived
// posts before calling an evicted rolling-window record freshly ingested.
const {isFirstPlatformAddition,resolveFirstAddedAt:resolveFirstAddedAtForReentry}=require('../fetch-live-intel.js');
const firstAddNow='2026-11-22T05:32:25.400Z';
const firstAddStatus=(id,feed,ledger,post)=>isFirstPlatformAddition({
  id,presentInFeed:feed,presentInPublishedLedger:ledger,postFileExists:post
});
test('historical published record evicted from 150-item rolling feed is never artificially re-ingested',()=>{
  // Reproduced in the 2026-11-22 05:32 source corpus for 15 ledger-known
  // advisories absent from the previous top-150 window.
  assert.equal(firstAddStatus('CVE-2026-77309',false,true,false),false);
  assert.equal(resolveFirstAddedAtForReentry(firstAddStatus('CVE-2026-77309',false,true,false),null,firstAddNow),undefined);
});

test('existing archive post prevents false freshness when the published ledger entry has expired',()=>{
  assert.equal(firstAddStatus('CVE-2026-77309',false,false,true),false);
  assert.equal(resolveFirstAddedAtForReentry(firstAddStatus('CVE-2026-77309',false,false,true),null,firstAddNow),undefined);
});

test('rolling feed retains originally recorded ingestion timestamp without refresh',()=>{
  assert.equal(firstAddStatus('CVE-2026-77309',true,true,true),false);
  assert.equal(resolveFirstAddedAtForReentry(false,{_addedAt:'2026-11-20T08:00:00.000Z'},firstAddNow),'2026-11-20T08:00:00.000Z');
});

test('genuine first platform addition alone receives its current ingestion timestamp',()=>{
  assert.equal(firstAddStatus('new-first-party-evidence',false,false,false),true);
  assert.equal(resolveFirstAddedAtForReentry(true,null,firstAddNow),firstAddNow);
});

test('missing, ambiguous or invalid source history never promotes an item to fresh',()=>{
  assert.equal(isFirstPlatformAddition({id:'CVE-2026-77309'}),false);
  assert.equal(isFirstPlatformAddition({id:'' ,presentInFeed:false,presentInPublishedLedger:false,postFileExists:false}),false);
  assert.equal(isFirstPlatformAddition({id:null,presentInFeed:false,presentInPublishedLedger:false,postFileExists:false}),false);
  assert.equal(firstAddStatus('CVE-2026-77309',false,undefined,false),false);
  assert.equal(firstAddStatus('CVE-2026-77309',false,false,undefined),false);
  assert.equal(firstAddStatus('CVE-2026-77309',undefined,false,false),false);
});

test('actual publisher maps publication ledger and archive file into the provenance decision',()=>{
  const code=fs.readFileSync(path.join(__dirname,'../fetch-live-intel.js'),'utf8');
  assert.match(code,/presentInPublishedLedger:\s*previouslyPublishedIds\.has\(item\.id\)/);
  assert.match(code,/postFileExists:\s*fs\.existsSync\(path\.join\(CFG\.postsDir, `\$\{resolvedSlug\}\.html`\)\)/);
  assert.match(code,/if \(isNewToFeed\) genuinelyFirstAddedIds\.add\(item\.id\)/);
  assert.match(code,/const trulyNewCount = genuinelyFirstAddedIds\.size/);
  assert.match(code,/const addedAt = resolveFirstAddedAt\(isNewToFeed, existingItem, nowTs\)/);
});
