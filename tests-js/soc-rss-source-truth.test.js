'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  validateRss, postPath, dateFromRss, MAX_RSS_ITEMS,
} = require('../scripts/verify-soc-rss-source-truth.cjs');
const {retainLatestRssItems, MAX_SOURCE_RSS_ITEMS} = require('../fetch-live-intel.js');

const ROOT = path.resolve(__dirname, '..');
const TODAY = 'Sat, 21 Nov 2026 06:35:00 GMT';
const OLD = 'Fri, 20 Nov 2026 10:00:00 GMT';
const NOW = Date.parse('2026-11-21T06:40:00Z');

function item(slug, date = OLD, guidSlug = slug) {
  const href = 'https://blog.cyberdudebivash.in/posts/' + slug + '.html';
  const guid = 'https://blog.cyberdudebivash.in/posts/' + guidSlug + '.html';
  return '<item><title>Evidence-bound report</title><link>' + href + '</link>' +
    '<guid isPermaLink="true">' + guid + '</guid><pubDate>' + date +
    '</pubDate></item>';
}
function feed(items, {channel = OLD, lastBuild = TODAY} = {}) {
  return '<?xml version="1.0"?>\n<rss version="2.0"><channel>' +
    '<title>SENTINEL APEX</title><lastBuildDate>' + lastBuild +
    '</lastBuildDate><pubDate>' + channel + '</pubDate>' +
    items.join('\n') + '</channel></rss>' +
    '<!-- test fixture padding ' + 'X'.repeat(530) + ' -->';
}
function check(xml, extra = {}) {
  return validateRss(xml, {nowMs:NOW, checkFiles:false, ...extra});
}
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'soc-rss-truth-'));
  fs.mkdirSync(path.join(root, 'posts'));
  t.after(() => fs.rmSync(root,{recursive:true,force:true}));
  return root;
}

test('source chronology: a valid canonical item passes read-only', () => {
  const result = check(feed([item('verified-report')]));
  assert.equal(result.status, 'PASS_READ_ONLY');
  assert.equal(result.itemCount, 1);
  assert.equal(result.checkedCanonical, 1);
});

test('source chronology: future source item and future header fail closed', () => {
  assert.equal(check(feed([item('future-report','Sat, 21 Nov 2026 12:00:00 GMT')])).status,'HOLD');
  assert.ok(check(feed([item('current')],{lastBuild:'Sun, 22 Nov 2026 12:00:00 GMT'}))
    .failureCodes.includes('CHANNEL_FRESHNESS_OR_DATE_INVALID'));
  assert.ok(check(feed([item('current')],{channel:'Sun, 22 Nov 2026 12:00:00 GMT'}))
    .failureCodes.includes('CHANNEL_FRESHNESS_OR_DATE_INVALID'));
});

test('RSS chronological gate rejects invalid or missing item publication dates', () => {
  assert.ok(check(feed([item('bad-date','not-a-date')]))
    .failureCodes.includes('POST_SOURCE_PUBLICATION_DATE_INVALID'));
  assert.ok(check(feed([item('bad-date','Sun, 22 Nov 2026 00:00:00 GMT')]))
    .failureCodes.includes('POST_SOURCE_PUBLICATION_DATE_INVALID'));
  assert.equal(dateFromRss('not a date',NOW),null);
});

test('RSS canonical source gate rejects wrong GUID, duplicate and unsafe links', () => {
  assert.ok(check(feed([item('a','Fri, 20 Nov 2026 10:00:00 GMT','b')]))
    .failureCodes.includes('POST_CANONICAL_OR_GUID_INVALID'));
  assert.ok(check(feed([item('a'),item('a')]))
    .failureCodes.includes('POST_CANONICAL_OR_GUID_INVALID'));
  assert.equal(postPath('https://evil.example/posts/a.html'),null);
  assert.equal(postPath('https://blog.cyberdudebivash.in/posts/%2e%2e%2fsecret.html'),null);
  assert.equal(postPath('https://blog.cyberdudebivash.in/posts/a.html?token=x'),null);
  assert.equal(postPath('javascript:alert(1)'),null);
});

test('bounded RSS refuses empty, malformed and oversized collections', () => {
  assert.equal(check(feed([])).reason,'RSS_ITEM_WINDOW_INVALID');
  assert.equal(check(feed(Array.from({length:MAX_RSS_ITEMS+1},(_,i)=>item('report-'+i))))
    .reason,'RSS_ITEM_WINDOW_INVALID');
  assert.equal(check('incomplete xml').reason,'RSS_SOURCE_FORMAT_OR_SIZE_INVALID');
});

test('canonical source must be real, bounded, non-symlink file',t => {
  const root = fixture(t), posts = path.join(root,'posts');
  const target = path.join(posts,'report.html');
  fs.writeFileSync(target,'<!DOCTYPE html><html><body>'+'E'.repeat(110)+'</body></html>');
  assert.equal(check(feed([item('report')]),{root,checkFiles:true}).status,'PASS_READ_ONLY');
  fs.rmSync(target);
  assert.ok(check(feed([item('report')]),{root,checkFiles:true})
    .failureCodes.includes('POST_SOURCE_FILE_MISSING'));
  fs.writeFileSync(path.join(root,'alternate.html'),'<!DOCTYPE html>'+'X'.repeat(110));
  fs.symlinkSync(path.join(root,'alternate.html'),target);
  assert.ok(check(feed([item('report')]),{root,checkFiles:true})
    .failureCodes.includes('POST_SOURCE_FILE_INVALID'));
});

test('source publisher bounds RSS history while retaining newest item order', () => {
  const cases = Array.from({length:60},(_,i)=>item('report-'+i));
  const before = feed(cases), after = retainLatestRssItems(before);
  assert.equal(MAX_SOURCE_RSS_ITEMS,50);
  assert.equal((after.match(/<item>/g)||[]).length,50);
  assert.ok(after.includes('/posts/report-0.html'));
  assert.ok(after.includes('/posts/report-49.html'));
  assert.ok(!after.includes('/posts/report-50.html'));
  assert.equal(retainLatestRssItems(after),after,'bounded source is idempotent');
  assert.equal(retainLatestRssItems(feed(cases.slice(0,2))),feed(cases.slice(0,2)));
  assert.throws(()=>retainLatestRssItems(before,0),/RSS_WINDOW_BOUNDS_INVALID/);
});

test('secondary RSS workflow has no scheduled/main writing authority',()=>{
  const workflow = fs.readFileSync(path.join(ROOT,'.github/workflows/generate-rss.yml'),'utf8');
  assert.match(workflow,/permissions:\s*\n\s*contents:\s*read/);
  assert.doesNotMatch(workflow,/(?:^|\n)\s*schedule\s*:/m);
  assert.doesNotMatch(workflow,/(?:^|\n)\s*contents\s*:\s*write/m);
  assert.doesNotMatch(workflow,/\bgit\s+(?:commit|push|pull|reset)\b/);
  assert.doesNotMatch(workflow,/node\s+generate-rss\.js/);
  assert.match(workflow,/node scripts\/verify-soc-rss-source-truth\.cjs/);
});

test('checked-in RSS and canonical post files pass source truth independent of edge',()=>{
  const rss=fs.readFileSync(path.join(ROOT,'rss.xml'),'utf8');
  const result=validateRss(rss,{root:ROOT});
  assert.deepEqual(result.failureCodes,[],JSON.stringify(result));
  assert.equal(result.status,'PASS_READ_ONLY');
  assert.ok(result.itemCount>=3);
});


test('global workflow security policy revokes secondary RSS contents-write allowance',()=>{
  const policy = fs.readFileSync(path.join(ROOT,'.github/workflows/workflow-security-gate.yml'),'utf8');
  const begin = policy.indexOf('content_writers = {');
  const end = policy.indexOf('}',begin);
  assert.ok(begin > 0 && end > begin,'security allowlist must remain identifiable');
  const writers = policy.slice(begin,end);
  assert.doesNotMatch(writers, /['"]generate-rss\.yml['"]/);
  assert.match(policy, /contents:write is not in the approved writer allowlist/);
});
