'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {latestCanonicalPosts, expectedPosts, verifyPost, predeploy, certify, HOSTS} =
  require('../scripts/certify-soc-cti-source-handoff.cjs');

const SHA = 'a'.repeat(40);
const PATHS = ['/posts/report-one.html', '/posts/report-two.html', '/posts/report-three.html'];
const TEXT = '<html><head><title>Verified source</title></head><body><main>' +
  'Authentic immutable SOC source dossier evidence '.repeat(10) + '</main></body></html>';

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cdb-handoff-'));
  fs.mkdirSync(path.join(root, 'dist-public', 'posts'), {recursive:true});
  for (const p of PATHS) fs.writeFileSync(path.join(root, 'dist-public', p.slice(1)), TEXT);
  const rss = '<rss><channel>' + PATHS.map(p =>
    '<item><title>Report</title><link>https://blog.cyberdudebivash.in' + p + '</link></item>'
  ).join('') + '</channel></rss>';
  fs.writeFileSync(path.join(root, 'rss.xml'), rss);
  return root;
}
function cleanup(root) {fs.rmSync(root, {recursive:true, force:true});}

test('select only three canonical first-party HTML reports from RSS', () => {
  const rss = '<item><link>https://evil.example/posts/bad.html</link></item>' +
    '<item><link>https://blog.cyberdudebivash.in/posts/report-one.html</link></item>' +
    '<item><link>https://blog.cyberdudebivash.in/posts/report-one.html</link></item>' +
    '<item><link>https://blog.cyberdudebivash.in/posts/report-two.html</link></item>' +
    '<item><link>https://blog.cyberdudebivash.in/posts/report-three.html</link></item>';
  assert.deepEqual(latestCanonicalPosts(rss), PATHS);
});

test('bad RSS and insufficient canonical reports hold the release', () => {
  assert.throws(() => latestCanonicalPosts(''), /SOURCE_RSS_INVALID/);
  assert.throws(() => latestCanonicalPosts('<rss><item>bad</item></rss>'), /NOT_ENOUGH_CANONICAL_SOURCE_POSTS/);
});

test('offline predeploy requires all three real build posts', () => {
  const root = fixture();
  try {
    assert.equal(predeploy({root}).verifiedBuildPosts, 3);
    assert.equal(expectedPosts({root}).length, 3);
    fs.rmSync(path.join(root, 'dist-public', 'posts', 'report-one.html'));
    assert.equal(predeploy({root}).status, 'HOLD');
  } finally {cleanup(root);}
});

test('symlinked source asset cannot pass', () => {
  const root = fixture();
  try {
    const p = path.join(root,'dist-public','posts','report-one.html');
    fs.rmSync(p);
    fs.symlinkSync(path.join(root,'dist-public','posts','report-two.html'),p);
    assert.equal(predeploy({root}).status,'HOLD');
  } finally {cleanup(root);}
});

test('content type, HTTP status and actual bytes are all mandatory', () => {
  const root = fixture();
  try {
    const p = expectedPosts({root})[0];
    assert.equal(verifyPost({status:404,contentType:'text/html',body:Buffer.from(TEXT),digest:p.digest}),
      'PUBLIC_POST_HTTP_NOT_200');
    assert.equal(verifyPost({status:200,contentType:'application/json',body:Buffer.from(TEXT),digest:p.digest}),
      'PUBLIC_POST_CONTENT_TYPE_INVALID');
    assert.equal(verifyPost({status:200,contentType:'text/html',body:Buffer.from(TEXT+'mutated'),digest:p.digest}),
      'PUBLIC_POST_SOURCE_BUILD_MISMATCH');
    assert.equal(verifyPost({status:200,contentType:'text/html',body:Buffer.from(TEXT),digest:p.digest}),
      'PUBLIC_POST_EXACT_SOURCE_PARITY');
  } finally {cleanup(root);}
});

test('all six exact post bytes must be visible across BOTH public SOC hosts', async () => {
  const root = fixture(), calls = [];
  try {
    const fetchImpl = async (url, options) => {
      calls.push({url:String(url),options});
      assert.equal(options.redirect, 'manual');
      assert.equal(url.searchParams.get('release_sha'),SHA);
      return new Response(TEXT,{status:200,headers:{'Content-Type':'text/html;charset=UTF-8'}});
    };
    const result = await certify({root,releaseSha:SHA,fetchImpl});
    assert.equal(result.status,'PASS_NOT_RELEASE_AUTHORIZATION');
    assert.equal(result.checked,6);
    assert.deepEqual([...new Set(calls.map(c=>new URL(c.url).hostname))],HOSTS);
  } finally {cleanup(root);}
});

test('no other successful assets hide a 404 on a customer-facing source path', async () => {
  const root = fixture();
  try {
    const result = await certify({root,releaseSha:SHA,
      fetchImpl:async (url) => new Response(TEXT,{
        status:url.hostname===HOSTS[0]&&url.pathname===PATHS[0]?404:200,
        headers:{'Content-Type':'text/html'}
      })
    });
    assert.equal(result.status,'HOLD');
    assert.ok(result.failures.some(v=>v.code==='PUBLIC_POST_HTTP_NOT_200'));
  } finally {cleanup(root);}
});

test('a content substitution under HTTP 200 is never accepted', async () => {
  const root = fixture();
  try {
    const result = await certify({root,releaseSha:SHA,
      fetchImpl:async url=>new Response(url.pathname===PATHS[1]?TEXT+'malicious-edit':TEXT,
        {status:200,headers:{'Content-Type':'text/html'}})
    });
    assert.equal(result.status,'HOLD');
    assert.ok(result.failures.some(v=>v.code==='PUBLIC_POST_SOURCE_BUILD_MISMATCH'));
  } finally {cleanup(root);}
});

test('missing immutable approval SHA holds before any HTTP request', async () => {
  const result = await certify({releaseSha:'main',fetchImpl:()=>{throw Error('should not fetch');}});
  assert.equal(result.reason,'RELEASE_SHA_OR_NETWORK_INVALID');
});
