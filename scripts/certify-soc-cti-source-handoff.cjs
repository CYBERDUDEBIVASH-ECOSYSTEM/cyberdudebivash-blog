#!/usr/bin/env node
'use strict';
/**
 * P0 SOC→Blogger source-delivery release gate.
 *
 * A fresh RSS / GitHub post is not customer-visible evidence. The protected
 * Cloudflare release must include real recent source dossiers as exact
 * allowlisted static assets on BOTH existing Custom Domains. Offline
 * predeploy and bounded, independent postdeploy checks use no credentials,
 * customer data, paid services, mutation or Blogger writes.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const HOSTS = Object.freeze(['soc.cyberdudebivash.in', 'blog.cyberdudebivash.in']);
const SOURCE_HOST = 'blog.cyberdudebivash.in';
const SHA = /^[a-f0-9]{40}$/i;
const POST_PATH = /^\/posts\/[a-z0-9][a-z0-9-]{0,119}\.html$/;
const MAX_POST_BYTES = 512 * 1024;
const SAMPLE_COUNT = 3;
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function latestCanonicalPosts(rssText, limit = SAMPLE_COUNT) {
  if (typeof rssText !== 'string' || rssText.length === 0 || rssText.length > 2 * 1024 * 1024) {
    throw Error('SOURCE_RSS_INVALID');
  }
  const items = rssText.match(/<item\b[^>]*>[\s\S]*?<\/item>/gi) || [];
  const selected = [], seen = new Set();
  for (const item of items.slice(0, 300)) {
    const href = item.match(/<link>\s*(https:\/\/[^<\s]+)\s*<\/link>/i)?.[1];
    if (!href) continue;
    let parsed;
    try { parsed = new URL(href); } catch { continue; }
    if (parsed.protocol !== 'https:' || parsed.hostname !== SOURCE_HOST ||
        parsed.port || parsed.username || parsed.password || parsed.search || parsed.hash ||
        !POST_PATH.test(parsed.pathname) || seen.has(parsed.pathname)) continue;
    seen.add(parsed.pathname);
    selected.push(parsed.pathname);
    if (selected.length >= limit) break;
  }
  if (selected.length < limit) throw Error('NOT_ENOUGH_CANONICAL_SOURCE_POSTS');
  return selected;
}

function expectedPosts({root = path.resolve(__dirname, '..'), readFile = fs.readFileSync} = {}) {
  const rssText = readFile(path.join(root, 'rss.xml'), 'utf8');
  const selected = latestCanonicalPosts(rssText);
  return selected.map(urlPath => {
    const file = path.join(root, 'dist-public', urlPath.slice(1));
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 80 || stat.size > MAX_POST_BYTES)
      throw Error('SOURCE_BUILD_POST_INVALID');
    const bytes = readFile(file);
    if (!Buffer.isBuffer(bytes) || bytes.length !== stat.size)
      throw Error('SOURCE_BUILD_POST_BYTES_INVALID');
    return {urlPath, size: bytes.length, digest: hash(bytes)};
  });
}

async function readBounded(response) {
  if (!response.body || typeof response.body.getReader !== 'function') throw Error('PUBLIC_POST_STREAM_MISSING');
  const reader = response.body.getReader(), parts = [];
  let total = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.byteLength;
      if (total > MAX_POST_BYTES) throw Error('PUBLIC_POST_TOO_LARGE');
      parts.push(Buffer.from(next.value));
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  return Buffer.concat(parts, total);
}

function verifyPost({status, contentType, body, digest} = {}) {
  if (status !== 200) return 'PUBLIC_POST_HTTP_NOT_200';
  if (!/^text\/html(?:\s*;|\s*$)/i.test(contentType || '')) return 'PUBLIC_POST_CONTENT_TYPE_INVALID';
  if (!Buffer.isBuffer(body) || body.length < 80 || body.length > MAX_POST_BYTES)
    return 'PUBLIC_POST_BYTES_INVALID';
  if (hash(body) !== digest) return 'PUBLIC_POST_SOURCE_BUILD_MISMATCH';
  return 'PUBLIC_POST_EXACT_SOURCE_PARITY';
}

async function certify({
  releaseSha, root, fetchImpl = globalThis.fetch, readFile = fs.readFileSync
} = {}) {
  if (!SHA.test(releaseSha || '') || typeof fetchImpl !== 'function') {
    return {status:'HOLD', reason:'RELEASE_SHA_OR_NETWORK_INVALID'};
  }
  let posts;
  try { posts = expectedPosts({root, readFile}); }
  catch (error) { return {status:'HOLD', reason:'SOURCE_BUILD_POST_SELECTION_FAILED', detail:error.message}; }
  const results = [];
  for (const host of HOSTS) {
    for (const post of posts) {
      const url = new URL('https://' + host + post.urlPath);
      url.searchParams.set('release_sha', releaseSha);
      let code = 'PUBLIC_POST_REQUEST_UNAVAILABLE';
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const response = await fetchImpl(url, {
            method:'GET', redirect:'manual', signal:AbortSignal.timeout(12000),
            headers:{Accept:'text/html','Cache-Control':'no-cache'}
          });
          if (response.status !== 200) {
            code = 'PUBLIC_POST_HTTP_NOT_200';
          } else {
            const body = await readBounded(response);
            code = verifyPost({
              status:response.status,
              contentType:response.headers.get('content-type'),
              body, digest:post.digest
            });
          }
          if (code === 'PUBLIC_POST_EXACT_SOURCE_PARITY') break;
        } catch (error) {
          code = error.message === 'PUBLIC_POST_TOO_LARGE'
            ? 'PUBLIC_POST_TOO_LARGE' : 'PUBLIC_POST_REQUEST_UNAVAILABLE';
        }
      }
      results.push({host, source:post.urlPath, code,
        verdict:code === 'PUBLIC_POST_EXACT_SOURCE_PARITY' ? 'PASS' : 'FAIL'});
    }
  }
  const pass = results.every(x => x.verdict === 'PASS');
  return {status:pass ? 'PASS_NOT_RELEASE_AUTHORIZATION' : 'HOLD',
    samples:posts.length, checked:results.length,
    failures:results.filter(x => x.verdict !== 'PASS')};
}

function predeploy({root} = {}) {
  try {
    const posts = expectedPosts({root});
    return {status:'PASS_NOT_RELEASE_AUTHORIZATION', verifiedBuildPosts:posts.length};
  } catch (error) {
    return {status:'HOLD', reason:error.message};
  }
}

if (require.main === module) {
  const mode = process.argv[2];
  if (!['--predeploy','--release-asset'].includes(mode) || process.argv.length !== 3) {
    console.error('USAGE: node scripts/certify-soc-cti-source-handoff.cjs --predeploy|--release-asset');
    process.exitCode = 2;
  } else {
    const p = mode === '--predeploy'
      ? Promise.resolve(predeploy())
      : certify({releaseSha:process.env.GITHUB_SHA});
    p.then(result => {
      console.log('P0_SOC_CTI_SOURCE_HANDOFF=' + JSON.stringify(result));
      if (result.status !== 'PASS_NOT_RELEASE_AUTHORIZATION') process.exitCode = 2;
    }).catch(() => {
      console.error('HOLD: SOC_CTI_SOURCE_HANDOFF_UNAVAILABLE');
      process.exitCode = 2;
    });
  }
}
module.exports = {HOSTS, SOURCE_HOST, MAX_POST_BYTES, SAMPLE_COUNT,
  latestCanonicalPosts, expectedPosts, verifyPost, readBounded, predeploy, certify};
