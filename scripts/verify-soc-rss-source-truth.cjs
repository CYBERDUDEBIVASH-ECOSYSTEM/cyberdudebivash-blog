#!/usr/bin/env node
'use strict';
/**
 * Read-only source-RSS release integrity. The source publisher is the only
 * authorized writer: this script NEVER regenerates or overwrites rss.xml.
 * It validates bounded public dates, canonical source post identities and
 * local source-file existence before an RSS change can be treated as healthy.
 */
const fs = require('node:fs');
const path = require('node:path');

const SOURCE_HOST = 'blog.cyberdudebivash.in';
const SOURCE_PATH = /^\/posts\/[a-z0-9][a-z0-9-]{0,150}\.html$/;
const MAX_RSS_BYTES = 2 * 1024 * 1024;
const MAX_POST_BYTES = 512 * 1024;
const MAX_RSS_ITEMS = 100; // migration headroom; the publisher targets 50
const CLOCK_SKEW_MS = 5 * 60 * 1000;

function onlyTag(xml, name) {
  const found = xml.match(new RegExp('<' + name + '>([^<]*)</' + name + '>', 'gi')) || [];
  if (found.length !== 1) return null;
  return found[0].replace(new RegExp('^<' + name + '>|</' + name + '>$', 'gi'), '').trim();
}
function dateFromRss(value, nowMs) {
  if (typeof value !== 'string' || !value.trim()) return null;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || parsed < Date.UTC(2000, 0, 1) ||
      parsed > nowMs + CLOCK_SKEW_MS) return null;
  return parsed;
}
function postPath(href) {
  let url;
  try { url = new URL(href); } catch { return null; }
  if (url.protocol !== 'https:' || url.hostname !== SOURCE_HOST ||
      url.username || url.password || url.port || url.search || url.hash ||
      !SOURCE_PATH.test(url.pathname)) return null;
  return url.pathname;
}

function validateRss(xml, {nowMs = Date.now(), root = path.resolve(__dirname, '..'),
                           checkFiles = true} = {}) {
  const failures = [];
  if (typeof xml !== 'string' || Buffer.byteLength(xml, 'utf8') < 500 ||
      Buffer.byteLength(xml, 'utf8') > MAX_RSS_BYTES ||
      !/<rss\s+version="2\.0"/i.test(xml) || !/<channel>/i.test(xml) ||
      !/<\/channel>/i.test(xml) || !/<\/rss>/i.test(xml)) {
    return {status:'HOLD', reason:'RSS_SOURCE_FORMAT_OR_SIZE_INVALID', itemCount:0};
  }
  const items = [...xml.matchAll(/<item(?:\s[^>]*)?>([\s\S]*?)<\/item>/gi)]
    .map(m => m[1]);
  if (!items.length || items.length > MAX_RSS_ITEMS)
    return {status:'HOLD', reason:'RSS_ITEM_WINDOW_INVALID', itemCount:items.length};

  const channelText = xml.slice(xml.indexOf('<channel>') + '<channel>'.length,
                                xml.indexOf('<item'));
  const lastBuild = dateFromRss(onlyTag(channelText, 'lastBuildDate'), nowMs);
  const publication = dateFromRss(onlyTag(channelText, 'pubDate'), nowMs);
  if (lastBuild === null || (publication !== null &&
       publication > lastBuild + CLOCK_SKEW_MS)) {
    failures.push('CHANNEL_FRESHNESS_OR_DATE_INVALID');
  }
  const seen = new Set();
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    const href = onlyTag(item, 'link');
    const guidMatch = item.match(/<guid(?:\s+[^>]*)?>([^<]*)<\/guid>/gi) || [];
    const guid = guidMatch.length === 1
      ? guidMatch[0].replace(/^<guid(?:\s+[^>]*)?>|<\/guid>$/gi, '').trim()
      : null;
    const localPath = postPath(href);
    const published = dateFromRss(onlyTag(item, 'pubDate'), nowMs);
    if (!localPath || !guid || guid !== href || seen.has(localPath)) {
      failures.push('POST_CANONICAL_OR_GUID_INVALID');
      continue;
    }
    seen.add(localPath);
    if (published === null || (lastBuild !== null &&
        published > lastBuild + CLOCK_SKEW_MS)) {
      failures.push('POST_SOURCE_PUBLICATION_DATE_INVALID');
    }
    if (checkFiles) {
      try {
        const file = path.join(root, localPath.slice(1));
        const st = fs.lstatSync(file);
        if (!st.isFile() || st.isSymbolicLink() ||
            st.size < 80 || st.size > MAX_POST_BYTES) {
          failures.push('POST_SOURCE_FILE_INVALID');
        }
      } catch {
        failures.push('POST_SOURCE_FILE_MISSING');
      }
    }
  }
  const deduped = [...new Set(failures)];
  return {status:deduped.length ? 'HOLD' : 'PASS_READ_ONLY',
    itemCount:items.length, checkedCanonical:seen.size,
    lastBuildDate: lastBuild === null ? null : new Date(lastBuild).toISOString(),
    failureCodes:deduped};
}

function main() {
  const root = path.resolve(__dirname, '..');
  let result;
  try {
    const text = fs.readFileSync(path.join(root, 'rss.xml'), 'utf8');
    result = validateRss(text, {root});
  } catch {
    result = {status:'HOLD', reason:'SOURCE_RSS_READ_FAILED'};
  }
  process.stdout.write('SOC_RSS_SOURCE_TRUTH=' + JSON.stringify(result) + '\n');
  if (result.status !== 'PASS_READ_ONLY') process.exitCode = 2;
}
if (require.main === module) main();
module.exports = {SOURCE_HOST, SOURCE_PATH, MAX_RSS_BYTES, MAX_RSS_ITEMS,
  CLOCK_SKEW_MS, dateFromRss, postPath, validateRss};
