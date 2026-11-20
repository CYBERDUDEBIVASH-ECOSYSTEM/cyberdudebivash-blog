'use strict';
/**
 * First-party outbound-link defense in depth for Ahmed #015/#017 / AI Hub #1201.
 * This does not attest third-party Facebook account remediation or research closure.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ROOT = path.resolve(__dirname, '..');
const RETIRED_PAGE_ID = '61583373732736';
const RETIRED_PAGE_VANITY = /https?:\/\/(?:(?:www|m)\.)?facebook\.com\/(?:cyberdudebivash|cyberbivash)(?:\b|\/)/i;
function htmlFiles(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return htmlFiles(full);
    return entry.isFile() && entry.name.endsWith('.html') ? [full] : [];
  });
}
test('SOC public HTML does not link to unverified Facebook Page A', () => {
  const paths = [
    path.join(ROOT, 'index.html'),
    path.join(ROOT, 'intelligence.html'),
    ...htmlFiles(path.join(ROOT, 'posts')),
  ];
  assert.ok(paths.length >= 9, 'SOC public HTML inventory must be present');
  for (const file of paths) {
    const html = fs.readFileSync(file, 'utf8');
    assert.equal(html.includes(RETIRED_PAGE_ID), false, path.relative(ROOT, file));
    assert.doesNotMatch(html, RETIRED_PAGE_VANITY, path.relative(ROOT, file));
  }
});
test('Blogger theme templates do not link to or embed unverified Facebook Page A', () => {
  // The Blogger theme is a separate publishing surface from the Cloudflare-served HTML above.
  // It previously carried the page id in JSON-LD sameAs, the footer social buttons and the contact grid.
  const dir = path.join(ROOT, 'blogger-theme');
  const themes = fs.readdirSync(dir).filter(name => name.endsWith('.xml'));
  assert.ok(themes.length >= 1, 'Blogger theme inventory must be present');
  for (const name of themes) {
    const xml = fs.readFileSync(path.join(dir, name), 'utf8');
    assert.equal(xml.includes(RETIRED_PAGE_ID), false, `blogger-theme/${name}`);
    assert.doesNotMatch(xml, RETIRED_PAGE_VANITY, `blogger-theme/${name}`);
    assert.doesNotMatch(xml, /facebook\.com\/profile\.php/i, `blogger-theme/${name}`);
  }
});
test('P0: immutable dual-host parity includes BOTH root homepages, not only SOC workspace assets', () => {
  const {ASSETS, HOSTS} = require('./certify-soc-dual-host-ui-release.cjs');
  assert.deepEqual(HOSTS, ['soc.cyberdudebivash.in', 'blog.cyberdudebivash.in']);
  const byUrl = new Map(ASSETS.map(item => [item.url, item]));
  assert.equal(byUrl.get('/')?.file, 'index.html');
  assert.equal(byUrl.get('/intelligence.html')?.file, 'intelligence.html');
  assert.equal(byUrl.get('/soc.html')?.file, 'soc.html');
  assert.ok(ASSETS.every(item => item.type === 'html' || item.type === 'javascript' || item.type === 'css'));
});

test('SOC homepage retains first-party approved identities and valid structured data', () => {
  const html = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  assert.match(html, /https:\/\/www\.linkedin\.com\/company\/cyberdudebivash\//);
  assert.match(html, /https:\/\/www\.instagram\.com\/cyberdudebivash_official\//);
  const blocks = [...html.matchAll(/<script\b[^>]*type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/g)];
  assert.ok(blocks.length > 0, 'structured data must remain available');
  for (const [, json] of blocks) assert.doesNotThrow(() => JSON.parse(json));
});
