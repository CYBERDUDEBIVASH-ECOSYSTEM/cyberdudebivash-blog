'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { renderRssItem } = require('../fetch-live-intel.js');

const source = {
  slug: 'byod-ransomware-hospitals',
  title: 'BYOD ransomware: hospital and university disruption',
  type: 'RANSOMWARE',
  priority: 33,
  threatLevel: 'LOW',
  cvss: null,
  pubDate: '2026-11-20T14:54:58+00:00',
  desc: 'Staff reported an audible ransom demand; impact remains under investigation.',
};

test('non-CVE threat RSS never serializes null CVSS or guarantees absent IOCs/rules', () => {
  const result = renderRssItem(source);
  assert.match(result, /Platform triage priority 33\/100 \(LOW\)/);
  assert.doesNotMatch(result, /\bCVSS\b|\bnull\b/i);
  assert.doesNotMatch(result, /Sigma\/YARA rules|Full analysis,|Attack Chain by/);
  assert.match(result, /any available detection guidance/);
  assert.match(result, /<category>RANSOMWARE<\/category>/);
});

test('source publication date is preserved rather than overwritten with feed build time', () => {
  assert.match(renderRssItem(source), /<pubDate>Fri, 20 Nov 2026 14:54:58 GMT<\/pubDate>/);
});

test('a CVE item with an authoritative numeric CVSS retains the score', () => {
  const result = renderRssItem({ ...source, type: 'CVE_REPORT', cvss: 9.8 });
  assert.match(result, /CVSS 9\.8/);
  assert.match(result, /<category>CVE_REPORT<\/category>/);
});

test('non-numeric and out-of-range CVSS never leak to the public feed', () => {
  for (const value of [null, undefined, 'null', '9.8', Infinity, -1, 11]) {
    const result = renderRssItem({ ...source, type: 'CVE_REPORT', cvss: value });
    assert.doesNotMatch(result, /\bCVSS\b|\bnull\b/i, String(value));
  }
});

test('undated and future-dated reports never inherit a fabricated current timestamp', () => {
  for (const date of [null, '', 'unknown', new Date(Date.now() + 2 * 86400000).toISOString()]) {
    assert.doesNotMatch(renderRssItem({ ...source, pubDate: date }), /<pubDate>/);
  }
});

test('title and description CDATA delimiters cannot break XML context', () => {
  const result = renderRssItem({ ...source, title: 'title]]><script>bad</script>',
    desc: 'sample]]><script>bad</script>' });
  assert.match(result, /title\]\]\]\]><!\[CDATA\[><script>/);
  assert.match(result, /sample\]\]\]\]><!\[CDATA\[><script>/);
  assert.equal((result.match(/<item>/g) || []).length, 1);
});

test('untrusted slug is rejected instead of creating a malicious link', () => {
  for (const slug of ['../outside', 'http://evil.example', 'a?x=1', '', 'x'.repeat(152)]) {
    assert.equal(renderRssItem({ ...source, slug }), '', slug);
  }
});

test('advisory category cannot inject XML tags', () => {
  const result = renderRssItem({ ...source, type: '<malicious attr="x">&bad' });
  assert.match(result, /&lt;malicious attr=&quot;x&quot;&gt;&amp;bad/);
  assert.doesNotMatch(result, /<malicious/);
});
