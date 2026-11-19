'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const source = fs.readFileSync(
  path.join(root, '.github/workflows/blogger-syndication.yml'), 'utf8'
);

// Dependency-free strict validation runs in the isolated Node engine CI,
// where repository-root js-yaml is NOT installed. GitHub rejected duplicate
// keys in this exact mapping with HTTP 422. Test every env mapping, plus
// precise preflight/publisher guard values, before release.
function envMappings(text) {
  const lines = text.split(/\r?\n/);
  const blocks = [];
  for (let i = 0; i < lines.length; i += 1) {
    const match = /^(\s*)env:\s*$/.exec(lines[i]);
    if (!match) continue;
    const indent = match[1].length;
    const entries = Object.create(null);
    for (let j = i + 1; j < lines.length; j += 1) {
      const line = lines[j];
      if (/^\s*(?:#.*)?$/.test(line)) continue;
      const offset = /^\s*/.exec(line)[0].length;
      if (offset <= indent) break;
      const m = new RegExp('^\\s{' + (indent + 2) + '}([A-Za-z_][A-Za-z_0-9]*):\\s*(.*)$').exec(line);
      if (!m) continue;
      assert.ok(!Object.hasOwn(entries, m[1]),
        'duplicate YAML env key ' + m[1] + ' near line ' + (j + 1));
      entries[m[1]] = m[2];
    }
    blocks.push({ line: i + 1, entries });
  }
  return blocks;
}

function stepText(name) {
  const marker = '      - name: "' + name + '"';
  const start = source.indexOf(marker);
  assert.ok(start >= 0, 'step missing: ' + name);
  const end = source.indexOf('\n      - name:', start + marker.length);
  return source.slice(start, end >= 0 ? end : undefined);
}

const expected = Object.freeze({
  CDB_BLOGGER_OAUTH_READY: "${{ vars.BLOGGER_OAUTH_READY }}",
  CDB_BLOGGER_CANARY_APPROVED: "${{ github.event.inputs.live_canary_approved || 'false' }}",
  CDB_BLOGGER_DRY_RUN_INPUT: "${{ github.event.inputs.dry_run || 'true' }}",
  MAX_POSTS_PER_RUN: "${{ github.event.inputs.max_posts || '4' }}",
});

test('all Blogger YAML environment mappings reject duplicate keys (GitHub 422 regression)', () => {
  const blocks = envMappings(source);
  assert.ok(blocks.length >= 2, 'expected two protected publisher env blocks');
});

test('early and pre-publish guards receive identical authorization variables', () => {
  const pre = stepText('P0 authorize Blogger dispatch before installing dependencies');
  const pub = stepText('⚡ Run Premium Syndication Pipeline');
  const a = envMappings(pre);
  const b = envMappings(pub);
  assert.equal(a.length, 1, 'early guard env');
  assert.equal(b.length, 1, 'publisher guard env');
  for (const [key, val] of Object.entries(expected)) {
    assert.equal(a[0].entries[key], val, 'preflight ' + key);
    assert.equal(b[0].entries[key], val, 'publisher ' + key);
  }
  assert.match(pre, /run: bash scripts\/blogger-live-dispatch-guard\.sh/);
  assert.match(pub, /\. \.\/scripts\/blogger-live-dispatch-guard\.sh/);
});

test('manual canary default remains false and omitted dry_run remains safe', () => {
  const top = source.slice(0, source.indexOf('\n# P0-BLOGGER-FRESHNESS'));
  assert.match(top, /dry_run:[\s\S]*?default: "true"/);
  assert.match(top, /max_posts:[\s\S]*?default: "1"/);
  assert.match(top, /live_canary_approved:[\s\S]*?default: "false"/);
  assert.match(source, /vars\.BLOGGER_OAUTH_READY == 'true'/);
});

test('duplicate env mapping sample reproduces strict validation failure', () => {
  const bad = 'env:\n  CDB_BLOGGER_OAUTH_READY: first\n  CDB_BLOGGER_OAUTH_READY: second\n';
  assert.throws(() => envMappings(bad), /duplicate YAML env key CDB_BLOGGER_OAUTH_READY/);
});
