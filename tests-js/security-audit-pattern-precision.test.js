'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const wf = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'security-audit.yml'), 'utf8');

test('production secret detection remains fail-closed', () => {
  assert.match(wf, /if \[ "\$FOUND" -ne 0 \]; then/);
  assert.match(wf, /Production secret exposure gate FAILED/);
  assert.match(wf, /git grep -nE "\$pattern"/);
  assert.doesNotMatch(wf, /continue-on-error:\s*true/);
});

test('short threat-research PAT placeholders do not create false alarms', () => {
  const match = wf.match(/'github_pat_\[A-Za-z0-9_\]\{(\d+),\}'/);
  assert.ok(match, 'fine-grained GitHub PAT detection must retain a suffix-length floor');
  const min = Number(match[1]);
  assert.ok(min >= 20 && min <= 30, 'recognize opaque PAT suffixes without matching a short word');
  const regex = new RegExp('github_pat_[A-Za-z0-9_]{' + min + ',}');
  assert.equal(regex.test('%github_pat_token%'), false);
  assert.equal(regex.test('%github_pat_dummy%'), false);
  assert.equal(regex.test('github_pat_' + 'A'.repeat(min)), true);
  assert.equal(regex.test('Authorization: Bearer github_pat_' + 'a1_'.repeat(27)), true);
});

test('other production credential patterns and non-disclosure remain intact', () => {
  for (const value of [
    'sk_live_[A-Za-z0-9]+',
    'AKIA[A-Z0-9]{16}',
    'ghp_[A-Za-z0-9]{36}',
    'xox[baprs]-[A-Za-z0-9-]+'
  ]) assert.ok(wf.includes(value), 'required detector missing');
  assert.match(wf, /content withheld/);
  assert.doesNotMatch(wf, /echo "\$match"\s*\|/);
});
