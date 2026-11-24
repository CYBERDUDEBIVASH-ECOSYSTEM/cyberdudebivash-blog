'use strict';
// A serialized publisher run must publish from the branch head at job start, never from the SHA of the
// commit that triggered it. Incident 2026-11-24: run 9301 queued behind run 9300 (concurrency group),
// checked out its older trigger SHA (publication ledger of 6816 posts instead of 6820) and re-posted
// LiteLLM, VMware vCenter and BADBOX 3.0 four minutes after run 9300 had published them.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const wf = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'blogger-syndication.yml'), 'utf8');

const checkout = () => wf.split('- name: "📥 Checkout Repository"')[1].split('- name: "P0 authorize Blogger dispatch')[0];

test('the publisher checkout resolves the branch head (github.ref), not the trigger SHA', () => {
  const step = checkout();
  assert.match(step, /actions\/checkout@[0-9a-f]{40}/, 'checkout stays pinned to a full commit SHA');
  assert.match(step, /\n\s+ref: \$\{\{ github\.ref \}\}\n/);
  assert.doesNotMatch(step, /ref: \$\{\{ github\.sha \}\}/);
  assert.doesNotMatch(step, /ref: \$\{\{ github\.event\.after \}\}/);
});

test('the safeguards this relies on are unchanged: main-only job, serialized writer, rebase-before-push', () => {
  assert.match(wf, /if: \$\{\{ github\.ref == 'refs\/heads\/main' && /);
  assert.match(wf, /group: blogger-syndication-writer\n\s+cancel-in-progress: false/);
  assert.match(wf, /git pull --rebase origin main --quiet/);
  assert.match(wf, /fetch-depth: 1/);
  assert.match(wf, /token: \$\{\{ secrets\.GITHUB_TOKEN \}\}/);
});

test('the explanation of why stays next to the line so it is not "cleaned up" later', () => {
  assert.match(checkout(), /never the trigger SHA/);
  assert.match(checkout(), /publication-state commit/);
});
