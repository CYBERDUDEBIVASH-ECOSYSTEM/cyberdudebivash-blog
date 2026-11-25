'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const { parseNameStatusZ, preflight } = require('../scripts/production-drift-preflight.cjs');
const { isReviewedOperationalPath, isKnownBenignPath } = require('../scripts/production-drift-policy.cjs');

const root = path.resolve(__dirname, '..');
const SCRIPT = path.join(root, 'scripts/production-drift-preflight.cjs');
const DEPLOY = '.github/workflows/cloudflare-production-deploy.yml';

function makeRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'drift-preflight-'));
  const sh = (...args) => execFileSync('git', args, { cwd: dir, encoding: 'utf8' }).trim();
  sh('init', '-q', '-b', 'main');
  sh('config', 'user.email', 'preflight@example.invalid');
  sh('config', 'user.name', 'preflight');
  sh('config', 'commit.gpgsign', 'false');
  fs.mkdirSync(path.join(dir, '.github/workflows'), { recursive: true });
  // The REAL deploy workflow gives the classifier its production path patterns (the policy needs 20 or more).
  fs.copyFileSync(path.join(root, DEPLOY), path.join(dir, DEPLOY));
  sh('add', '-A');
  sh('commit', '-q', '-m', 'base');
  const write = (files) => {
    for (const [name, body] of Object.entries(files)) {
      fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
      fs.writeFileSync(path.join(dir, name), body);
    }
  };
  const commit = (files, message = 'change') => { write(files); sh('add', '-A'); sh('commit', '-q', '-m', message); return sh('rev-parse', 'HEAD'); };
  const run = (base, head) => preflight({ base, head, cwd: dir, deployWorkflow: DEPLOY });
  return { dir, sh, commit, run, tip: () => sh('rev-parse', 'HEAD'), cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('name-status parsing covers add, modify, delete, type change, rename and copy', () => {
  const out = ['A', 'a.txt', 'M', 'b.txt', 'D', 'c.txt', 'T', 'd.txt', 'R097', 'old.txt', 'new.txt', 'C075', 'src.txt', 'dup.txt', ''].join('\0');
  assert.deepEqual(parseNameStatusZ(out), [
    { filename: 'a.txt', status: 'added' },
    { filename: 'b.txt', status: 'modified' },
    { filename: 'c.txt', status: 'removed' },
    { filename: 'd.txt', status: 'changed' },
    { filename: 'new.txt', previous_filename: 'old.txt', status: 'renamed' },
    { filename: 'dup.txt', previous_filename: 'src.txt', status: 'copied' },
  ]);
  assert.deepEqual(parseNameStatusZ(''), []);
});

test('an unregistered path blocks the pull request and is named, with how to fix it', () => {
  const r = makeRepo();
  try {
    const base = r.tip();
    const head = r.commit({ 'automation/never_reviewed.py': 'x = 1\n' });
    const out = r.run(base, head);
    assert.equal(out.code, 1);
    assert.equal(out.state, 'blocked');
    assert.deepEqual(out.unknown, ['automation/never_reviewed.py']);
    assert.match(out.summary, /`automation\/never_reviewed\.py`/);
    assert.match(out.summary, /REVIEWED_OPERATIONAL_FILES/);
    assert.match(out.summary, /No deployment, publication, secret access or write was performed/);
  } finally { r.cleanup(); }
});

test('paths the policy already reviews pass, as do documentation-only changes', () => {
  const r = makeRepo();
  try {
    const base = r.tip();
    const reviewed = r.commit({ 'automation/threat_relevance.py': 'x = 1\n', '.env.example': '# example\n' });
    const ok = r.run(base, reviewed);
    assert.equal(ok.code, 0, ok.summary);
    assert.equal(ok.state, 'manual_release_required');
    assert.deepEqual(ok.unknown, []);
    const docsBase = r.tip();
    const docsHead = r.commit({ 'docs/note.md': '# note\n' });
    const docs = r.run(docsBase, docsHead);
    assert.equal(docs.code, 0, docs.summary);
    assert.equal(docs.state, 'nonproduction_only');
  } finally { r.cleanup(); }
});

test('one unregistered path among reviewed ones blocks, and only that path is named', () => {
  const r = makeRepo();
  try {
    const base = r.tip();
    const head = r.commit({ 'automation/threat_relevance.py': 'x = 1\n', 'automation/surprise.py': 'y = 2\n', 'docs/a.md': 'a\n' });
    const out = r.run(base, head);
    assert.equal(out.code, 1);
    assert.deepEqual(out.unknown, ['automation/surprise.py']);
  } finally { r.cleanup(); }
});

test('a rename into an unregistered name is caught (old and new names are both classified)', () => {
  const r = makeRepo();
  try {
    r.commit({ 'automation/threat_relevance.py': 'def f():\n    return 1\n'.repeat(20) });
    const base = r.tip();
    r.sh('mv', 'automation/threat_relevance.py', 'automation/renamed_unreviewed.py');
    r.sh('commit', '-q', '-m', 'rename');
    const out = r.run(base, r.tip());
    assert.equal(out.code, 1);
    assert.deepEqual(out.unknown, ['automation/renamed_unreviewed.py']);
  } finally { r.cleanup(); }
});

test('only the pull request own changes are compared when the base branch has moved on', () => {
  const r = makeRepo();
  try {
    const fork = r.tip();
    r.sh('checkout', '-q', '-b', 'feature');
    const head = r.commit({ 'docs/feature.md': 'feature\n' });
    r.sh('checkout', '-q', 'main');
    // main advances with an unregistered path that is NOT part of the pull request
    const base = r.commit({ 'automation/main_only_unreviewed.py': 'z = 3\n' });
    assert.notEqual(base, fork);
    const out = r.run(base, head);
    assert.equal(out.code, 0, out.summary);
    assert.deepEqual(out.unknown, []);
    assert.equal(out.compared, 1);
  } finally { r.cleanup(); }
});

test('a pull request with no changes passes', () => {
  const r = makeRepo();
  try {
    const sha = r.tip();
    const out = r.run(sha, sha);
    assert.equal(out.code, 0);
    assert.equal(out.state, 'no_drift');
  } finally { r.cleanup(); }
});

// The classifier refuses a comparison of 300 or more files (production-drift-policy.cjs classify()). These are the
// classifier's own literal limits, deliberately NOT read from the module under test.
function bulkDocs(count) {
  const files = {};
  for (let i = 0; i < count; i += 1) files[`docs/bulk/f${i}.md`] = `${i}\n`;
  return files;
}

test('299 files are still classified, 300 are beyond the classifier range and are deferred, not failed', () => {
  const r = makeRepo();
  try {
    const base = r.tip();
    const inRange = r.run(base, r.commit(bulkDocs(299)));
    assert.equal(inRange.code, 0, inRange.summary);
    assert.equal(inRange.state, 'nonproduction_only', '299 files must really be classified');
    assert.equal(inRange.compared, 299);

    const base2 = r.tip();
    const beyond = r.run(base2, r.commit(Object.fromEntries(Object.entries(bulkDocs(300)).map(([k, v]) => [k.replace('bulk', 'bulk2'), v]))));
    assert.equal(beyond.code, 0, beyond.summary);
    assert.equal(beyond.state, 'not_evaluated');
    assert.equal(beyond.compared, 300);
    assert.match(beyond.summary, /Production Drift Reconciler classifies it after merge/);
  } finally { r.cleanup(); }
});

test('an unsafe file name fails closed and is never echoed', () => {
  const r = makeRepo();
  try {
    const base = r.tip();
    const head = r.commit({ 'docs/has space.md': 'x\n' });
    const out = r.run(base, head);
    assert.equal(out.code, 1);
    assert.equal(out.state, 'blocked');
    assert.match(out.reason, /unsafe filename/);
    assert.doesNotMatch(out.summary, /has space/);
  } finally { r.cleanup(); }
});

test('malformed or missing commit ids stop the preflight with exit code 2 before any git call', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'drift-preflight-bad-'));
  try {
    for (const [base, head] of [['', ''], ['main', 'HEAD'], ['a'.repeat(39), 'b'.repeat(40)], ['A'.repeat(40), 'b'.repeat(40)]]) {
      const out = preflight({ base, head, cwd: dir, deployWorkflow: DEPLOY });
      assert.equal(out.code, 2, `${base}/${head}`);
    }
    // well-formed ids that do not exist in the repository are an infrastructure error too, not a pass
    const out = preflight({ base: 'a'.repeat(40), head: 'b'.repeat(40), cwd: dir, deployWorkflow: DEPLOY });
    assert.equal(out.code, 2);
    assert.match(out.reason, /could not build the comparison/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('the command line entry point prints annotations, writes the step summary and sets the exit code', () => {
  const r = makeRepo();
  const summaryFile = path.join(os.tmpdir(), `drift-summary-${process.pid}-${Date.now()}.md`);
  try {
    const base = r.tip();
    const head = r.commit({ 'automation/cli_unreviewed.py': 'x = 1\n' });
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, BASE_SHA: base, HEAD_SHA: head, GITHUB_STEP_SUMMARY: summaryFile };
    const bad = spawnSync(process.execPath, [SCRIPT], { cwd: r.dir, env, encoding: 'utf8' });
    assert.equal(bad.status, 1, bad.stderr);
    assert.match(bad.stdout, /::error file=automation\/cli_unreviewed\.py,title=Unclassified path/);
    assert.match(fs.readFileSync(summaryFile, 'utf8'), /unclassified paths \(1\)/);
    const none = spawnSync(process.execPath, [SCRIPT], { cwd: r.dir, env: { PATH: process.env.PATH, HOME: process.env.HOME }, encoding: 'utf8' });
    assert.equal(none.status, 2);
    assert.match(none.stderr, /BASE_SHA and HEAD_SHA must be 40-hex/);
    const good = r.commit({ 'docs/ok.md': 'ok\n' });
    const ok = spawnSync(process.execPath, [SCRIPT], { cwd: r.dir, env: { ...env, BASE_SHA: head, HEAD_SHA: good }, encoding: 'utf8' });
    assert.equal(ok.status, 0, ok.stdout + ok.stderr);
  } finally { fs.rmSync(summaryFile, { force: true }); r.cleanup(); }
});

test('the workflow is read-only, covers every pull request, and passes untrusted values only through env', () => {
  const wf = fs.readFileSync(path.join(root, '.github/workflows/production-drift-preflight.yml'), 'utf8');
  assert.match(wf, /^on:\s*\n  pull_request:\s*\n    branches: \[main\]\s*$/m);
  assert.doesNotMatch(wf, /^\s+paths:/m, 'a paths filter would let an unregistered file in an unrelated PR through');
  assert.doesNotMatch(wf, /pull_request_target/);
  assert.match(wf, /^permissions:\s*\n  contents: read\s*$/m);
  assert.match(wf, /timeout-minutes: \d+/);
  assert.match(wf, /^concurrency:/m);
  assert.match(wf, /persist-credentials: false/);
  assert.match(wf, /fetch-depth: 0/);
  assert.doesNotMatch(wf, /secrets\./);
  assert.doesNotMatch(wf, /wrangler|workflow_dispatch|gh (?:workflow|api)|git push/);
  for (const m of wf.matchAll(/^\s*(?:-\s*)?uses:\s*([^\s#]+)/gm)) assert.match(m[1], /@[0-9a-f]{40}$/, `unpinned: ${m[1]}`);
  for (const m of wf.matchAll(/^\s*run:\s*(.+)$/gm)) assert.doesNotMatch(m[1], /\$\{\{/, 'no expression may be interpolated into shell source');
  assert.match(wf, /BASE_SHA: \$\{\{ github\.event\.pull_request\.base\.sha \}\}/);
  assert.match(wf, /HEAD_SHA: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/);
});

test('the preflight is itself release control: registered as operational, never benign, and run by the security gate', () => {
  for (const file of ['scripts/production-drift-preflight.cjs', '.github/workflows/production-drift-preflight.yml']) {
    assert.equal(fs.existsSync(path.join(root, file)), true, file);
    assert.equal(isReviewedOperationalPath(file), true, `${file} must be reviewed operational`);
    assert.equal(isKnownBenignPath(file), false, `${file} must never be benign`);
  }
  const gate = fs.readFileSync(path.join(root, '.github/workflows/workflow-security-gate.yml'), 'utf8');
  assert.match(gate, /node --test[^\n]*tests-js\/production-drift-preflight\.test\.js/);
  const [pushPart, rest] = gate.split('  pull_request:');
  const prPart = rest.split('  schedule:')[0];
  for (const file of ['scripts/production-drift-preflight.cjs', 'tests-js/production-drift-preflight.test.js']) {
    assert.ok(pushPart.includes(`      - '${file}'`), `push must watch ${file}`);
    assert.ok(prPart.includes(`      - '${file}'`), `PR must watch ${file}`);
  }
});
