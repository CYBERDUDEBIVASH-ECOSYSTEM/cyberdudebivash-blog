'use strict';
// Script-injection guard for every GitHub Actions workflow in this repository.
//
// Incident class: a workflow_dispatch input of type string (free text) interpolated with ${{ }} into a
// `run:` block becomes shell source. Dispatch needs only write access, not a merged and reviewed change,
// so anyone who can dispatch gets code execution in a job that holds that workflow's secrets.
// Found 2026-11-25 in blogger-legacy-quality.yml: `--max-posts "${{ inputs.max_posts }}"` in the step that
// holds BLOGGER_CLIENT_SECRET and BLOGGER_REFRESH_TOKEN.
//
// Rule enforced here: inside a `run:` block, an expression may reference a dispatch/call input ONLY if the
// input is declared type choice, boolean or environment (the server rejects other values). Free-text
// inputs must reach the shell through `env:` and be validated there. Context values an outsider can
// influence (issue/PR text, branch names, commit messages) are never allowed in `run:`.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const yaml = require('js-yaml');

const DIR = path.join(__dirname, '..', '.github', 'workflows');
const SAFE_INPUT_TYPES = new Set(['choice', 'boolean', 'environment']);
const UNTRUSTED_CONTEXT = [
  /\bgithub\.event\.(issue|pull_request|comment|review|review_comment|discussion|pages|commits|head_commit|workflow_run\.(head_branch|head_commit|display_title|pull_requests))\b/,
  /\bgithub\.head_ref\b/,
  /\bgithub\.event\.client_payload\b/,
];

function triggerBlock(doc) {
  const on = doc.on !== undefined ? doc.on : doc[true]; // YAML 1.1 parsers read the key `on` as true
  return on && typeof on === 'object' ? on : {};
}

function declaredInputs(doc) {
  const on = triggerBlock(doc);
  const out = {};
  for (const trig of ['workflow_dispatch', 'workflow_call']) {
    const inputs = on[trig] && on[trig].inputs;
    if (inputs && typeof inputs === 'object') {
      for (const [name, def] of Object.entries(inputs)) out[name] = String((def && def.type) || 'string');
    }
  }
  return out;
}

function expressions(text) {
  return [...String(text).matchAll(/\$\{\{([\s\S]*?)\}\}/g)].map((m) => m[1].trim());
}

function runBlocks(doc) {
  const blocks = [];
  for (const [jobName, job] of Object.entries(doc.jobs || {})) {
    (job.steps || []).forEach((step, i) => {
      if (typeof step.run === 'string') blocks.push({ where: `${jobName}#${i + 1} ${step.name || ''}`.trim(), run: step.run });
    });
  }
  return blocks;
}

function violations(doc) {
  const inputs = declaredInputs(doc);
  const found = [];
  for (const { where, run } of runBlocks(doc)) {
    for (const expr of expressions(run)) {
      for (const m of expr.matchAll(/\b(?:github\.event\.inputs|inputs)\.([A-Za-z0-9_-]+)/g)) {
        const type = inputs[m[1]];
        if (!SAFE_INPUT_TYPES.has(type)) found.push(`${where}: \${{ ${expr} }} uses input "${m[1]}" of type ${type || 'undeclared'} in a run block`);
      }
      if (UNTRUSTED_CONTEXT.some((re) => re.test(expr))) found.push(`${where}: \${{ ${expr} }} puts attacker-influenced context in a run block`);
    }
  }
  return found;
}

const files = fs.readdirSync(DIR).filter((f) => /\.ya?ml$/.test(f)).sort();
const docs = files.map((f) => [f, yaml.load(fs.readFileSync(path.join(DIR, f), 'utf8'))]);

test('the scan sees the workflows and the interpolations it is meant to judge', () => {
  assert.ok(files.length >= 25, `expected the repository workflows, saw ${files.length}`);
  const checked = docs.reduce((n, [, d]) => n + runBlocks(d).reduce((m, b) => m + expressions(b.run).length, 0), 0);
  assert.ok(checked > 50, `scan looked at too few expressions (${checked}); the parser may have stopped reading run blocks`);
  const syndication = docs.find(([f]) => f === 'blogger-syndication.yml')[1];
  assert.equal(declaredInputs(syndication).dry_run, 'choice', 'a choice input that is interpolated today must be recognised as constrained');
});

for (const [file, doc] of docs) {
  test(`${file}: no free-text input or attacker-influenced context is interpolated into a run block`, () => {
    assert.deepEqual(violations(doc), []);
  });
}

test('detector self-check: it flags a string input and an issue title, and accepts a choice input', () => {
  const bad = yaml.load(`
on:
  workflow_dispatch:
    inputs:
      n: { type: string }
      m: { type: choice, options: [a, b] }
jobs:
  j:
    steps:
      - run: echo "\${{ inputs.n }}" "\${{ inputs.m }}" "\${{ github.event.issue.title }}"
`);
  const v = violations(bad);
  assert.equal(v.length, 2);
  assert.ok(v.some((x) => x.includes('input "n" of type string')));
  assert.ok(v.some((x) => x.includes('attacker-influenced')));
  assert.ok(!v.some((x) => x.includes('input "m"')));
  // an input with no declared type defaults to string and is therefore rejected
  const untyped = yaml.load('on:\n  workflow_dispatch:\n    inputs:\n      k: { description: x }\njobs:\n  j:\n    steps:\n      - run: echo ${{ inputs.k }}\n');
  assert.equal(violations(untyped).length, 1);
});

// ---- Behaviour of the fixed step (blogger-legacy-quality.yml "Audit or quarantine") ------------------
// Runs the REAL script text from the workflow under bash with a stub `python`, so the test proves what is
// executed for valid, invalid and hostile inputs, not just what the text looks like.
const { spawnSync } = require('node:child_process');
const os = require('node:os');

const legacy = docs.find(([f]) => f === 'blogger-legacy-quality.yml')[1];
const step = legacy.jobs.audit.steps.find((s) => s.name === 'Audit or quarantine');
const hasBash = spawnSync('bash', ['-c', 'true']).status === 0;

function runStep(mode, maxPosts) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lq-'));
  try {
    fs.mkdirSync(path.join(dir, 'bin'));
    fs.writeFileSync(path.join(dir, 'bin', 'python'), '#!/bin/bash\necho "$*" >> "$LQ_LOG"\n', { mode: 0o755 });
    fs.writeFileSync(path.join(dir, 'step.sh'), step.run);
    const log = path.join(dir, 'log');
    const r = spawnSync('bash', [path.join(dir, 'step.sh')], {
      cwd: dir,
      env: { PATH: `${path.join(dir, 'bin')}:${process.env.PATH}`, LQ_LOG: log, INPUT_MODE: mode, INPUT_MAX_POSTS: maxPosts },
      encoding: 'utf8',
    });
    return { status: r.status, calls: fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n') : [], dir: null, stderr: r.stdout + r.stderr, marker: fs.existsSync(path.join(dir, 'PWNED')) };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('the step reads its inputs from the environment and has no ${{ }} text in the script', () => {
  assert.ok(!/\$\{\{/.test(step.run), 'script text must not contain expression interpolation');
  assert.match(step.env.INPUT_MODE, /inputs\.mode/);
  assert.match(step.env.INPUT_MAX_POSTS, /inputs\.max_posts/);
});

test('valid inputs run the auditor exactly as before (dry-run and --apply)', { skip: !hasBash }, () => {
  const a = runStep('dry-run', '50');
  assert.equal(a.status, 0);
  assert.deepEqual(a.calls, ['-m automation.legacy_quality_auditor --max-posts 50 --manifest logs/legacy-quality-manifest.json']);
  const b = runStep('quarantine', '500');
  assert.equal(b.status, 0);
  assert.deepEqual(b.calls, ['-m automation.legacy_quality_auditor --max-posts 500 --manifest logs/legacy-quality-manifest.json --apply']);
});

test('invalid or hostile inputs are refused before the auditor (or any injected command) can run', { skip: !hasBash }, () => {
  const hostile = [
    ['dry-run', '0'], ['dry-run', '501'], ['dry-run', ''], ['dry-run', ' 50'], ['dry-run', '5e1'], ['dry-run', '-5'],
    ['dry-run', '50 --apply'], ['dry-run', '50"; touch PWNED; echo "'], ['dry-run', '$(touch PWNED)'], ['dry-run', '`touch PWNED`'],
    ['evil', '50'], ['dry-run; touch PWNED', '50'], ['', '50'], ['QUARANTINE', '50'],
  ];
  for (const [mode, max] of hostile) {
    const r = runStep(mode, max);
    assert.notEqual(r.status, 0, `mode=${JSON.stringify(mode)} max=${JSON.stringify(max)} must be refused`);
    assert.deepEqual(r.calls, [], `the auditor must not run for mode=${JSON.stringify(mode)} max=${JSON.stringify(max)}`);
    assert.equal(r.marker, false, `no injected command may run for max=${JSON.stringify(max)}`);
  }
});
