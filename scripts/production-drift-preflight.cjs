#!/usr/bin/env node
'use strict';

/**
 * PR-time production drift preflight. READ-ONLY: it never deploys, publishes, dispatches, reads a secret or writes.
 *
 * Why it exists: the Production Drift Reconciler fails closed (decision `blocked`, exit 1) on any changed path that
 * scripts/production-drift-policy.cjs has not classified. Files added by a merged pull request therefore turned
 * `main` red until somebody registered them: 21 paths on 2026-11-21, 25 under P0 #433, and 4 paths on 2026-11-24
 * (29 red reconciler runs in about ten hours). This script runs the SAME classifier on the files a pull request
 * changes, so the author learns before merge.
 *
 * It is advisory and does not replace the reconciler: the reconciler stays the authoritative post-merge gate. A pull
 * request too large for the classifier (300 or more files, 250 or more commits) is reported and left to the
 * reconciler rather than being failed for a limit that is not the author's mistake.
 *
 * Exit codes: 0 every changed path is classified (or the comparison is out of the classifier's range);
 *             1 at least one changed path is unclassified, or the classifier blocked the comparison;
 *             2 the preflight could not run (bad input or git failure).
 */

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { deployPaths, classify } = require('./production-drift-policy.cjs');

const SHA = /^[a-f0-9]{40}$/;
// The classifier refuses comparisons at or beyond these sizes (see classify()).
const MAX_FILES = 299;
const MAX_COMMITS = 249;
const LISTED_PATHS = 30;
const ANNOTATED_PATHS = 10;

function git(args, cwd) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

/** `git diff --name-status -M -z` => [{filename, status, previous_filename?}] in the policy's compare shape. */
function parseNameStatusZ(output) {
  const tokens = String(output).split('\0');
  if (tokens.length && tokens[tokens.length - 1] === '') tokens.pop();
  const files = [];
  for (let i = 0; i < tokens.length;) {
    const code = tokens[i++] || '';
    const kind = code[0];
    if (kind === 'R' || kind === 'C') {
      const previous = tokens[i++];
      const filename = tokens[i++];
      files.push({ filename, previous_filename: previous, status: kind === 'R' ? 'renamed' : 'copied' });
    } else {
      const filename = tokens[i++];
      files.push({ filename, status: { A: 'added', M: 'modified', D: 'removed', T: 'changed' }[kind] || 'changed' });
    }
  }
  return files;
}

function buildCompare(base, head, cwd) {
  const mergeBase = git(['merge-base', base, head], cwd).trim();
  const commits = git(['rev-list', '--reverse', `${mergeBase}..${head}`], cwd).split('\n').filter(Boolean);
  const files = parseNameStatusZ(git(['diff', '--name-status', '-M', '-z', '--no-ext-diff', mergeBase, head], cwd));
  return {
    mergeBase,
    compare: {
      status: 'ahead',
      base_commit: { sha: mergeBase },
      merge_base_commit: { sha: mergeBase },
      ahead_by: commits.length,
      behind_by: 0,
      total_commits: commits.length,
      commits: commits.map(sha => ({ sha })),
      files,
    },
  };
}

function renderSummary(r) {
  const lines = ['### PR drift preflight (read-only)', `- decision: **${r.state}**`];
  if (r.reason) lines.push(`- reason: ${r.reason}`);
  lines.push(`- changed files compared: ${r.compared}`);
  if (r.unknown.length) {
    lines.push(`- **unclassified paths (${r.unknown.length}) — the Production Drift Reconciler would go red on these after merge:**`);
    for (const name of r.unknown.slice(0, LISTED_PATHS)) lines.push(`  - \`${name}\``);
    if (r.unknown.length > LISTED_PATHS) lines.push(`  - ... plus ${r.unknown.length - LISTED_PATHS} more`);
    lines.push('',
      'To fix: review each path, then add its EXACT path to `REVIEWED_OPERATIONAL_FILES` in `scripts/production-drift-policy.cjs` ' +
      'with a rationale comment (copy the existing blocks) and extend `tests-js/production-drift-safety.test.js`. ' +
      'Do not add a wildcard: unreviewed siblings must keep blocking. This is inventory classification, not a deploy approval.');
  }
  if (r.note) lines.push(`- note: ${r.note}`);
  lines.push('- No deployment, publication, secret access or write was performed.');
  return lines.join('\n') + '\n';
}

/**
 * @returns {{code:number,state:string,unknown:string[],compared:number,reason?:string,note?:string,summary:string}}
 */
function preflight({ base, head, cwd, deployWorkflow }) {
  const fail = (code, reason) => {
    const r = { code, state: 'error', unknown: [], compared: 0, reason };
    return { ...r, summary: renderSummary(r) };
  };
  if (!SHA.test(base || '') || !SHA.test(head || '')) {
    return fail(2, 'BASE_SHA and HEAD_SHA must be 40-hex commit ids');
  }
  let patterns;
  let built;
  try {
    const text = fs.readFileSync(path.join(cwd, deployWorkflow), 'utf8');
    patterns = deployPaths(text);
    built = buildCompare(base, head, cwd);
  } catch (err) {
    return fail(2, `could not build the comparison: ${String(err.message).split('\n')[0].slice(0, 160)}`);
  }
  const { mergeBase, compare } = built;
  const compared = compare.files.length;
  if (compare.total_commits === 0 || compared === 0) {
    const r = { code: 0, state: 'no_drift', unknown: [], compared, note: 'the pull request changes no files' };
    return { ...r, summary: renderSummary(r) };
  }
  if (compared > MAX_FILES || compare.total_commits > MAX_COMMITS) {
    const r = {
      code: 0, state: 'not_evaluated', unknown: [], compared,
      note: `the comparison (${compared} files, ${compare.total_commits} commits) is beyond the classifier's range; ` +
        'the Production Drift Reconciler classifies it after merge',
    };
    return { ...r, summary: renderSummary(r) };
  }
  const result = classify(compare, mergeBase, head, patterns);
  const unknown = Array.isArray(result.unknown) ? result.unknown : [];
  const blocked = result.state === 'blocked';
  const r = {
    code: blocked ? 1 : 0,
    state: result.state,
    reason: blocked ? result.reason : undefined,
    unknown,
    compared,
  };
  return { ...r, summary: renderSummary(r) };
}

function main(env = process.env, cwd = process.cwd()) {
  const result = preflight({
    base: env.BASE_SHA,
    head: env.HEAD_SHA,
    cwd,
    deployWorkflow: '.github/workflows/cloudflare-production-deploy.yml',
  });
  process.stdout.write(result.summary);
  if (env.GITHUB_STEP_SUMMARY) {
    try { fs.appendFileSync(env.GITHUB_STEP_SUMMARY, result.summary); } catch (_) { /* summary is best effort */ }
  }
  // Names reached this point only after the policy's strict filename check ([\w.@+/-]), so they are safe to echo.
  for (const name of result.unknown.slice(0, ANNOTATED_PATHS)) {
    process.stdout.write(`::error file=${name},title=Unclassified path for the Production Drift Reconciler::Register this exact path in scripts/production-drift-policy.cjs (REVIEWED_OPERATIONAL_FILES) before merge.\n`);
  }
  if (result.code === 2) process.stderr.write(`::error::PR drift preflight could not run: ${result.reason}\n`);
  return result.code;
}

if (require.main === module) {
  try {
    process.exitCode = main();
  } catch (err) {
    process.stderr.write(`::error::PR drift preflight failed unexpectedly: ${String(err.message).slice(0, 160)}\n`);
    process.exitCode = 2;
  }
}

module.exports = { parseNameStatusZ, buildCompare, preflight, renderSummary, main, MAX_FILES, MAX_COMMITS };
