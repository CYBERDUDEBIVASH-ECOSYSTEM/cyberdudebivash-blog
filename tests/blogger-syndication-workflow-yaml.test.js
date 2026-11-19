'use strict';

const fs = require('node:fs');
const path = require('node:path');
const yaml = require('js-yaml'); // Already a pinned production root dependency.

const filename = path.join(__dirname, '..', '.github', 'workflows', 'blogger-syndication.yml');
const source = fs.readFileSync(filename, 'utf8');

describe('P0 Blogger Actions workflow YAML parser contract', () => {
  test('strict YAML parser accepts all mappings without duplicate keys', () => {
    const doc = yaml.load(source, { json: false });
    expect(doc).toHaveProperty('jobs.syndicate.steps');
    expect(doc.jobs.syndicate.if).toContain("vars.BLOGGER_OAUTH_READY == 'true'");
  });

  test('both authorization gates receive the same explicit inputs', () => {
    const doc = yaml.load(source, { json: false });
    const steps = doc.jobs.syndicate.steps;
    const pre = steps.find(s => s.name === 'P0 authorize Blogger dispatch before installing dependencies');
    const pub = steps.find(s => s.id === 'syndication_pipeline');
    expect(pre).toBeDefined();
    expect(pub).toBeDefined();
    const keys = {
      CDB_BLOGGER_OAUTH_READY: "${{ vars.BLOGGER_OAUTH_READY }}",
      CDB_BLOGGER_CANARY_APPROVED: "${{ github.event.inputs.live_canary_approved || 'false' }}",
      CDB_BLOGGER_DRY_RUN_INPUT: "${{ github.event.inputs.dry_run || 'true' }}",
      CDB_BLOGGER_CANARY_SOURCE_URL: "${{ github.event.inputs.canary_source_url || '' }}",
      CDB_BLOGGER_CANARY_SOURCE_HASH: "${{ github.event.inputs.canary_source_hash || '' }}",
      MAX_POSTS_PER_RUN: "${{ github.event.inputs.max_posts || '4' }}",
    };
    for (const [key, value] of Object.entries(keys)) {
      expect(pre.env[key]).toBe(value);
      expect(pub.env[key]).toBe(value);
    }
    expect(doc.on.workflow_dispatch.inputs.live_canary_approved.default).toBe('false');
    expect(doc.on.workflow_dispatch.inputs.dry_run.default).toBe('true');
    expect(doc.on.workflow_dispatch.inputs.canary_source_url.default).toBe('');
    expect(doc.on.workflow_dispatch.inputs.canary_source_hash.default).toBe('');
  });

  test('strict parser rejects exact duplicate mapping pattern from P0 GitHub 422', () => {
    const bad = [
      'env:',
      '  CDB_BLOGGER_OAUTH_READY: value1',
      '  CDB_BLOGGER_OAUTH_READY: value2'
    ].join('\n');
    expect(() => yaml.load(bad, { json: false })).toThrow(/duplicated mapping key/);
  });
});
