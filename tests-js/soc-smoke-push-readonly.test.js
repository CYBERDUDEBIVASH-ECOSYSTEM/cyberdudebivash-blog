'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const workflow = fs.readFileSync(
  path.join(__dirname, '..', '.github/workflows/smoke-test.yml'), 'utf8'
);

test('source push must not sleep waiting for a deploy it did not initiate', () => {
  const step = workflow.match(
    /- name: "⏳ Allow propagation after deliberate manual release"([\s\S]*?)(?=\n\s+- name: "🚀 Smoke test)/
  );
  assert.ok(step, 'a bounded, explicit postdeployment settle step must exist');
  assert.match(step[1], /if: .*github\.event_name == 'workflow_dispatch'/);
  assert.match(step[1], /github\.ref == 'refs\/heads\/main'/);
  assert.match(step[1], /run: sleep 90/);
  assert.doesNotMatch(step[1], /always\(\)|event_name == 'push'/);
});

test('public freshness, S2N API and commerce gates are retained after timeout optimization', () => {
  assert.match(workflow, /timeout-minutes: 8/);
  assert.match(workflow, /node scripts\/certify-soc-public-feed-parity\.cjs/);
  assert.match(workflow, /node scripts\/certify-soc-s2n-api-release\.cjs --monitor-public/);
  assert.match(workflow, /node scripts\/check-soc-public-commerce\.cjs/);
  assert.doesNotMatch(workflow, /continue-on-error: true/);
  assert.doesNotMatch(workflow, /wrangler deploy|git push origin|pages deploy/);
  assert.match(workflow, /permissions:\s*\n  contents: read/);
});
