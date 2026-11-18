'use strict';

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');

const workflow = readFileSync(
  path.join(__dirname, '..', '.github', 'workflows', 'blogger-syndication.yml'),
  'utf8'
);

function manualInputBlock(name) {
  const dispatchSection = workflow.split(/^  workflow_dispatch:\s*$/m);
  assert.equal(dispatchSection.length, 2, 'exactly one manual workflow_dispatch section expected');
  const inputMatch = dispatchSection[1].match(
    new RegExp('^ {6}' + name + ':\\r?\\n((?:^ {8}.*(?:\\r?\\n|$))+)', 'm')
  );
  assert.ok(inputMatch, 'manual input ' + name + ' must be present');
  return inputMatch[1];
}

test('manual Blogger runs are nonpublishing by default', () => {
  assert.match(manualInputBlock('dry_run'), /^ {8}default:\s*"true"\s*$/m);
});

test('manual Blogger runs select only one candidate by default', () => {
  assert.match(manualInputBlock('max_posts'), /^ {8}default:\s*"1"\s*$/m);
});

test('scheduled and push publisher still require readiness while manual execution stays main-only', () => {
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /github\.event_name == 'workflow_dispatch' \|\| vars\.BLOGGER_OAUTH_READY == 'true'/);
  assert.match(workflow, /if \[ "\$\{\{ github\.event\.inputs\.dry_run \}\}" = "true" \]; then/);
  assert.match(workflow, /case "\$\{MAX_POSTS_PER_RUN\}" in/);
});
