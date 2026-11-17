'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const file = fs.readFileSync(
  path.join(__dirname, '../.github/workflows/blogger-oauth-readonly-certification.yml'), 'utf8'
);

test('OAuth runner certification is manually triggered, read-only, and scoped to main', () => {
  assert.match(file, /^  workflow_dispatch:\s*$/m);
  assert.doesNotMatch(file, /^  (schedule|push|pull_request|workflow_run):/m);
  assert.match(file, /permissions:\s*\n  contents: read/);
  assert.match(file, /if: github.ref == 'refs\/heads\/main'/);
  assert.doesNotMatch(file, /contents: write|actions: write|git push|wrangler deploy|createWorkflowDispatch|npm install|pip install/);
});

test('OAuth certification performs only a Google refresh plus read-only Blogger GET', () => {
  assert.match(file, /https:\/\/oauth2\.googleapis\.com\/token/);
  assert.match(file, /https:\/\/www\.googleapis\.com\/blogger\/v3\/blogs\//);
  assert.match(file, /method="GET"/);
  assert.match(file, /2163240462341298251/);
  assert.match(file, /cti\.cyberdudebivash\.in/);
  assert.match(file, /BLOGGER_READ_ONLY_API=PASS/);
  assert.match(file, /BLOGGER_PUBLICATION=NOT_ATTEMPTED/);
  assert.doesNotMatch(file, /\/(posts|pages)\b|method="DELETE"|method="PUT"|method="PATCH"/);
});

test('OAuth certification does not expose credentials or HTTP error bodies', () => {
  assert.match(file, /CERTIFICATION=HOLD_/);
  assert.doesNotMatch(file, /print\(access_token|print\(token_data|print\(form|print\(os\.environ|traceback\.print_exc/);
});
