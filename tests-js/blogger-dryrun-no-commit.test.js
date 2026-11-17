'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const wf=fs.readFileSync(path.join(__dirname,'..','.github','workflows','blogger-syndication.yml'),'utf8');

test('Blogger dry run exits before any Git ledger staging or push',()=>{
  const step=wf.split('- name: "💾 Commit Publication State"')[1]
    .split('- name: "📊 Pipeline Summary"')[0];
  assert.match(step,/if: always\(\)/);
  const guard=step.indexOf('DRY_RUN_GIT_MUTATIONS=NONE');
  const add=step.indexOf('git add data/published_posts.json');
  const commit=step.indexOf('git commit -m');
  const push=step.indexOf('git push origin main');
  assert.ok(guard>0 && add>guard && commit>add && push>commit);
  assert.match(step,/github\.event\.inputs\.dry_run \}\}" = "true"/);
  assert.match(step,/github\.event_name \}\}" = "workflow_dispatch"/);
  assert.match(step,/DRY_RUN_GIT_MUTATIONS=NONE"\s*\n\s*exit 0/);
});

test('normal Blogger live publication remains main-only, readiness-gated, and serialized',()=>{
  assert.match(wf,/vars\.BLOGGER_OAUTH_READY == 'true'/);
  assert.match(wf,/GITHUB_REF\}" != "refs\/heads\/main"/);
  assert.match(wf,/cancel-in-progress: false/);
  assert.match(wf,/MAX_POSTS_PER_RUN/);
  assert.match(wf,/git pull --rebase origin main --quiet/);
  assert.match(wf,/git push origin main/);
});
