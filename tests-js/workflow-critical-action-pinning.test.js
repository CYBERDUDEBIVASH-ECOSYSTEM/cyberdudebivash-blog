'use strict';
// Audited 2026-11-18 from the official GitHub tags, no mutable runner refs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const dir = path.join(root, '.github', 'workflows');

// Every checked-in workflow is included, including new files introduced later.
const critical = fs.readdirSync(dir).filter(name => /\.ya?ml$/.test(name)).sort();
const approved = new Map([
  ['actions/checkout','fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09'],
  ['actions/setup-node','a0853c24544627f65ddf259abe73b1d18a591444'],
  ['actions/setup-python','ece7cb06caefa5fff74198d8649806c4678c61a1'],
  ['actions/github-script','f28e40c7f34bde8b3046d885e986cb6290c5673b'],
  ['actions/upload-artifact','ea165f8d65b6e75b540449e92b4886f43607fa02'],
  ['actions/download-artifact','d3f86a106a0bac45b974a628896c90dbdf5c8093']
]);

test('P0 immutable action supply-chain audit covers every SOC workflow file', () => {
  assert.ok(critical.length >= 29, 'workflow inventory unexpectedly contracted');
});

for (const file of critical) {
  test('P0 immutable official action references: '+file, () => {
    const yaml = fs.readFileSync(path.join(dir, file), 'utf8');
    const references = [...yaml.matchAll(/^\s*(?:-\s*)?uses:\s*([^\s#]+)/gm)].map(m => m[1]);
    assert.match(yaml, /^jobs:\s*$/m, 'workflow must declare jobs');
    for (const reference of references) {
      if (reference.startsWith('./')) continue;
      assert.match(reference,/^actions\/[a-z-]+@[a-f0-9]{40}$/,
        'unknown or unpinned dependency: '+reference);
      const [repository, sha] = reference.split('@');
      assert.equal(sha, approved.get(repository),
        'dependency update requires independent verification and allowlist review');
    }
  });
}

test('immutability does not weaken manual Cloudflare deploy or Blogger publication authorization', () => {
  const cf = fs.readFileSync(path.join(dir,'cloudflare-production-deploy.yml'),'utf8');
  const blog = fs.readFileSync(path.join(dir,'blogger-syndication.yml'),'utf8');
  assert.match(cf, /github\.event_name == 'workflow_dispatch' && github\.ref == 'refs\/heads\/main'/);
  assert.match(cf, /environment: production/);
  assert.match(blog, /vars\.BLOGGER_OAUTH_READY == 'true'/);
  assert.match(blog, /default: "true"/);
  assert.match(blog, /default: "1"/);
});
