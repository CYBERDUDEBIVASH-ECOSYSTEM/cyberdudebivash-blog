'use strict';
/**
 * Accessibility semantics of the SOC dashboard pages. Measured with axe-core (WCAG 2.x A/AA + best practice) in Chromium before
 * this change: an unlabeled <select> (critical), accessible names that did not contain the visible text (serious, WCAG 2.5.3),
 * no <h1> on /intel/, /ai-security/ and /malware/, no main landmark on three pages, and content outside any landmark.
 *
 * CI has no browser, so this test pins the SOURCE invariants that produced those results. The real-browser axe audit remains the
 * verification of record. Static checks use plain markup patterns and are intentionally narrow.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const read = f => fs.readFileSync(path.join(ROOT, f), 'utf8');

const INTEL_PAGES = ['intel/index.html', 'ai-security/index.html', 'malware/index.html'];
const LANDMARK_PAGES = ['api-dashboard.html', 'hunts.html', 'workbench.html', 'soc.html', 'intelligence.html', 'detections/index.html', ...INTEL_PAGES];

test('every <select> on the SOC pages has an accessible name', () => {
  for (const f of ['api-dashboard.html', 'hunts.html', 'workbench.html', 'soc.html', 'detections/index.html', 'intelligence.html']) {
    const html = read(f);
    for (const m of html.matchAll(/<select\b([^>]*)>/gi)) {
      const attrs = m[1];
      if (/\baria-label(ledby)?\s*=/.test(attrs) || /\btitle\s*=/.test(attrs)) continue;
      const before = html.slice(0, m.index);
      if (before.toLowerCase().lastIndexOf('<label') > before.toLowerCase().lastIndexOf('</label>')) continue; // wrapped by its <label>
      const id = (attrs.match(/\bid\s*=\s*["']([^"']+)["']/) || [])[1];
      assert.ok(id && new RegExp(`<label\\b[^>]*\\bfor\\s*=\\s*["']${id}["']`, 'i').test(html), `${f}: <select${id ? ' id=' + id : ''}> has no label, aria-label or title`);
    }
  }
});

test('the plan selector on the API dashboard is associated with its visible label', () => {
  assert.match(read('api-dashboard.html'), /<label for="reg-plan">Plan<\/label>\s*<select id="reg-plan">/);
});

test('the intel dashboards expose a real <h1>, and the page title does not shift layout', () => {
  for (const f of INTEL_PAGES) {
    const html = read(f);
    assert.equal((html.match(/<h1\b/gi) || []).length, 1, `${f}: expected exactly one <h1>`);
    assert.match(html, /<h1 class="page-title">/, `${f}: page title is not the <h1>`);
    assert.doesNotMatch(html, /<div class="page-title">/, `${f}: a div page title is back`);
    // an <h1> brings a default top margin; the rule resets it so the layout does not move
    assert.match(html, /\.page-title\{[^}]*margin:0 0 6px;[^}]*\}/, `${f}: .page-title lost its margin reset`);
  }
});

test('headings after the <h1> do not skip a level on the intel dashboards', () => {
  assert.match(read('ai-security/index.html'), /<h3 role="heading" aria-level="2">🤖 AI Security Assessment/);
  assert.match(read('intel/index.html'), /<h3 role="heading" aria-level="2">🔒 SOC Pro Intelligence/);
});

test('every SOC page has a main landmark, and the workbench login view has a level-one heading', () => {
  for (const f of LANDMARK_PAGES) assert.match(read(f), /<main\b|role="main"/, `${f}: no main landmark`);
  const wb = read('workbench.html');
  assert.match(wb, /<div id="login-screen" role="main">/);
  assert.match(wb, /<div id="app"[^>]*role="main">/);
  assert.match(wb, /<div class="card-title" role="heading" aria-level="1">🔐 Analyst Sign-In<\/div>/);
  const api = read('api-dashboard.html');
  assert.equal((api.match(/<main\b/g) || []).length, 1);
  assert.ok(api.indexOf('<main id="main-content">') < api.indexOf('id="panel-register"') && api.indexOf('</main>') > api.indexOf('id="panel-plans"') && api.indexOf('</main>') < api.indexOf('<footer'), 'api-dashboard: <main> must wrap the hero through the plans panel and end before the footer');
});

test('accessible names contain the visible text (WCAG 2.5.3 label in name)', () => {
  const soc = read('soc.html');
  for (const [cls, visible] of [['soc-desk__refresh', 'Refresh snapshot'], ['soc-desk__export', 'Export filtered CSV']]) {
    const m = soc.match(new RegExp(`<button class="${cls}"[^>]*aria-label="([^"]+)"[^>]*>([^<]+)`));
    assert.ok(m, `${cls} not found`);
    assert.ok(m[1].toLowerCase().includes(visible.toLowerCase()), `${cls}: aria-label "${m[1]}" must contain "${visible}"`);
    assert.ok(m[2].includes(visible), `${cls}: visible text changed`);
  }
  const ws = read('soc-hybrid-workspace.js');
  assert.match(ws, /b\.textContent='Select for analysis'/);
  const label = ws.match(/b\.setAttribute\('aria-label','([^']+)'\)/)[1];
  assert.ok(label.includes('Select for analysis'), `record select aria-label "${label}" must contain its visible text`);
  assert.doesNotMatch(read('intelligence.html'), /class="header-logo" aria-label=/, 'the logo link must be named by its visible text');
});
