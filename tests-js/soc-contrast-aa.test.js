'use strict';
/**
 * WCAG 2.x AA colour contrast (1.4.3) and use-of-colour (1.4.1) guard for the SOC dashboard pages.
 *
 * Measured with axe-core 4.x in headless Chromium (1440px and 390px, hostile-free fixture data) before this change, the SOC pages
 * carried 534 serious `color-contrast` nodes: --apex-muted #6b7280 (3.7-4.1:1) on every page that defines it, and hard-coded greys
 * #333/#444/#555/#666/#888/#475569 (1.5-4.35:1) on the /intel/, /ai-security/ and /malware/ dashboards and in auto-intel-engine.js.
 * Lightening the muted text also pushed the cyan footer links below 3:1 against it, so those links must carry an underline (1.4.1).
 *
 * This is a static guard (axe needs a browser; CI does not run one). It computes real contrast ratios from the colours the files
 * declare, so it fails on a regression to a failing colour, not merely on a string.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const read = f => fs.readFileSync(path.join(ROOT, f), 'utf8');

function lum(hex) {
  const h = hex.replace('#', '');
  const full = h.length === 3 ? h.split('').map(c => c + c).join('') : h;
  const c = [0, 2, 4].map(i => parseInt(full.slice(i, i + 2), 16) / 255).map(x => (x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}
function ratio(a, b) {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}
const token = (src, name) => { const m = src.match(new RegExp(`--${name}\\s*:\\s*(#[0-9a-fA-F]{3,6})`)); assert.ok(m, `--${name} not declared`); return m[1]; };

const DASHBOARDS = ['detections/index.html', 'hunts.html', 'workbench.html', 'api-dashboard.html', 'intelligence.html'];
const INTEL_DASHBOARDS = ['intel/index.html', 'ai-security/index.html', 'malware/index.html', 'auto-intel-engine.js'];
const ALL = [...DASHBOARDS, ...INTEL_DASHBOARDS];

// every text colour that measured below 4.5:1 on the dark SOC surfaces; `(?<![\w-])` keeps background-color / border-color out
const FAILING_TEXT = /(?<![\w-])color\s*:\s*#(?:333(?:333)?|444(?:444)?|555(?:555)?|666(?:666)?|888(?:888)?|475569|6b7280)(?![0-9a-fA-F])/gi;

test('the text-colour detector flags the old values and ignores backgrounds and borders', () => {
  assert.equal('a{color:#555;x:y}'.match(FAILING_TEXT).length, 1);
  assert.equal('a{color: #6b7280}'.match(FAILING_TEXT).length, 1);
  assert.equal('a{background-color:#555;border-color:#888;background:#444}'.match(FAILING_TEXT), null);
  assert.equal('a{color:#9ca3af}'.match(FAILING_TEXT), null);
});

for (const file of ALL) {
  test(`REGRESSION: ${file} declares no text colour that fails AA on the dark surfaces`, () => {
    const hits = (read(file).match(FAILING_TEXT) || []);
    assert.deepEqual(hits, [], `${file}: ${hits.join(' | ')}`);
  });
}

for (const file of DASHBOARDS) {
  test(`REGRESSION: ${file} --apex-muted meets 4.5:1 on every surface token it declares`, () => {
    const src = read(file);
    const muted = token(src, 'apex-muted');
    for (const surface of ['apex-bg', 'apex-surface', 'apex-card']) {
      const bg = token(src, surface);
      assert.ok(ratio(muted, bg) >= 4.5, `${file}: ${muted} on ${bg} (${surface}) is ${ratio(muted, bg).toFixed(2)}:1`);
    }
  });
}

test('REGRESSION: replacement colours meet 4.5:1 on the tinted backgrounds axe measured them against', () => {
  const pairs = [
    ['#9ca3af', '#1a2535', 'pill / gate chips'], ['#9ca3af', '#2a131c', 'time chip on critical tint'], ['#9ca3af', '#311d2a', 'muted on critical tint'],
    ['#9ca3af', '#252043', 'muted on purple tint'], ['#94a3b8', '#0a0e12', 'trust footer / analyst meta'], ['#ff5c75', '#4a1522', 'actively exploited badge'],
    ['#ff5c80', '#3d0011', 'critical severity badge'], ['#ff5c80', '#560017', 'critical CVSS chip'], ['#ff7a3d', '#0d1117', 'Volt Typhoon'],
    ['#ff6b52', '#0d1117', 'Lazarus Group'], ['#ff5252', '#311d2a', 'critical level label'], ['#c084fc', '#252043', 'ransomware tag'], ['#c084fc', '#1f1532', 'internal badge'],
  ];
  for (const [fg, bg, what] of pairs) assert.ok(ratio(fg, bg) >= 4.5, `${what}: ${fg} on ${bg} is ${ratio(fg, bg).toFixed(2)}:1`);
});

test('the specific severity / tag colours were applied where axe measured the failures', () => {
  assert.match(read('auto-intel-engine.js'), /\.badge-exploit\{[^}]*color:#ff5c75;/);
  assert.match(read('intelligence.html'), /\.severity-badge\.critical \{[^}]*color: #ff5c80;/);
  assert.match(read('intelligence.html'), /\.card-cvss\.critical \{[^}]*color: #ff5c80;/);
  assert.match(read('malware/index.html'), /style="color:#ff7a3d">Volt Typhoon/);
  assert.match(read('malware/index.html'), /style="color:#ff6b52">Lazarus Group/);
  assert.match(read('detections/index.html'), /\.lvl-critical\{[^}]*color:#ff5252;/);
  assert.match(read('detections/index.html'), /\.rw\{[^}]*color:#c084fc;/);
  assert.match(read('workbench.html'), /\.internal-badge\{[^}]*color:#c084fc;/);
});

// ── 1.4.1: links inside muted body text cannot rely on colour alone once the text is light enough to pass AA ──────────────────
test('REGRESSION: the cyan links inside muted footer / breadcrumb text are underlined', () => {
  for (const [file, selectors] of [['detections/index.html', ['.crumb a', 'footer a']], ['hunts.html', ['footer a']], ['api-dashboard.html', ['footer a']]]) {
    const src = read(file);
    for (const sel of selectors) {
      const rule = src.match(new RegExp(`(?:^|[}\\n])${sel.replace(/\./g, '\\.')}\\{([^}]*)\\}`)); // anchored: not `.cta-footer a{`
      assert.ok(rule, `${file}: no ${sel} rule`);
      assert.match(rule[1], /text-decoration:underline/, `${file}: ${sel} must be underlined`);
      assert.doesNotMatch(rule[1], /text-decoration:none/, `${file}: ${sel} must not remove the underline`);
    }
  }
  const mail = read('intelligence.html').match(/class="footer-meta"[\s\S]*?<a href="mailto:bivash@cyberdudebivash\.com" style="([^"]*)"/); // the footer link, not the earlier CTA button
  assert.ok(mail, 'intelligence.html footer mailto link not found');
  assert.match(mail[1], /text-decoration:underline/);
});

test('REGRESSION: intelligence.html has no default-blue links (nav Products, footer About/Privacy/Terms)', () => {
  const src = read('intelligence.html');
  assert.match(src, /<a href="\/products\.html" class="nav-link">Products<\/a>/);
  assert.match(src, /<div class="footer-meta"/);
  assert.match(src, /\.footer-meta a \{ color: var\(--apex-muted\);/);
});
