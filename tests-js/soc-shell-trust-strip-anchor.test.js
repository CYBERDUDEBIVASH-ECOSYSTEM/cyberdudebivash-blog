'use strict';
/**
 * Regression: the conversion-engine trust strip must never be placed inside the SOC shell.
 *
 * scripts/soc-platform-presentation.cjs injects the shell straight after <body>, so the first <nav> in document
 * order is the shell's own nav. The strip used to anchor on `document.querySelector('nav')` and landed inside the
 * shell's flex row: the shell grew from ~76px to 222-404px, its nav wrapped into rows and the page shifted late
 * (measured on soc.cyberdudebivash.in: CLS 0.36 on the homepage, 0.35 on articles, ~98% of pages).
 *
 * The strip logic runs in a browser, so it is extracted from the real source and executed against a small fake DOM
 * that supports only what the injector touches.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { SHELL } = require('../scripts/soc-platform-presentation.cjs');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'conversion-engine.js'), 'utf8');

function extractTrust() {
  const start = SRC.indexOf('var TRUST = (function () {');
  const ret = SRC.indexOf('return { inject: inject };', start);
  assert.ok(start > 0 && ret > start, 'TRUST section not found in conversion-engine.js');
  return SRC.slice(start, SRC.indexOf('}());', ret) + 4);
}

class FakeNode {
  constructor(tag, className = '', id = '') {
    this.tagName = tag.toUpperCase();
    this.className = className;
    this.id = id;
    this.parentNode = null;
    this.childNodes = [];
    this.innerHTML = '';
  }
  get firstElementChild() { return this.childNodes[0] || null; }
  get nextSibling() {
    return this.parentNode ? this.parentNode.childNodes[this.parentNode.childNodes.indexOf(this) + 1] || null : null;
  }
  appendChild(child) { child.parentNode = this; this.childNodes.push(child); return child; }
  insertBefore(child, ref) {
    child.parentNode = this;
    if (!ref) this.childNodes.push(child); else this.childNodes.splice(this.childNodes.indexOf(ref), 0, child);
    return child;
  }
  descendants() { return this.childNodes.flatMap(c => [c, ...c.descendants()]); }
}

const h = (tag, className = '', children = [], id = '') => {
  const n = new FakeNode(tag, className, id);
  children.forEach(c => n.appendChild(c));
  return n;
};
const hasClass = (n, cls) => (' ' + n.className + ' ').includes(' ' + cls + ' ');

/** The shell exactly as the build emits it: identity link, nav, action (see SHELL in soc-platform-presentation.cjs). */
const shell = () => h('div', 'soc-unified-shell', [h('div', 'soc-unified-shell__inner', [
  h('a', 'soc-unified-shell__identity'), h('nav', 'soc-unified-shell__nav'), h('a', 'soc-unified-shell__action')])]);

function run(bodyChildren) {
  const body = h('body', '', bodyChildren);
  const events = [];
  const document = {
    body,
    getElementById: id => body.descendants().find(n => n.id === id) || null,
    querySelectorAll: sel => body.descendants().filter(n => sel[0] === '.' ? hasClass(n, sel.slice(1)) : n.tagName === sel.toUpperCase()),
    querySelector(sel) {
      if (sel === 'body > div:first-child') { const f = body.childNodes[0]; return f && f.tagName === 'DIV' ? f : null; }
      return this.querySelectorAll(sel)[0] || null;
    },
  };
  const sandbox = {
    document, css() {}, el: (tag, attrs) => new FakeNode(tag, '', (attrs && attrs.id) || ''), CYAN: '#0ff',
    CFG: { trust: { evidence: 'Source-linked', freshness: 'Runtime-verified', delivery: 'Cloudflare', controls: 'Fail-closed' } },
    window: { trackEvent: name => events.push(name) },
  };
  const TRUST = vm.runInNewContext(extractTrust() + '\nTRUST;', sandbox);
  TRUST.inject();
  return { body, events, strip: body.descendants().find(n => n.id === 'cx4-trust-strip') || null, TRUST };
}

test('REGRESSION: with the SOC shell present, the strip is a page-level sibling of the page nav, never inside the shell', () => {
  const drawer = h('nav', 'mobile-nav-drawer', [], 'mobileNavDrawer');
  const s = shell();
  const { body, strip } = run([h('a', 'cx-skip-link'), s, drawer, h('header', '', [h('nav')], 'main-header')]);
  assert.ok(strip, 'strip injected');
  assert.equal(strip.parentNode, body, 'strip is a direct child of <body>');
  assert.equal(body.childNodes[body.childNodes.indexOf(drawer) + 1], strip, 'strip sits right after the page nav, below the shell');
  assert.equal(s.childNodes[0].childNodes.length, 3, "the shell's flex row still has exactly identity, nav, action");
  assert.ok(!s.descendants().includes(strip));
});

test('REGRESSION: a nav nested anywhere inside the shell is never an anchor', () => {
  const pageNav = h('nav', 'page-nav');
  const s = h('div', 'soc-unified-shell', [h('div', 'soc-unified-shell__inner', [h('div', '', [h('nav', 'deep')])])]);
  const { body, strip } = run([s, h('main'), pageNav]);
  assert.ok(strip, 'strip injected');
  assert.equal(strip.parentNode, body);
  assert.equal(body.childNodes[body.childNodes.indexOf(pageNav) + 1], strip, 'strip follows the page nav, not the deeply nested shell nav');
  assert.ok(!s.descendants().includes(strip));
});

test('a page whose only <nav> and <header> live inside the shell gets the strip right after the shell', () => {
  const s = shell();
  const { body, strip } = run([h('a', 'cx-skip-link'), s, h('main')]);
  assert.equal(strip.parentNode, body);
  assert.equal(body.childNodes[body.childNodes.indexOf(s) + 1], strip);
});

test('a <header> inside the shell is never an anchor either (future shell markup)', () => {
  const s = h('div', 'soc-unified-shell', [h('div', 'soc-unified-shell__inner', [h('header', 'shell-header')])]);
  const { body, strip } = run([h('a', 'cx-skip-link'), s, h('main')]);
  assert.equal(strip.parentNode, body);
  assert.equal(body.childNodes[body.childNodes.indexOf(s) + 1], strip);
  assert.ok(!s.descendants().includes(strip));
});

test('page header nav is preferred over body-level fallbacks (strip lands after the page nav)', () => {
  const pageNav = h('nav', 'main');
  const header = h('header', '', [pageNav], 'main-header');
  const { strip } = run([shell(), header]);
  assert.equal(strip.parentNode, header);
  assert.equal(header.childNodes[header.childNodes.indexOf(pageNav) + 1], strip);
});

test('unchanged behaviour on a page without the shell: strip goes after the first nav', () => {
  const nav = h('nav');
  const wrap = h('div', '', [nav, h('main')]);
  const { strip } = run([wrap]);
  assert.equal(strip.parentNode, wrap);
  assert.equal(wrap.childNodes[1], strip);
});

test('a page that already ships its own .cdb-trust-strip does not get a duplicate', () => {
  const { strip, events } = run([shell(), h('div', 'cdb-trust-strip'), h('header', '', [h('nav')])]);
  assert.equal(strip, null);
  assert.deepEqual(events, []);
});

test('injecting twice never creates a second strip', () => {
  const { body, TRUST } = run([shell(), h('nav')]);
  TRUST.inject();
  assert.equal(body.descendants().filter(n => n.id === 'cx4-trust-strip').length, 1);
});

test('CONTRACT: the class the injector avoids is the class the build emits for the shell', () => {
  assert.match(SHELL, /class="soc-unified-shell"/);
  assert.match(SRC, /' soc-unified-shell '/, 'conversion-engine.js must keep recognising the shell by its class');
  assert.match(SHELL, /<nav class="soc-unified-shell__nav"/, 'the shell nav lives inside .soc-unified-shell');
});
