'use strict';
/**
 * workbench.html rendered related graph entities as
 *     onclick="Workbench.loadEntity('${esc(r.id || r.entityId)}')"
 * esc() is an HTML escaper. In an attribute the browser decodes &#39; back to ' BEFORE the handler is parsed, so a quote in the
 * identifier ended the JS string. Measured on the real page with a related-entity list: of six identifiers, an apostrophe in a
 * legitimate URL indicator raised "SyntaxError: missing ) after argument list" (the click did nothing), and a crafted identifier ran
 * injected code.
 *
 * The handler now receives `jsArg(id)`: JSON.stringify makes a valid JS string literal, esc() makes it safe in a double-quoted attribute.
 * This test decodes the attribute exactly as a browser does and executes the handler in a vm with a spy.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const PAGE = fs.readFileSync(path.join(__dirname, '..', 'workbench.html'), 'utf8');

function extractFunction(src, name) {
  const start = src.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `function ${name} not found in workbench.html`);
  const open = src.indexOf('{', src.indexOf(')', start));
  let depth = 0;
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(start, i + 1);
  }
  throw new Error(`unbalanced braces in ${name}`);
}

const ctx = vm.createContext({});
vm.runInContext(`${extractFunction(PAGE, 'esc')}\n${extractFunction(PAGE, 'jsArg')}\nthis.esc = esc; this.jsArg = jsArg;`, ctx);
const { esc, jsArg } = ctx;

// what a browser does with an attribute value before it hands it to the JS parser
const decodeAttr = v => v.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

/** Render a handler attribute with `argumentSource`, decode it, run it; returns what the handler received and any side effects. */
function click(attrValueTemplate) {
  const html = `<div class="entity-card" onclick="${attrValueTemplate}">x</div>`;
  const m = html.match(/onclick="([^"]*)"/);
  assert.ok(m, `attribute broke apart: ${html}`);
  const received = []; const side = [];
  const sandbox = vm.createContext({ Workbench: { loadEntity: (...a) => received.push(a) }, window: { __pwn: side } });
  let error = null;
  try { vm.runInContext(decodeAttr(m[1]), sandbox); } catch (e) { error = e.name; }
  return { received, side, error, html };
}

const IDS = [
  'plain-id-123',
  'ioc:url:http://evil.example/a\'b',
  "x');window.__pwn.push('INJECTED');//",
  'back\\slash\'q',
  'dq"id',
  '</script><b onmouseover=1>',
  ' line sep',
  'a&b<c>d',
  '',
];

for (const id of IDS) {
  test(`jsArg: the handler receives exactly ${JSON.stringify(id).slice(0, 40)} and nothing else runs`, () => {
    const r = click(`Workbench.loadEntity(${jsArg(id)})`);
    assert.equal(r.error, null, `handler threw ${r.error}`);
    assert.deepEqual(r.received, [[id]]);
    assert.deepEqual(r.side, [], 'injected code ran');
  });
}

test('CONTROL: the previous pattern breaks on an apostrophe and runs injected code (so the harness can tell)', () => {
  const old = id => click(`Workbench.loadEntity('${esc(id)}')`);
  assert.equal(old("ioc:url:http://evil.example/a'b").error, 'SyntaxError');
  const attack = old("x');window.__pwn.push('INJECTED');//");
  assert.deepEqual(attack.side, ['INJECTED']);
});

test('jsArg treats null and undefined as an empty string, like esc()', () => {
  assert.equal(decodeAttr(jsArg(null)), '""');
  assert.equal(decodeAttr(jsArg(undefined)), '""');
  assert.equal(decodeAttr(jsArg(42)), '"42"');
});

test('source contract: the related-entity card passes its id through jsArg, not a quoted esc()', () => {
  assert.match(PAGE, /onclick="Workbench\.loadEntity\(\$\{jsArg\(r\.id \|\| r\.entityId\)\}\)"/);
  assert.doesNotMatch(PAGE, /loadEntity\('\$\{esc\(/);
});
