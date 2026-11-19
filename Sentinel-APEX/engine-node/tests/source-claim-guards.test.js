'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { validCves, verifiedAffectedTechnology, sourceDescribesConcreteEncryption, NON_VENDOR_LABELS } = require('../source-claim-guards');
const { NON_VENDOR_LABELS: HUB_NON_VENDORS } = require('../../../api/_lib/intelligence-hub');
const { buildReasoning } = require('../reasoning-engine');
const { buildProducts } = require('../products-engine');
const { AnalystMemory } = require('../analyst-memory');

const news = {
  id: 'DARKREADING-0c597ec3c532313d',
  title: 'AttackIQ Research Reveals Iranian network access transfers and ransomware',
  desc: 'Research on twenty Iranian groups maps espionage, ransomware, hacktivism and access handoffs.',
  vendor: 'darkreading', product: 'Threat Intelligence', link: 'https://www.darkreading.com/report',
  cves: [], iocs: [],
};
const verifiedCve = {
  id: 'CVE-2024-4577', title: 'LockBit exploits PHP deployment',
  desc: 'Attackers deleted volume shadow copies with vssadmin before encrypting files.',
  vendor: 'PHP', product: 'PHP-CGI', cves: ['CVE-2024-4577'],
  cvss: 9.8, cisaKev: true, exploited: true,
};

test('source categories remain in sync with canonical hub non-vendor labels', () => {
  assert.deepEqual([...NON_VENDOR_LABELS].sort(), [...HUB_NON_VENDORS].sort());
});
test('news publisher not reported as verified affected vendor or product', () => {
  assert.equal(verifiedAffectedTechnology(news), null);
  const reasoning = buildReasoning(news);
  assert.ok(!reasoning.facts.some(x => /Affected technology/.test(x)));
  assert.ok(reasoning.gaps.some(x => /reporting publisher/.test(x)));
});
test('ransomware headline alone never becomes observed encryption or HIGH event confidence', () => {
  assert.equal(sourceDescribesConcreteEncryption(news), false);
  const reasoning = buildReasoning(news);
  assert.ok(!reasoning.assessments.some(a => a.confidence === 'HIGH' && /ransomware operation|encryption/.test(a.text)));
  assert.ok(!reasoning.assessments.some(a => /was observed/.test(a.text)));
  assert.ok(!reasoning.outlook.some(o => /Double-extortion/.test(o.text)));
});
test('news API and customer products do not invent affected technology or default HIGH severity', () => {
  const products = buildProducts(news);
  assert.equal(products.apiPackage.vendor, null);
  assert.equal(products.apiPackage.product, null);
  assert.equal(products.apiPackage.affected_technology_status, 'NOT_ESTABLISHED');
  assert.equal(products.apiPackage.severity, 'UNASSESSED');
  assert.equal(products.socBulletin.affectedTechnology, 'NOT_ESTABLISHED');
  assert.deepEqual(products.socBulletin.detectionCoverage.techniques, []);
  assert.ok(!products.executiveAdvisory.headline.includes('affecting darkreading'));
  assert.ok(!products.boardBrief.bullets.some(x => /threat affects darkreading/i.test(x)));
  assert.ok(!products.executiveAdvisory.decisions.some(x => /darkreading assets|patching of darkreading/i.test(x.decision)));
});
test('legitimate CVE vendor, severity and source-described behavior preserved', () => {
  assert.deepEqual(validCves(verifiedCve), ['CVE-2024-4577']);
  assert.equal(verifiedAffectedTechnology(verifiedCve), 'PHP PHP-CGI');
  assert.equal(sourceDescribesConcreteEncryption(verifiedCve), true);
  const p = buildProducts(verifiedCve);
  assert.equal(p.apiPackage.vendor, 'PHP');
  assert.equal(p.apiPackage.product, 'PHP-CGI');
  assert.equal(p.apiPackage.severity, 'CRITICAL');
  assert.ok(p.executiveAdvisory.headline.includes('affecting PHP PHP-CGI'));
  assert.ok(buildReasoning(verifiedCve).assessments.some(x => x.confidence === 'HIGH' && /ransomware operation/.test(x.text)));
});
test('repeated source mentions are not called targeted victims', () => {
  const mem = new AnalystMemory();
  mem.ingest(news, 'prior-1'); mem.ingest(news, 'prior-2');
  const notes = mem.correlationNotes(news);
  assert.ok(notes.some(x => /darkreading was mentioned/.test(x)), JSON.stringify(notes));
  assert.ok(!notes.some(x => /has been targeted|recurring target/.test(x)), JSON.stringify(notes));
});
test('malformed CVEs and journalist sources fail closed without extra technology claims', () => {
  assert.deepEqual(validCves({id:'NEWS-1',cves:['fake']}), []);
  assert.equal(verifiedAffectedTechnology({...news,cves:['CVE-2026-123456']}), null);
  assert.equal(verifiedAffectedTechnology({id:'NEWS-1',vendor:'Fortinet',product:'FortiOS'}), null);
  assert.equal(verifiedAffectedTechnology(null), null);
});
