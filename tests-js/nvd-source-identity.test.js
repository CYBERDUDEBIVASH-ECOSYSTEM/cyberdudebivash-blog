'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {nvdSourceIdentity}=require('../fetch-live-intel.js');

test('new Wordfence/NVD WordPress product identity is source-backed, never Unknown Vendor The',()=>{
  const known=[
    ['The Swift Performance Lite plugin for WordPress is vulnerable to Stored Cross-Site Scripting via an AJAX parameter.', 'Swift Performance Lite'],
    ['The Accept Stripe Payments plugin for WordPress is vulnerable to Stored DOM-Based Cross-Site Scripting.', 'Accept Stripe Payments'],
    ['The Orphans plugin for WordPress is vulnerable to Stored Cross-Site Scripting.', 'Orphans']
  ];
  for(const [description,product] of known){
    const x=nvdSourceIdentity({configurations:[]},description);
    assert.deepEqual(x,{vendor:'',product,subject:product});
    assert.doesNotMatch(x.subject,/Unknown Vendor|^The /);
  }
});

test('structured CPE vendor and product override unrelated narrative; wildcard fields are never identities',()=>{
  const record={configurations:[{nodes:[{cpeMatch:[{
    criteria:'cpe:2.3:a:wordpress:wp_forms:1.0:*:*:*:*:*:*:*'
  }]}]}]};
  assert.deepEqual(nvdSourceIdentity(record,'The Other plugin for WordPress is vulnerable.'),{
    vendor:'wordpress', product:'wp forms',subject:'wordpress wp forms'
  });
  const wildcard={configurations:[{nodes:[{cpeMatch:[{
    criteria:'cpe:2.3:a:*:*:*:*:*:*:*:*:*:*'
  }]}]}]};
  assert.equal(nvdSourceIdentity(wildcard,'No verified product name.').product,'');
  assert.equal(nvdSourceIdentity(wildcard,'No verified product name.').vendor,'');
});

test('unstructured prose and HTML-like payload cannot fabricate vendor or product',()=>{
  const adversarial=[
    'The vendor described a vulnerability without naming an affected product.',
    'A vulnerability in a system of unknown ownership.',
    'The <img src=x onerror=alert(1)> plugin for WordPress is vulnerable.',
    'Swift Performance Lite plugin for WordPress is vulnerable.',
    'The https://attacker.example plugin for WordPress is vulnerable.',
  ];
  for(const description of adversarial){
    const x=nvdSourceIdentity({},description);
    assert.equal(x.vendor,'');
    assert.equal(x.product,'',description);
    assert.equal(x.subject,'Affected software (product not identified)');
  }
});

test('publisher uses source-backed identity in NVD title and retains unchanged no-network source envelope',()=>{
  const source=fs.readFileSync(path.join(__dirname,'..','fetch-live-intel.js'),'utf8');
  assert.match(source,/const \{ vendor, product, subject \} = nvdSourceIdentity\(cve, desc\)/);
  assert.match(source,/title:`\$\{id\} — \$\{subject\} CVSS \$\{cvss\} \$\{sevLabel\}`/);
  assert.doesNotMatch(source, /\|\|'Unknown Vendor'/);
  assert.doesNotMatch(source, /desc\.split\(\/\\s\+\/\)\.slice\(0,3\)/);
  assert.match(source,/const iocs = \[\];/);
});
