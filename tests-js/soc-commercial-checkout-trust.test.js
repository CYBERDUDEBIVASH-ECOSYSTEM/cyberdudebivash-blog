'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const ROOT=path.resolve(__dirname,'..');
const price=fs.readFileSync(path.join(ROOT,'pricing.html'),'utf8');
const dashboard=fs.readFileSync(path.join(ROOT,'api-dashboard.html'),'utf8');
const plans=fs.readFileSync(path.join(ROOT,'intel-plans.js'),'utf8');

test('SOC free API key and separate keyless Community access are clearly distinguished',()=>{
  assert.match(price,/id="free-product-boundary"/);
  assert.match(price,/Two separate free access routes/);
  assert.match(price,/SOC API dashboard/);
  assert.match(price,/SENTINEL APEX Community tier/);
  assert.match(price,/keyless/);
  assert.match(price,/get-api-key\.html\?plan=community/);
  assert.match(dashboard,/100 req\/day/);
  assert.match(price,/100 requests\/day/);
  assert.match(price,/50 requests\/day/);
  assert.match(price,/current SOC service evidence/);
});

test('free landing CTA still points to the non-payment SOC API registration flow',()=>{
  const freeCard=price.match(/<div class="plan-card" id="free">([\s\S]*?)<\/ul>\s*<\/div>/)?.[1];
  assert.ok(freeCard,'Free SOC plan card exists');
  assert.match(freeCard,/api-dashboard\.html/);
  assert.match(freeCard,/Get Free API Key/);
  assert.doesNotMatch(freeCard,/intel\.cyberdudebivash\.com\/upgrade/);
});

test('paid CTA links preserve exact canonical checkout plan and tracked source',()=>{
  for(const p of ['pro','enterprise','mssp']){
    const re=new RegExp('data-intel-plan="'+p+'"[^>]*href="([^"]+)"','g');
    const found=[...price.matchAll(re)];
    assert.ok(found.length>0,p+' CTA required');
    for(const m of found){
      const url=new URL(m[1].replace(/&amp;/g,'&'));
      assert.equal(url.origin,'https://intel.cyberdudebivash.com');
      assert.equal(url.pathname,'/upgrade.html');
      assert.equal(url.searchParams.get('plan'),p);
      assert.equal(url.searchParams.get('utm_campaign'),'plan-checkout');
    }
  }
  assert.match(plans,/plan-checkout/);
});

test('no invented live-freshness or unsupported customer social proof appears on pricing CTA',()=>{
  assert.doesNotMatch(price,/Get started with live threat data/);
  assert.doesNotMatch(price,/Join security teams using SENTINEL APEX/);
  assert.match(price,/verify the current feed freshness before integration/);
  assert.match(price,/Review current intelligence freshness evidence, plan entitlements and checkout terms/);
});

test('paid plan price display retains dynamic canonical pricing rather than fictitious amounts',()=>{
  for(const plan of ['PRO','ENTERPRISE','MSSP']){
    assert.match(price,new RegExp('data-intel-price="'+plan+'"'));
  }
  assert.match(price,/Prices are never hardcoded here/);
  assert.match(price,/see the exact amount before you pay/);
});
