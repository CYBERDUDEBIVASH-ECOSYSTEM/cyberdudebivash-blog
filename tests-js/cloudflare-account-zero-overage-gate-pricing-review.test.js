'use strict';
// P0: the 2026-12-01 Observability pricing cutoff previously rejected EVERY
// billing cycle that ends after the cutoff, including next month's cycle at
// zero usage, so no release could ever pass again without editing the gate.
// These tests pin the replacement contract:
//   * cycles ending on/before the cutoff behave exactly as before;
//   * a crossing cycle passes the pricing check ONLY with a fresh, structured,
//     zero-charge owner pricing review;
//   * the review never relaxes any usage meter or any other gate code.
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {assess,PLAN,PRICE_REVIEW_CUTOFF,MAX_PRICING_REVIEW_AGE_MS}=require('../scripts/cloudflare-account-zero-overage-gate.cjs');

const ACCOUNT='a'.repeat(32);
const hash=s=>crypto.createHash('sha256').update(s).digest('hex');
const NOW='2026-11-24T06:00:00.000Z';

function review(over={}){
  return {
    schemaVersion:'cdb-observability-pricing-review/v1',
    reviewedAt:'2026-11-24T04:00:00.000Z',
    pricingSourceReference:'CLOUDFLARE-OBSERVABILITY-PRICING-2026-12-01',
    operatorApprovalReference:'OWNER-APPROVAL-20261124',
    evidenceSha256:'c'.repeat(64),
    allWorkersObservabilitySettingsReviewed:true,
    projectedPostCutoffAdditionalMeteredChargesUsd:0,
    ...over
  };
}
function crossing(){
  return {
    schemaVersion:'cdb-cloudflare-shared-budget/v1',
    accountScope:'ALL_PLATFORMS_SINGLE_CLOUDFLARE_ACCOUNT',
    accountCoverageConfirmed:true,
    allActiveMeteredServicesReviewed:true,
    reviewedPlatforms:['sentinel-apex-threat-intel','sentinel-apex-ai-security-hub','sentinel-apex-soc','nilachala-devotional'],
    accountFingerprintSha256:hash(ACCOUNT),
    source:'cloudflare-account-billing-and-service-metrics',
    privateEvidenceSha256:'b'.repeat(64),
    operatorApprovalReference:'OWNER-APPROVAL-20261124',
    operatorReviewed:true,
    verifiedWorkersPlan:'paid-standard',
    r2StorageClass:'standard-only',
    anyInfrequentAccessStorage:false,
    unmodeledBillableServicesPresent:false,
    optionalPaidProductsOrAddonsPresent:false,
    currentAccountProjectedOverageUsd:0,
    accountBillingCurrency:'USD',
    accountMonthToDateAdditionalMeteredChargesUsd:0,
    forecastAccountAdditionalMeteredChargesUsd:0,
    // Ends 2026-12-03: crosses the 2026-12-01 pricing cutoff.
    cycle:{start:'2026-11-03T00:00:00.000Z',end:'2026-12-03T00:00:00.000Z'},
    capturedAt:'2026-11-24T05:00:00.000Z',
    metrics:Object.fromEntries(Object.entries(PLAN).map(([name,limit])=>
      [name,{used:limit*0.1,forecastRemaining:limit*0.2}]))
  };
}
const run=(mutate)=>{const s=crossing();mutate(s);return assess(s,ACCOUNT,NOW);};

test('cutoff constant and review window are unchanged / explicit',()=>{
  assert.equal(PRICE_REVIEW_CUTOFF,'2026-12-01T00:00:00.000Z');
  assert.equal(MAX_PRICING_REVIEW_AGE_MS,14*24*60*60*1000);
});

test('a crossing cycle WITHOUT a review still HOLDs on NEW_PRICING_REVIEW_REQUIRED (default behaviour preserved)',()=>{
  const r=run(()=>{});
  assert.equal(r.ok,false);
  assert.deepEqual(r.codes,['NEW_PRICING_REVIEW_REQUIRED']);
});

test('a crossing cycle with a fresh, complete, zero-charge review passes',()=>{
  const r=run(s=>{s.postCutoffPricingReview=review();});
  assert.deepEqual(r,{ok:true,codes:[]});
});

test('a cycle ending exactly at the cutoff needs no review and is unaffected by one',()=>{
  const base=s=>{s.cycle={start:'2026-11-01T00:00:00.000Z',end:PRICE_REVIEW_CUTOFF};};
  assert.deepEqual(run(base),{ok:true,codes:[]});
  assert.deepEqual(run(s=>{base(s);s.postCutoffPricingReview=review();}),{ok:true,codes:[]});
  // A garbage review on a non-crossing cycle must not matter either.
  assert.deepEqual(run(s=>{base(s);s.postCutoffPricingReview='junk';}),{ok:true,codes:[]});
});

const invalid={
  'wrong schema version':{schemaVersion:'cdb-observability-pricing-review/v0'},
  'missing schema version':{schemaVersion:undefined},
  'reviewedAt not ISO-Z':{reviewedAt:'2026-11-24 04:00'},
  'reviewedAt in the future':{reviewedAt:'2026-11-24T07:00:00.000Z'},
  'reviewedAt older than 14 days':{reviewedAt:new Date(Date.parse(NOW)-MAX_PRICING_REVIEW_AGE_MS-1000).toISOString().replace(/\.\d{3}Z$/,'.000Z')},
  'pricing source reference missing':{pricingSourceReference:undefined},
  'pricing source reference is a placeholder':{pricingSourceReference:'PLACEHOLDER-REFERENCE-1'},
  'pricing source reference too short':{pricingSourceReference:'short'},
  'approval reference is TBD':{operatorApprovalReference:'TBD-APPROVAL-REF-1'},
  'evidence hash not sha256':{evidenceSha256:'not-a-hash'},
  'evidence hash wrong length':{evidenceSha256:'c'.repeat(63)},
  'observability settings not reviewed (false)':{allWorkersObservabilitySettingsReviewed:false},
  'observability settings not reviewed (truthy string)':{allWorkersObservabilitySettingsReviewed:'true'},
  'projected charge is non-zero':{projectedPostCutoffAdditionalMeteredChargesUsd:0.01},
  'projected charge is a string zero':{projectedPostCutoffAdditionalMeteredChargesUsd:'0'},
  'projected charge is null':{projectedPostCutoffAdditionalMeteredChargesUsd:null},
  'projected charge missing':{projectedPostCutoffAdditionalMeteredChargesUsd:undefined},
};
for(const [name,over] of Object.entries(invalid)){
  test('crossing cycle HOLDs when the review is invalid: '+name,()=>{
    const r=run(s=>{s.postCutoffPricingReview=review(over);});
    assert.equal(r.ok,false);
    assert.ok(r.codes.includes('NEW_PRICING_REVIEW_REQUIRED'),r.codes.join(','));
  });
}

for(const [name,value] of [['array',[review()]],['string','true'],['boolean',true],['null',null],['number',1]]){
  test('crossing cycle HOLDs when postCutoffPricingReview is a '+name,()=>{
    const r=run(s=>{s.postCutoffPricingReview=value;});
    assert.equal(r.ok,false);
    assert.ok(r.codes.includes('NEW_PRICING_REVIEW_REQUIRED'));
  });
}

test('a valid review never masks any other gate failure',()=>{
  const cases=[
    ['RESERVE_EXHAUSTED_workersCpuMs',s=>{s.metrics.workersCpuMs={used:PLAN.workersCpuMs*0.85,forecastRemaining:0};}],
    ['RESERVE_EXHAUSTED_workersLogEvents',s=>{s.metrics.workersLogEvents={used:PLAN.workersLogEvents*0.9,forecastRemaining:0};}],
    ['ADDITIONAL_METERED_SPEND_NOT_ZERO',s=>{s.forecastAccountAdditionalMeteredChargesUsd=0.02;}],
    ['OVERAGE_ALREADY_PROJECTED',s=>{s.currentAccountProjectedOverageUsd=1;}],
    ['FRESH_USAGE_EVIDENCE_REQUIRED',s=>{s.capturedAt='2026-11-24T02:00:00.000Z';}],
    ['SOURCE_AND_APPROVAL_NOT_VERIFIED',s=>{s.operatorReviewed=false;}],
  ];
  for(const [code,mutate] of cases){
    const r=run(s=>{s.postCutoffPricingReview=review();mutate(s);});
    assert.equal(r.ok,false,code);
    assert.ok(r.codes.includes(code),code+' missing from '+r.codes.join(','));
    assert.ok(!r.codes.includes('NEW_PRICING_REVIEW_REQUIRED'),'pricing code must be satisfied by the review');
  }
});

test('the review is accepted at exactly the 14-day boundary and rejected one second later',()=>{
  const at=ms=>new Date(Date.parse(NOW)-ms).toISOString().replace(/\.\d{3}Z$/,'.000Z');
  assert.deepEqual(run(s=>{s.postCutoffPricingReview=review({reviewedAt:at(MAX_PRICING_REVIEW_AGE_MS)});}),{ok:true,codes:[]});
  const late=run(s=>{s.postCutoffPricingReview=review({reviewedAt:at(MAX_PRICING_REVIEW_AGE_MS+1000)});});
  assert.ok(late.codes.includes('NEW_PRICING_REVIEW_REQUIRED'));
});
