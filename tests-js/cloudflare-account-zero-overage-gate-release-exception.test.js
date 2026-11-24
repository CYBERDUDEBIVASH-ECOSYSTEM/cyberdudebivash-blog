'use strict';
// Single-release CPU reserve exception.
// Contract under test:
//   * it waives ONLY RESERVE_EXHAUSTED_workersCpuMs and never any other code;
//   * it is bound to the exact release SHA (supplied by the CLI from git HEAD);
//   * it expires within 24h and never later than the 2026-12-01 pricing cutoff;
//   * it NEVER permits a projected CPU overage: measured-rate projection with
//     the gate's 1.25 buffer, and the owner's own forecast, must both fit in
//     100% of the plan, and the forecast may not understate the measurement;
//   * results for every caller that does not use it keep the exact {ok,codes}
//     shape.
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const fs=require('node:fs');
const path=require('node:path');
const {assess,PLAN,PRICE_REVIEW_CUTOFF,MAX_EXCEPTION_WINDOW_MS}=require('../scripts/cloudflare-account-zero-overage-gate.cjs');

const ACCOUNT='a'.repeat(32);
const SHA='0123456789abcdef0123456789abcdef01234567';
const CPU='RESERVE_EXHAUSTED_workersCpuMs';
const hash=s=>crypto.createHash('sha256').update(s).digest('hex');
const iso=ms=>new Date(ms).toISOString().replace(/\.\d{3}Z$/,'.000Z');
const NOW='2026-11-24T06:00:00.000Z';
const END=Date.parse('2026-12-03T00:00:00.000Z');

function attestation(nowIso,{used=21.0e6,recent=0.5e6,forecast}={}){
  const now=Date.parse(nowIso);
  const remainingDays=(END-now)/86400000;
  const metrics=Object.fromEntries(Object.entries(PLAN).map(([n,l])=>[n,{used:l*0.1,forecastRemaining:l*0.2}]));
  metrics.workersCpuMs={used,forecastRemaining:forecast===undefined?recent*remainingDays:forecast};
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
    cycle:{start:'2026-11-03T00:00:00.000Z',end:'2026-12-03T00:00:00.000Z'},
    capturedAt:iso(now-3600e3),
    postCutoffPricingReview:{
      schemaVersion:'cdb-observability-pricing-review/v1',
      reviewedAt:iso(now-7200e3),
      pricingSourceReference:'CLOUDFLARE-OBSERVABILITY-PRICING-2026-12-01',
      operatorApprovalReference:'OWNER-APPROVAL-20261124',
      evidenceSha256:'c'.repeat(64),
      allWorkersObservabilitySettingsReviewed:true,
      projectedPostCutoffAdditionalMeteredChargesUsd:0
    },
    metrics
  };
}
function exception(nowIso,over={}){
  const now=Date.parse(nowIso);
  const {cpuMeasurement:m,...rest}=over;
  return {
    schemaVersion:'cdb-budget-release-exception/v1',
    scope:'single-release-cpu-reserve',
    waives:[CPU],
    approvedReleaseSha:SHA,
    approvedAt:iso(now-3600e3),
    expiresAt:iso(now+12*3600e3),
    approvedBy:'OWNER-APPROVAL-20261124',
    rationaleReference:'SOC-RELEASE-RATIONALE-20261124',
    evidenceSha256:'d'.repeat(64),
    cpuMeasurement:{windowHours:48,measuredAt:iso(now-1800e3),recentMsPerDay:0.5e6,...(m||{})},
    ...rest
  };
}
const run=({now=NOW,att={},ex,ctx={releaseSha:SHA},mutate}={})=>{
  const a=attestation(now,att);
  if(ex!==false)a.releaseException=exception(now,ex);
  if(mutate)mutate(a);
  return assess(a,ACCOUNT,now,ctx);
};

test('without the exception the realistic post-fix CPU state HOLDs only on the CPU reserve',()=>{
  const r=run({ex:false});
  assert.equal(r.ok,false);
  assert.deepEqual(r.codes,[CPU]);
  assert.equal('exception' in r,false);
});

test('a valid, SHA-bound, expiring exception with a safe measured rate passes and is reported',()=>{
  const r=run();
  assert.equal(r.ok,true);
  assert.deepEqual(r.codes,[]);
  assert.deepEqual(r.exception,{waived:CPU,approvedReleaseSha:SHA,expiresAt:iso(Date.parse(NOW)+12*3600e3)});
});

test('result shape is byte-identical for callers that never use the exception',()=>{
  const a=attestation(NOW,{used:1e6,recent:0.1e6});
  delete a.releaseException;
  assert.deepEqual(assess(a,ACCOUNT,NOW),{ok:true,codes:[]});
  // An exception supplied when nothing needs waiving is ignored and not reported.
  a.releaseException=exception(NOW);
  assert.deepEqual(assess(a,ACCOUNT,NOW,{releaseSha:SHA}),{ok:true,codes:[]});
});

// ---- binding to the release -------------------------------------------------
test('rejected when no release SHA is supplied or it cannot be determined',()=>{
  // `null` is used instead of `undefined` so run()'s default context is not applied.
  for(const ctx of [null,{},{releaseSha:''},{releaseSha:null},{releaseSha:123}]){
    const r=run({ctx});
    assert.equal(r.ok,false,JSON.stringify(ctx));assert.deepEqual(r.codes,[CPU]);
  }
  // And a caller that omits the 4th argument entirely (every pre-existing caller).
  const a=attestation(NOW);a.releaseException=exception(NOW);
  assert.deepEqual(assess(a,ACCOUNT,NOW).codes,[CPU]);
});
test('rejected when the SHA differs, is malformed, or differs only by case',()=>{
  const other='f'.repeat(40);
  assert.deepEqual(run({ctx:{releaseSha:other}}).codes,[CPU]);
  assert.deepEqual(run({ex:{approvedReleaseSha:other}}).codes,[CPU]);
  assert.deepEqual(run({ex:{approvedReleaseSha:SHA.slice(0,39)},ctx:{releaseSha:SHA.slice(0,39)}}).codes,[CPU]);
  assert.deepEqual(run({ex:{approvedReleaseSha:SHA.toUpperCase()},ctx:{releaseSha:SHA.toUpperCase()}}).codes,[CPU]);
  assert.deepEqual(run({ex:{approvedReleaseSha:SHA.toUpperCase()}}).codes,[CPU]);
});

// ---- scope / schema / waives -----------------------------------------------
test('rejected on wrong schema, scope, or any waives list other than exactly the CPU code',()=>{
  for(const over of [
    {schemaVersion:'cdb-budget-release-exception/v0'},
    {scope:'anything-else'},
    {waives:[]},
    {waives:['RESERVE_EXHAUSTED_r2ClassA']},
    {waives:[CPU,'RESERVE_EXHAUSTED_r2ClassA']},
    {waives:[CPU,CPU]},
    {waives:CPU},
  ]){
    const r=run({ex:over});
    assert.equal(r.ok,false,JSON.stringify(over));assert.deepEqual(r.codes,[CPU]);
  }
});
test('rejected for non-object exception values',()=>{
  for(const v of [null,true,'yes',1,[exception(NOW)]]){
    const r=run({ex:false,mutate:a=>{a.releaseException=v;}});
    assert.equal(r.ok,false);assert.deepEqual(r.codes,[CPU]);
  }
});

// ---- time-boxing -----------------------------------------------------------
test('rejected when expired, not yet approved, malformed, or longer than 24h',()=>{
  const now=Date.parse(NOW);
  for(const over of [
    {expiresAt:iso(now-1000)},
    {expiresAt:iso(now)},
    {approvedAt:iso(now+60e3),expiresAt:iso(now+3600e3)},
    {approvedAt:'2026-11-24 05:00'},
    {expiresAt:'tomorrow'},
    {approvedAt:iso(now-3600e3),expiresAt:iso(now-3600e3+MAX_EXCEPTION_WINDOW_MS+1000)},
  ]){
    const r=run({ex:over});
    assert.equal(r.ok,false,JSON.stringify(over));assert.deepEqual(r.codes,[CPU]);
  }
  // Exactly 24h is allowed.
  assert.equal(run({ex:{approvedAt:iso(now-3600e3),expiresAt:iso(now-3600e3+MAX_EXCEPTION_WINDOW_MS)}}).ok,true);
});
test('can never outlive the 2026-12-01 pricing cutoff',()=>{
  const late='2026-11-30T20:00:00.000Z',lateMs=Date.parse(late);
  // used is raised so the CPU reserve code genuinely fires at this point of the cycle (2.2 days left);
  // the measured-rate hard floor still holds (23.9M + 0.5M x 2.17d x 1.25 = 25.3M <= 30M).
  const att={used:23.9e6};
  assert.deepEqual(run({now:late,att,ex:false}).codes,[CPU],'precondition: CPU reserve must fire without an exception');
  assert.equal(run({now:late,att,ex:{expiresAt:iso(lateMs+3*3600e3)}}).ok,true,'expires 23:00 Nov 30: allowed');
  const r=run({now:late,att,ex:{expiresAt:iso(lateMs+5*3600e3)}});
  assert.equal(r.ok,false,'expires after cutoff: rejected');assert.deepEqual(r.codes,[CPU]);
  assert.equal(PRICE_REVIEW_CUTOFF,'2026-12-01T00:00:00.000Z');
});

// ---- references / receipts -------------------------------------------------
test('rejected for placeholder or missing approver, rationale, or evidence receipt',()=>{
  for(const over of [
    {approvedBy:undefined},{approvedBy:'TBD-APPROVAL-REF-1'},{approvedBy:'short'},
    {rationaleReference:undefined},{rationaleReference:'PLACEHOLDER-RATIONALE-1'},
    {evidenceSha256:undefined},{evidenceSha256:'zz'.repeat(32)},{evidenceSha256:'d'.repeat(63)},
  ]){
    const r=run({ex:over});
    assert.equal(r.ok,false,JSON.stringify(over));assert.deepEqual(r.codes,[CPU]);
  }
});

// ---- CPU measurement --------------------------------------------------------
test('rejected for a missing, stale, or out-of-range CPU measurement',()=>{
  const now=Date.parse(NOW);
  for(const cpuMeasurement of [
    {windowHours:12},{windowHours:23},{windowHours:73},{windowHours:48.5},{windowHours:'48'},
    {measuredAt:iso(now-3*3600e3)},{measuredAt:iso(now+60e3)},{measuredAt:'yesterday'},
    {recentMsPerDay:-1},{recentMsPerDay:Number.NaN},{recentMsPerDay:'500000'},{recentMsPerDay:Infinity},
  ]){
    const r=run({ex:{cpuMeasurement}});
    assert.equal(r.ok,false,JSON.stringify(cpuMeasurement));assert.deepEqual(r.codes,[CPU]);
  }
  const noMeasurement=run({ex:false,mutate:a=>{const e=exception(NOW);delete e.cpuMeasurement;a.releaseException=e;}});
  assert.deepEqual(noMeasurement.codes,[CPU]);
  const boundaries=run({ex:{cpuMeasurement:{windowHours:24}}}).ok&&run({ex:{cpuMeasurement:{windowHours:72}}}).ok;
  assert.equal(boundaries,true,'24h and 72h windows are accepted');
});

// ---- the hard floor: never permit a projected overage ----------------------
test('HARD FLOOR: measured rate x remaining x 1.25 plus used must fit inside 100% of the plan',()=>{
  // used 21.0M, 8.75 days left: 1.0M/day -> 21+10.94=31.9M > 30M  => rejected
  let r=run({att:{recent:1.0e6},ex:{cpuMeasurement:{recentMsPerDay:1.0e6}}});
  assert.equal(r.ok,false);assert.deepEqual(r.codes,[CPU]);
  // 0.8M/day -> 21+8.75=29.75M <= 30M  => accepted (still above the 80% reserve line, below plan)
  r=run({att:{recent:0.8e6},ex:{cpuMeasurement:{recentMsPerDay:0.8e6}}});
  assert.equal(r.ok,true,r.codes.join());
  // 0.85M/day -> 21+9.30=30.30M > 30M => rejected
  r=run({att:{recent:0.85e6},ex:{cpuMeasurement:{recentMsPerDay:0.85e6}}});
  assert.equal(r.ok,false);assert.deepEqual(r.codes,[CPU]);
});
test('HARD FLOOR: cannot be used once CPU is already past the plan allowance, whatever the measured rate',()=>{
  for(const used of [PLAN.workersCpuMs+1,PLAN.workersCpuMs*1.2]){
    const r=run({att:{used,recent:0,forecast:0},ex:{cpuMeasurement:{recentMsPerDay:0}}});
    assert.equal(r.ok,false,'used='+used);
    assert.deepEqual(r.codes,[CPU]);
  }
});
test('HARD FLOOR: the owner forecast may not understate the measurement',()=>{
  // measured 0.5M/day x 8.75 = 4.375M; owner claims only 1M remaining
  const r=run({att:{forecast:1.0e6}});
  assert.equal(r.ok,false);assert.deepEqual(r.codes,[CPU]);
  // claiming exactly the measurement is accepted
  assert.equal(run({att:{forecast:0.5e6*8.75}}).ok,true);
});
test('HARD FLOOR: the owner forecast itself must also fit inside the plan',()=>{
  // low measured rate but an owner forecast that overshoots the plan
  const r=run({att:{used:29.0e6,recent:0.05e6,forecast:2.0e6},ex:{cpuMeasurement:{recentMsPerDay:0.05e6}}});
  assert.equal(r.ok,false);assert.deepEqual(r.codes,[CPU]);
});

// ---- never waives anything else ---------------------------------------------
test('never waives another meter, spend, freshness, approval, pricing or account failure',()=>{
  const cases=[
    ['RESERVE_EXHAUSTED_r2ClassA',a=>{a.metrics.r2ClassA={used:PLAN.r2ClassA*0.85,forecastRemaining:0};}],
    ['RESERVE_EXHAUSTED_workersLogEvents',a=>{a.metrics.workersLogEvents={used:PLAN.workersLogEvents*0.9,forecastRemaining:0};}],
    ['ADDITIONAL_METERED_SPEND_NOT_ZERO',a=>{a.forecastAccountAdditionalMeteredChargesUsd=0.02;}],
    ['OVERAGE_ALREADY_PROJECTED',a=>{a.currentAccountProjectedOverageUsd=1;}],
    ['FRESH_USAGE_EVIDENCE_REQUIRED',a=>{a.capturedAt=iso(Date.parse(NOW)-3*3600e3);}],
    ['SOURCE_AND_APPROVAL_NOT_VERIFIED',a=>{a.operatorReviewed=false;}],
    ['NEW_PRICING_REVIEW_REQUIRED',a=>{delete a.postCutoffPricingReview;}],
    ['ACCOUNT_BINDING_INVALID',a=>{a.accountFingerprintSha256='0'.repeat(64);}],
    ['METRIC_COVERAGE_INCOMPLETE',a=>{delete a.metrics.r2ClassB;}],
  ];
  for(const [code,mutate] of cases){
    const r=run({mutate});
    assert.equal(r.ok,false,code);
    assert.ok(r.codes.includes(code),code+' missing from '+r.codes.join());
  }
  // The CPU code itself is the only thing removed when everything else is healthy-but-one.
  const r=run({mutate:a=>{a.metrics.r2ClassA={used:PLAN.r2ClassA*0.85,forecastRemaining:0};}});
  assert.deepEqual(r.codes,['RESERVE_EXHAUSTED_r2ClassA']);
  assert.equal('exception' in r,true,'exception was applied to the CPU code even though the release still HOLDs');
});

// ---- CLI wiring (static; the CLI uses the real clock so it is not run here) --
test('CLI binds the exception to git HEAD, fails closed on error, and keeps the default PASS text',()=>{
  const src=fs.readFileSync(path.join(__dirname,'..','scripts','cloudflare-account-zero-overage-gate.cjs'),'utf8');
  assert.match(src,/execFileSync\('git',\['rev-parse','HEAD'\]/);
  assert.match(src,/catch\{releaseSha='';\}/);
  assert.match(src,/assess\(body,process\.env\.CLOUDFLARE_ACCOUNT_ID,undefined,\{releaseSha\}\)/);
  assert.match(src,/PASS: ACCOUNT_WIDE_BUDGET_RELEASE_GATE with 20-percent headroom; no overage forecast on submitted evidence/);
  assert.ok(!/process\.env\.CDB_[A-Z_]*EXCEPTION/.test(src),'no environment-variable bypass may exist');
});
