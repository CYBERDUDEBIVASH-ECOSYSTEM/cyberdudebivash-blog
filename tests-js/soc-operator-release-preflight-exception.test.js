'use strict';
// The operator preflight must evaluate the account budget exactly like the
// deploy workflow's gate CLI. The single-release CPU exception is bound to the
// checked-out commit (git HEAD); before this fix the preflight never supplied
// it, so a valid exception passed the real gate but HELD the mandatory
// preflight with BUDGET_RESERVE_EXHAUSTED_workersCpuMs.
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {verdict}=require('../scripts/soc-operator-release-preflight.cjs');
const {PLAN,REQUIRED_PLATFORMS}=require('../scripts/cloudflare-account-zero-overage-gate.cjs');

const NOW=Date.parse('2026-11-24T16:10:00Z'),SHA='a'.repeat(40),ACCOUNT='b'.repeat(32);
const CPU_CODE='BUDGET_RESERVE_EXHAUSTED_workersCpuMs';
const stamp=m=>new Date(NOW-m*60*1000).toISOString();
const iso=ms=>new Date(ms).toISOString().replace(/\.\d{3}Z$/,'.000Z');
const END=Date.parse('2026-12-03T00:00:00Z');

function exception(over={}){
  return {
    schemaVersion:'cdb-budget-release-exception/v1',
    scope:'single-release-cpu-reserve',
    waives:['RESERVE_EXHAUSTED_workersCpuMs'],
    approvedReleaseSha:SHA,
    approvedAt:iso(NOW-3600e3),
    expiresAt:iso(NOW+12*3600e3),
    approvedBy:'OWNER-APPROVAL-20261124',
    rationaleReference:'SOC-RELEASE-RATIONALE-20261124',
    evidenceSha256:'d'.repeat(64),
    cpuMeasurement:{windowHours:48,measuredAt:iso(NOW-600e3),recentMsPerDay:0.5e6},
    ...over
  };
}
function sample({withException=true}={}){
  const ids=Array.from({length:12},(_,i)=>({id:'CVE-2026-'+(10000+i)}));
  const t=stamp(20);
  const remainingDays=(END-NOW)/86400000;
  const metrics=Object.fromEntries(Object.entries(PLAN).map(([k,v])=>[k,{used:v*.10,forecastRemaining:v*.15}]));
  metrics.workersCpuMs={used:21.0e6,forecastRemaining:0.5e6*remainingDays};
  const budgetEvidence={
    schemaVersion:'cdb-cloudflare-shared-budget/v1',
    accountScope:'ALL_PLATFORMS_SINGLE_CLOUDFLARE_ACCOUNT',
    accountCoverageConfirmed:true,allActiveMeteredServicesReviewed:true,
    reviewedPlatforms:[...REQUIRED_PLATFORMS],
    accountFingerprintSha256:crypto.createHash('sha256').update(ACCOUNT).digest('hex'),
    source:'cloudflare-account-billing-and-service-metrics',
    privateEvidenceSha256:'c'.repeat(64),
    operatorApprovalReference:'vault/owner-release-20261124',
    operatorReviewed:true,verifiedWorkersPlan:'paid-standard',
    r2StorageClass:'standard-only',anyInfrequentAccessStorage:false,
    unmodeledBillableServicesPresent:false,optionalPaidProductsOrAddonsPresent:false,
    currentAccountProjectedOverageUsd:0,
    accountBillingCurrency:'USD',
    accountMonthToDateAdditionalMeteredChargesUsd:0,
    forecastAccountAdditionalMeteredChargesUsd:0,
    // Crosses the 2026-12-01 pricing cutoff, so it carries the owner's review.
    cycle:{start:'2026-11-03T00:00:00.000Z',end:'2026-12-03T00:00:00.000Z'},
    capturedAt:stamp(15),
    postCutoffPricingReview:{
      schemaVersion:'cdb-observability-pricing-review/v1',
      reviewedAt:stamp(60),
      pricingSourceReference:'CLOUDFLARE-OBSERVABILITY-PRICING-2026-12-01',
      operatorApprovalReference:'vault/owner-release-20261124',
      evidenceSha256:'e'.repeat(64),
      allWorkersObservabilitySettingsReviewed:true,
      projectedPostCutoffAdditionalMeteredChargesUsd:0
    },
    metrics
  };
  if(withException)budgetEvidence.releaseException=exception();
  return {
    approvedSha:SHA,accountId:ACCOUNT,nowMs:NOW,
    git:{origin:'https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog.git',
      head:SHA,upstream:SHA,clean:true,shallow:false},
    budgetEvidence,
    bundle:{
      state:{lastRun:t,lastReportGeneratedAt:t,totalPublished:6563,published:[],lastIngestion:{reportsGenerated:15}},
      rootSource:{generatedAt:t,totalPublished:6563,metadata:{lastPipelineRun:t,lastReportGeneratedAt:t},items:ids},
      apiSource:{generated:t,lastReportGeneratedAt:t,total_published:6563,items:ids},
      rootAsset:{generatedAt:t,totalPublished:6563,metadata:{lastPipelineRun:t,lastReportGeneratedAt:t},items:structuredClone(ids)},
      apiAsset:{generated:t,lastReportGeneratedAt:t,total_published:6563,items:structuredClone(ids)}
    }
  };
}
const evaluate=(opts,fn)=>{const x=sample(opts);if(fn)fn(x);return verdict(x);};

test('control: without the exception this CPU state HOLDs the preflight (reserve still enforced)',()=>{
  const out=evaluate({withException:false});
  assert.equal(out.status,'HOLD');
  assert.ok(out.codes.includes('ACCOUNT_WIDE_BUDGET_UNCERTIFIED'));
  assert.ok(out.codes.includes(CPU_CODE),out.codes.join());
});

test('a valid exception bound to the checked-out commit passes the preflight, as it does the deploy gate',()=>{
  const out=evaluate();
  assert.equal(out.status,'OFFLINE_PREFLIGHT_PASS_NOT_DEPLOY_APPROVAL',JSON.stringify(out));
  assert.deepEqual(out.codes,[]);
  assert.equal(out.workerDeploymentAuthorized,false);
  assert.equal(out.customerManagedSocGo,false);
});

test('an exception bound to a different commit than HEAD is ignored and the preflight HOLDs',()=>{
  const out=evaluate({},x=>{x.budgetEvidence.releaseException=exception({approvedReleaseSha:'f'.repeat(40)});});
  assert.equal(out.status,'HOLD');
  assert.ok(out.codes.includes(CPU_CODE),out.codes.join());
});

test('the exception is evaluated against git HEAD, not the operator-typed approved SHA',()=>{
  // HEAD differs from the exception SHA while approvedSha equals the exception SHA:
  // the pinned-SHA gate also fails, and the exception must not be honoured.
  const out=evaluate({},x=>{x.git.head='c'.repeat(40);x.git.upstream='c'.repeat(40);});
  assert.equal(out.status,'HOLD');
  assert.ok(out.codes.includes('PINNED_SHA_NOT_CURRENT_MAIN'));
  assert.ok(out.codes.includes(CPU_CODE));
});

test('HEAD is lower-cased before binding (git prints lower-case, operators may paste upper-case)',()=>{
  const out=evaluate({},x=>{x.git.head=SHA.toUpperCase();x.git.upstream=SHA.toUpperCase();x.approvedSha=SHA.toUpperCase();});
  assert.equal(out.status,'OFFLINE_PREFLIGHT_PASS_NOT_DEPLOY_APPROVAL',JSON.stringify(out));
});

test('a missing or malformed HEAD never enables the exception',()=>{
  for(const head of [undefined,null,'',123,'zz']){
    const out=evaluate({},x=>{x.git.head=head;});
    assert.equal(out.status,'HOLD');
    assert.ok(out.codes.includes(CPU_CODE),String(head)+': '+out.codes.join());
  }
});

test('the exception cannot hide an unsafe CPU projection in the preflight either (hard floor)',()=>{
  const out=evaluate({},x=>{
    x.budgetEvidence.releaseException=exception({cpuMeasurement:{windowHours:48,measuredAt:iso(NOW-600e3),recentMsPerDay:1.2e6}});
  });
  assert.equal(out.status,'HOLD');
  assert.ok(out.codes.includes(CPU_CODE));
});
