#!/usr/bin/env node
'use strict';

/**
 * Account-wide Cloudflare ZERO OVERAGE change-control gate.
 * Does not fetch metrics, incur Cloudflare usage, or guarantee a future bill.
 * Requires a fresh, operator-reviewed private account-wide billing attestation.
 * Rejects absent/stale/partial evidence BEFORE any Wrangler deployment.
 */
const crypto=require('node:crypto');
const PLAN=Object.freeze({
  workersRequests:10000000,
  workersCpuMs:30000000,
  d1RowsRead:25000000000,
  d1RowsWritten:50000000,
  d1StorageGbMonth:5,
  kvReads:10000000,
  kvWrites:1000000,
  kvDeletes:1000000,
  kvLists:1000000,
  kvStorageGbMonth:1,
  r2StandardStorageGbMonth:10,
  r2ClassA:1000000,
  r2ClassB:10000000,
  // AI Security Hub deploy configuration includes scan-jobs producer/consumer.
  // Cloudflare bills Queues by operations (write, read, delete, retries).
  queuesStandardOperations:1000000,
  workersLogEvents:20000000
});
const STOCK=new Set(['d1StorageGbMonth','kvStorageGbMonth','r2StandardStorageGbMonth']);
// Stable inventory identifiers: an attestation cannot omit a known ecosystem
// workload while still passing a superficial three-platform count.
const REQUIRED_PLATFORMS=Object.freeze([
  'sentinel-apex-threat-intel',
  'sentinel-apex-ai-security-hub',
  'sentinel-apex-soc',
  'nilachala-devotional'
]);
const MAX_ATTESTATION_AGE_MS=2*60*60*1000;
const SAFETY_RATIO=0.80;
const FORECAST_BUFFER=1.25;
// Owner's USD4 describes existing Workers usage allocation, NOT a cap on
// existing account subscription fees. ZERO extra metered spend is authorized
// across the shared account, regardless of the base subscription price.
const MAX_ADDITIONAL_METERED_CHARGES_USD=0;
const PRICE_REVIEW_CUTOFF='2026-12-01T00:00:00.000Z';
const sha256=x=>crypto.createHash('sha256').update(x).digest('hex');
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const isValidTime=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(s)&&Number.isFinite(Date.parse(s));
const metric=x=>obj(x)&&Number.isFinite(x.used)&&x.used>=0&&
  Number.isFinite(x.forecastRemaining)&&x.forecastRemaining>=0;
const receipt=x=>typeof x==='string'&&/^[a-f0-9]{64}$/i.test(x);
const isRef=x=>typeof x==='string'&&/^[A-Za-z0-9][A-Za-z0-9._/-]{7,159}$/.test(x)&&!/(?:placeholder|tbd|unknown|demo)/i.test(x);
// Owner attestation that Cloudflare's post-PRICE_REVIEW_CUTOFF Observability
// pricing was reviewed against ALL Workers observability settings and that no
// additional metered charge is projected. Same trust model as the rest of this
// gate (owner-supplied private evidence + receipt hash); stale (>14 days) or
// partial reviews never count. It does NOT relax any usage metric: the
// workersLogEvents reserve (and every other meter) is still enforced below.
const MAX_PRICING_REVIEW_AGE_MS=14*24*60*60*1000;
const pricingReviewAttested=(r,nowMs)=>obj(r)&&
  r.schemaVersion==='cdb-observability-pricing-review/v1'&&
  isValidTime(r.reviewedAt)&&Date.parse(r.reviewedAt)<=nowMs&&
  nowMs-Date.parse(r.reviewedAt)<=MAX_PRICING_REVIEW_AGE_MS&&
  isRef(r.pricingSourceReference)&&isRef(r.operatorApprovalReference)&&
  receipt(r.evidenceSha256)&&
  r.allWorkersObservabilitySettingsReviewed===true&&
  r.projectedPostCutoffAdditionalMeteredChargesUsd===0;

// SINGLE-RELEASE CPU RESERVE EXCEPTION (owner-signed, expiring).
// Waives ONLY the 20% safety reserve of Workers CPU for ONE exact release SHA
// while keeping a HARD FLOOR at 100% of the included allowance: the measured
// recent daily CPU rate, with the gate's own 1.25 forecast buffer, plus CPU
// already used must still fit inside the plan, and the owner's forecast may not
// be lower than that measurement. It can never waive any other code, never
// lasts more than 24h, and can never outlive the pricing cutoff.
const EXCEPTION_WAIVABLE_CODE='RESERVE_EXHAUSTED_workersCpuMs';
const MAX_EXCEPTION_WINDOW_MS=24*60*60*1000;
const releaseExceptionApplies=(ex,input,ctx,nowMs,endMs)=>{
  if(!obj(ex)||ex.schemaVersion!=='cdb-budget-release-exception/v1'||
    ex.scope!=='single-release-cpu-reserve')return false;
  if(!Array.isArray(ex.waives)||ex.waives.length!==1||ex.waives[0]!==EXCEPTION_WAIVABLE_CODE)return false;
  const sha=ctx&&typeof ctx.releaseSha==='string'?ctx.releaseSha:'';
  if(!/^[a-f0-9]{40}$/.test(sha)||ex.approvedReleaseSha!==sha)return false;
  if(!isValidTime(ex.approvedAt)||!isValidTime(ex.expiresAt))return false;
  const approved=Date.parse(ex.approvedAt),expires=Date.parse(ex.expiresAt);
  if(!(approved<=nowMs&&nowMs<expires&&expires-approved<=MAX_EXCEPTION_WINDOW_MS&&
    expires<=Date.parse(PRICE_REVIEW_CUTOFF)))return false;
  if(!isRef(ex.approvedBy)||!isRef(ex.rationaleReference)||!receipt(ex.evidenceSha256))return false;
  const m=ex.cpuMeasurement;
  if(!obj(m)||!Number.isInteger(m.windowHours)||m.windowHours<24||m.windowHours>72||
    !isValidTime(m.measuredAt))return false;
  const measured=Date.parse(m.measuredAt);
  if(!(measured<=nowMs&&nowMs-measured<=MAX_ATTESTATION_AGE_MS))return false;
  if(!(typeof m.recentMsPerDay==='number'&&Number.isFinite(m.recentMsPerDay)&&m.recentMsPerDay>=0))return false;
  const cpu=input.metrics&&input.metrics.workersCpuMs;
  if(!metric(cpu))return false;
  const remainingDays=(endMs-nowMs)/86400000;
  // The owner's own forecast must not understate what was measured.
  if(cpu.forecastRemaining+1e-9<m.recentMsPerDay*remainingDays)return false;
  const limit=PLAN.workersCpuMs;
  return cpu.used+m.recentMsPerDay*remainingDays*FORECAST_BUFFER<=limit+1e-9&&
    cpu.used+cpu.forecastRemaining<=limit+1e-9;
};

function assess(input, accountId,now=new Date().toISOString(),ctx={}){
  const codes=new Set();
  const fail=(code,pass)=>{if(!pass)codes.add(code)};
  if(!obj(input)||!isValidTime(now))return {ok:false,codes:['ATTESTATION_INVALID']};
  fail('SCHEMA_INVALID',input.schemaVersion==='cdb-cloudflare-shared-budget/v1');
  fail('SHARED_ACCOUNT_NOT_ATTESTED',input.accountScope==='ALL_PLATFORMS_SINGLE_CLOUDFLARE_ACCOUNT'&&
    input.accountCoverageConfirmed===true&&input.allActiveMeteredServicesReviewed===true&&
    Array.isArray(input.reviewedPlatforms)&&input.reviewedPlatforms.length>=3&&
    input.reviewedPlatforms.every(isRef)&&new Set(input.reviewedPlatforms).size===input.reviewedPlatforms.length&&
    REQUIRED_PLATFORMS.every(id=>input.reviewedPlatforms.includes(id)));
  fail('ACCOUNT_BINDING_INVALID',typeof accountId==='string'&&/^[a-f0-9]{32}$/i.test(accountId)&&
    input.accountFingerprintSha256===sha256(accountId.toLowerCase()));
  fail('SOURCE_AND_APPROVAL_NOT_VERIFIED',input.source==='cloudflare-account-billing-and-service-metrics'&&
    receipt(input.privateEvidenceSha256)&&isRef(input.operatorApprovalReference)&&
    input.operatorReviewed===true);
  fail('BASE_PLAN_NOT_VERIFIED',input.verifiedWorkersPlan==='paid-standard'&&
    input.r2StorageClass==='standard-only'&&input.anyInfrequentAccessStorage===false);
  fail('UNMODELED_BILLING_NOT_REVIEWED',input.unmodeledBillableServicesPresent===false&&
    input.optionalPaidProductsOrAddonsPresent===false);
  fail('OVERAGE_ALREADY_PROJECTED',input.currentAccountProjectedOverageUsd===0);
  // Private billing evidence covers ALL account workloads: AI Hub, SOC, CTI,
  // NILACHALA, D1, R2, KV, Queues, Workers and any other billable service.
  // Incremental metered charges EXCLUDE pre-existing flat subscription fees.
  // This guard does not impose a provider hard cap or certify the final bill.
  const validUsd=x=>typeof x==='number'&&Number.isFinite(x)&&x>=0;
  const billEvidenceValid=input.accountBillingCurrency==='USD'&&
    validUsd(input.accountMonthToDateAdditionalMeteredChargesUsd)&&
    validUsd(input.forecastAccountAdditionalMeteredChargesUsd)&&
    input.forecastAccountAdditionalMeteredChargesUsd>=input.accountMonthToDateAdditionalMeteredChargesUsd;
  fail('ACCOUNT_ADDITIONAL_METERED_EVIDENCE_REQUIRED',billEvidenceValid);
  if(billEvidenceValid)fail('ADDITIONAL_METERED_SPEND_NOT_ZERO',
    input.accountMonthToDateAdditionalMeteredChargesUsd===MAX_ADDITIONAL_METERED_CHARGES_USD&&
    input.forecastAccountAdditionalMeteredChargesUsd===MAX_ADDITIONAL_METERED_CHARGES_USD);
  const cycle=input.cycle||{};
  const validCycle=obj(cycle)&&isValidTime(cycle.start)&&isValidTime(cycle.end)&&isValidTime(input.capturedAt);
  if(!validCycle){
    codes.add('BILLING_WINDOW_INVALID');
    return {ok:false,codes:[...codes].sort()};
  }
  const nowMs=Date.parse(now),start=Date.parse(cycle.start),end=Date.parse(cycle.end),captured=Date.parse(input.capturedAt);
  fail('FRESH_USAGE_EVIDENCE_REQUIRED',captured<=nowMs&&nowMs-captured<=MAX_ATTESTATION_AGE_MS);
  fail('BILLING_WINDOW_INVALID',start<nowMs&&nowMs<end&&end-start>=24*60*60*1000&&
    end-start<=35*24*60*60*1000&&captured>=start);
  // 2026-12-01 changes account-wide Observability pricing; require updated
  // model before allowing any billing cycle that crosses the switch date.
  // A cycle that ends on/before the cutoff is unaffected. A cycle that crosses
  // it is accepted ONLY with a fresh, structured owner pricing review (see
  // pricingReviewAttested); the hard-coded date alone must not block every
  // future release forever, and an unreviewed crossing still HOLDs.
  fail('NEW_PRICING_REVIEW_REQUIRED',end<=Date.parse(PRICE_REVIEW_CUTOFF)||
    pricingReviewAttested(input.postCutoffPricingReview,nowMs));
  if(!(start<nowMs&&nowMs<end))return {ok:false,codes:[...codes].sort()};
  const expected=Object.keys(PLAN).sort();
  fail('METRIC_COVERAGE_INCOMPLETE',obj(input.metrics)&&
    Object.keys(input.metrics).sort().join('|')===expected.join('|'));
  if(!obj(input.metrics))return {ok:false,codes:[...codes].sort()};
  for(const [name,included] of Object.entries(PLAN)){
    const value=input.metrics[name];
    if(!metric(value)){codes.add('METRIC_MISSING_OR_INVALID_'+name);continue;}
    const elapsed=Math.max(60*1000,nowMs-start),remaining=end-nowMs;
    // For usage counters, require remaining forecast to be at least 125%
    // of elapsed account-wide usage pace. Storage GB-month already accrued
    // and forecast for remaining cycle are additive; max(used,remaining)
    // dangerously undercounts storage that increases late in the month.
    const pace=value.used*remaining/elapsed*FORECAST_BUFFER;
    const projected=STOCK.has(name)?
      value.used+value.forecastRemaining:
      value.used+Math.max(value.forecastRemaining,pace);
    if(!(projected<=(included*SAFETY_RATIO)+1e-9))codes.add('RESERVE_EXHAUSTED_'+name);
  }
  let exception=null;
  if(codes.has(EXCEPTION_WAIVABLE_CODE)&&input.releaseException!==undefined&&
    releaseExceptionApplies(input.releaseException,input,ctx,nowMs,end)){
    codes.delete(EXCEPTION_WAIVABLE_CODE);
    exception={waived:EXCEPTION_WAIVABLE_CODE,approvedReleaseSha:input.releaseException.approvedReleaseSha,
      expiresAt:input.releaseException.expiresAt};
  }
  const result={ok:codes.size===0,codes:[...codes].sort()};
  // Only present when an exception was actually used, so the normal result
  // shape ({ok,codes}) is byte-for-byte unchanged for every other caller.
  if(exception)result.exception=exception;
  return result;
}
if(require.main===module){
  let body;
  try{
    const input=process.env.CDB_CF_ACCOUNT_BUDGET_ATTESTATION||'';
    if(Buffer.byteLength(input)>16000||!input)throw new Error('MISSING_OR_OVERSIZED');
    body=JSON.parse(input);
  }catch{
    console.error('HOLD: SHARED_CLOUDFLARE_ACCOUNT_BUDGET_ATTESTATION_MISSING');
    process.exitCode=1;
  }
  if(body){
    // The exception is bound to the exact commit being released.
    let releaseSha='';
    try{
      releaseSha=require('node:child_process').execFileSync('git',['rev-parse','HEAD'],
        {encoding:'utf8',stdio:['ignore','pipe','ignore']}).trim().toLowerCase();
    }catch{releaseSha='';}
    const result=assess(body,process.env.CLOUDFLARE_ACCOUNT_ID,undefined,{releaseSha});
    if(!result.ok){
      // Only deterministic error codes, never account IDs, metrics, tokens,
      // or the private source evidence.
      console.error('HOLD: SHARED_CLOUDFLARE_BUDGET '+result.codes.join(', '));
      process.exitCode=1;
    }else if(result.exception){
      console.log('PASS: ACCOUNT_WIDE_BUDGET_RELEASE_GATE under SINGLE_RELEASE_CPU_EXCEPTION for '+
        result.exception.approvedReleaseSha.slice(0,12)+' until '+result.exception.expiresAt+
        '; 20-percent CPU reserve waived, 100-percent CPU hard floor verified on measured rate');
    }else{
      console.log('PASS: ACCOUNT_WIDE_BUDGET_RELEASE_GATE with 20-percent headroom; no overage forecast on submitted evidence');
    }
  }
}
module.exports={assess,PLAN,REQUIRED_PLATFORMS,SAFETY_RATIO,FORECAST_BUFFER,MAX_ADDITIONAL_METERED_CHARGES_USD,PRICE_REVIEW_CUTOFF,MAX_PRICING_REVIEW_AGE_MS,MAX_EXCEPTION_WINDOW_MS};
