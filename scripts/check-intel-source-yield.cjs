#!/usr/bin/env node
'use strict';
/**
 * This-run source-yield proof for Sentinel APEX v5.
 * Transport OK is not a claim of new verified intelligence.
 * Bounded, read-only. No remote calls, resets, delivery or deployment.
 * Called AFTER normal commit/push, so successful genuine publication is kept.
 * A high-frequency poll may return zero new records from healthy authoritative
 * sources. This condition is NOT an outage and does NOT satisfy the separate
 * minimum five *nonempty* sources for commercial/operational release gates.
 * Only fresh per-source success receipts can avoid a false publisher failure.
 * Never count yesterday's successful polls, cached items, or denied providers.
 */
const fs = require('node:fs');
const path = require('node:path');
const MIN_ACTIVE_SOURCES = 5;
const MIN_CURRENT_SUCCESSFUL_POLLS = 5;
const MAX_SOURCE_POLL_LAG_MS = 5 * 60000;
const MAX_RUN_AGE_MINUTES = 120;

/** Count only actual current-run successful source fetches, including valid empty results. */
function countFreshSuccessfulPolls(health, runCheckedAt, totalSources) {
  if (!health || typeof health !== 'object' || Array.isArray(health)) return 0;
  const records = Object.entries(health);
  if (records.length > totalSources) return -1;
  let current = 0;
  for (const [name, source] of records) {
    if (!/^[a-z0-9_]{2,64}$/.test(name) ||
        !source || typeof source !== 'object' || Array.isArray(source) ||
        !['ok','empty'].includes(source.status) ||
        source.consecutiveFails !== 0 ||
        !Number.isSafeInteger(source.lastItemCount) || source.lastItemCount < 0 ||
        (source.status === 'empty' && source.lastItemCount !== 0) ||
        (source.status === 'ok' && source.lastItemCount < 1)) continue;
    const success = Date.parse(source.lastSuccess || '');
    const fetched = Date.parse(source.lastFetchAt || '');
    if (!Number.isFinite(success) || !Number.isFinite(fetched) ||
        Math.abs(success - fetched) > 5000 ||
        success < runCheckedAt - MAX_SOURCE_POLL_LAG_MS ||
        success > runCheckedAt + 60000 ||
        fetched < runCheckedAt - MAX_SOURCE_POLL_LAG_MS ||
        fetched > runCheckedAt + 60000) continue;
    current++;
  }
  return current;
}
function evaluate(state,nowMs=Date.now()) {
  const run = state && state.lastIngestion;
  if(!state || !run || !Number.isSafeInteger(run.totalSources) || run.totalSources<1 ||
     !Number.isSafeInteger(run.activeSources) || run.activeSources<0 ||
     run.activeSources>run.totalSources ||
     !Number.isSafeInteger(run.fetchedRecords) || run.fetchedRecords<0 ||
     !Number.isSafeInteger(run.reportsGenerated) || run.reportsGenerated<0 ||
     // Every nonempty source must contribute at least one fetched record.
     // Do not certify contradictory or fabricated per-run source receipts.
     run.activeSources>run.fetchedRecords ||
     (run.reportsGenerated>0 && run.fetchedRecords===0)) {
    return {status:'MONITOR_ERROR',exitCode:1,code:'INGESTION_RECEIPT_MISSING_OR_INVALID'};
  }
  const checkedAt=Date.parse(run.checkedAt||''),lastRun=Date.parse(state.lastRun||'');
  if(!Number.isFinite(checkedAt)||!Number.isFinite(lastRun)||
     checkedAt>nowMs+5*60000||lastRun>nowMs+5*60000||
     nowMs-checkedAt>MAX_RUN_AGE_MINUTES*60000||
     Math.abs(lastRun-checkedAt)>15*60000) {
    return {status:'MONITOR_ERROR',exitCode:1,code:'INGESTION_RECEIPT_TIME_INVALID'};
  }
  const coverage={activeSources:run.activeSources,totalSources:run.totalSources,
    fetchedRecords:run.fetchedRecords,reportsGenerated:run.reportsGenerated};
  if(run.activeSources<MIN_ACTIVE_SOURCES) {
    const freshSuccessfulPolls = countFreshSuccessfulPolls(
      state.sourceHealth, checkedAt, run.totalSources);
    if(freshSuccessfulPolls < 0) {
      return {status:'MONITOR_ERROR',exitCode:1,code:'SOURCE_POLL_LEDGER_INVALID'};
    }
    // Distinct provenance: a fresh successful empty poll is not a new IOC,
    // source corroboration, or a passing paid-customer release requirement.
    // Separate product/GA gates require status exactly COVERAGE_VERIFIED.
    if(freshSuccessfulPolls>=MIN_CURRENT_SUCCESSFUL_POLLS) {
      return {status:'POLL_HEALTHY_LOW_YIELD',exitCode:0,
        code:'FRESH_SOURCE_POLLS_CONFIRMED_LOW_NEW_RECORD_DIVERSITY',
        freshSuccessfulPolls,
        releaseSourceDiversityCertified:false,
        ...coverage};
    }
    return {status:'SOURCE_COVERAGE_DEGRADED',exitCode:2,
      code:'FEWER_THAN_FIVE_SOURCES_RETURNED_RECORDS',
      freshSuccessfulPolls,releaseSourceDiversityCertified:false,...coverage};
  }
  return {status:'COVERAGE_VERIFIED',exitCode:0,
    code:'SOURCE_YIELD_MET_MINIMUM',releaseSourceDiversityCertified:true,...coverage};
}
if(require.main===module) {
  try {
    if(process.argv.length!==2)throw Error('UNEXPECTED_CLI_ARGUMENT');
    const state=JSON.parse(fs.readFileSync(path.join(__dirname,'..','intel-state.json'),'utf8'));
    const result=evaluate(state);
    console.log(JSON.stringify(result));
    if(result.status==='POLL_HEALTHY_LOW_YIELD') {
      // This publishes a GitHub warning, not a fake full source-diversity pass.
      // Enterprise GA and source-product certification still HOLD.
      console.error('::warning title=Intel Source Diversity Below Release Floor::Fresh source polling succeeded, but fewer than five independent sources yielded records. Paid-customer release remains HOLD.');
    }
    process.exitCode=result.exitCode;
  }catch(_){
    console.error('MONITOR_ERROR: INGESTION_EVIDENCE_UNAVAILABLE');
    process.exitCode=1;
  }
}
module.exports={evaluate,MIN_ACTIVE_SOURCES,MIN_CURRENT_SUCCESSFUL_POLLS,countFreshSuccessfulPolls};
