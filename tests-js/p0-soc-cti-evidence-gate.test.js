'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {assessSource,checkHomepage}=require('../scripts/p0-soc-cti-evidence-gate.cjs');
const now=Date.parse('2026-11-15T08:00:00Z');
const stamp=ms=>new Date(ms).toISOString();
function fixture(){const v=stamp(now-30*60000);return {state:{lastRun:v,lastReportGeneratedAt:v,totalPublished:7519,lastIngestion:{activeSources:5,totalSources:35,fetchedRecords:60,checkedAt:v}},root:{totalPublished:7519,metadata:{lastReportGeneratedAt:v}},s2n:{total_published:7519,lastReportGeneratedAt:v}};}
test('fresh matching genuine receipts and real source coverage are valid',()=>{let v=fixture();assert.equal(assessSource(v.state,v.root,v.s2n,now).status,'SOURCE_CERTIFIED');});
test('heartbeat never certifies an old genuine report',()=>{let v=fixture();v.state.lastReportGeneratedAt=stamp(now-200*60000);v.root.metadata.lastReportGeneratedAt=v.state.lastReportGeneratedAt;v.s2n.lastReportGeneratedAt=v.state.lastReportGeneratedAt;assert.match(assessSource(v.state,v.root,v.s2n,now).problems.join(),/GENUINE_REPORT_STALE/);});
test('few active sources never pass',()=>{let v=fixture();v.state.lastIngestion.activeSources=4;assert.match(assessSource(v.state,v.root,v.s2n,now).problems.join(),/SOURCE_COVERAGE_NOT_CERTIFIED/);});
test('source and edge candidate counts and receipts must match',()=>{let v=fixture();v.s2n.total_published=7518;v.s2n.lastReportGeneratedAt=stamp(now-50*60000);let r=assessSource(v.state,v.root,v.s2n,now);assert.equal(r.status,'NOT_CERTIFIED');assert.ok(r.problems.includes('GENUINE_RECEIPT_PARITY_FAILURE'));assert.ok(r.problems.includes('PUBLICATION_COUNT_PARITY_FAILURE'));});
test('future and impossible ingestion receipts fail closed',()=>{let v=fixture();v.state.lastIngestion.activeSources=7;v.state.lastIngestion.fetchedRecords=3;v.state.lastRun=stamp(now+6*60000);let r=assessSource(v.state,v.root,v.s2n,now);assert.equal(r.status,'NOT_CERTIFIED');assert.ok(r.problems.includes('INGESTION_SOURCE_COVERAGE_NOT_CERTIFIED'));});
test('static October cards and unverified LIVE badges are rejected',()=>{let p=checkHomepage('<h2>SENTINEL APEX</h2><h3>Featured Reports</h3><div class="fi-badge live-badge">&#9679; LIVE</div>');assert.equal(p.length,2);});
test('safe homepage with runtime badge and archive link passes static checks',()=>{assert.deepEqual(checkHomepage('<title>SENTINEL APEX</title><a href="/archive">Archive</a>'),[]);});
