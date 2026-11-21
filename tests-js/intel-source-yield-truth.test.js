'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {evaluate}=require('../scripts/check-intel-source-yield.cjs');
const now=Date.parse('2026-10-25T06:15:00Z');
function fixture({active=5,total=35,records=75,reports=0,age=10}={}) {
  const checkedAt=new Date(now-age*60000).toISOString();
  return {lastRun:checkedAt,lastIngestion:{checkedAt,activeSources:active,
    totalSources:total,fetchedRecords:records,reportsGenerated:reports}};
}
test('5 of 35 sources returning records passes even when no novel report exists',()=>{
  const result=evaluate(fixture(),now);
  assert.equal(result.status,'COVERAGE_VERIFIED');
  assert.equal(result.exitCode,0);
  assert.equal(result.reportsGenerated,0);
});
test('per-run receipt cannot report more nonempty sources than fetched records',()=>{
  for(const [active,records] of [[5,0],[5,4],[2,1]]) {
    const result=evaluate(fixture({active,records}),now);
    assert.equal(result.status,'MONITOR_ERROR');
    assert.equal(result.code,'INGESTION_RECEIPT_MISSING_OR_INVALID');
  }
});
test('a reported new genuine report with zero fetched records cannot certify coverage',()=>{
  const result=evaluate(fixture({active:0,records:0,reports:1}),now);
  assert.equal(result.status,'MONITOR_ERROR');
  assert.equal(result.exitCode,1);
});
test('zero new reports with source records may still pass the independent source-yield gate',()=>{
  assert.equal(evaluate(fixture({active:5,records:5,reports:0}),now).status,'COVERAGE_VERIFIED');
});
test('reproduce production incident: 2 of 35 return items but previous 6518 cumulative is NOT healthy',()=>{
  const state={...fixture({active:2,total:35,reports:0}),totalPublished:6518};
  const result=evaluate(state,now);
  assert.equal(result.status,'SOURCE_COVERAGE_DEGRADED');
  assert.equal(result.exitCode,2);
  assert.equal(result.code,'FEWER_THAN_FIVE_SOURCES_RETURNED_RECORDS');
});
test('source count can never be inferred from old state.sourceHealth ok entries',()=>{
  const state=fixture({active:0,total:35,records:0});
  state.sourceHealth=Object.fromEntries(Array.from({length:35},(_,i)=>['s'+i,{status:'ok'}]));
  assert.equal(evaluate(state,now).status,'SOURCE_COVERAGE_DEGRADED');
});
test('receipt impossible counts fail as monitoring corruption',()=>{
  for(const v of [-1,36,1.5,'35']) {
    assert.equal(evaluate(fixture({active:v}),now).status,'MONITOR_ERROR',String(v));
  }
  assert.equal(evaluate(fixture({total:0}),now).status,'MONITOR_ERROR');
  assert.equal(evaluate(fixture({reports:-1}),now).status,'MONITOR_ERROR');
  assert.equal(evaluate({lastRun:fixture().lastRun},now).status,'MONITOR_ERROR');
});
test('stale, future, or detached receipts do not certify green',()=>{
  assert.equal(evaluate(fixture({age:121}),now).code,'INGESTION_RECEIPT_TIME_INVALID');
  assert.equal(evaluate(fixture({age:-10}),now).code,'INGESTION_RECEIPT_TIME_INVALID');
  const invalid=fixture();invalid.lastRun='2026-10-24T03:00:00Z';
  assert.equal(evaluate(invalid,now).code,'INGESTION_RECEIPT_TIME_INVALID');
});
test('real source-health implementation records empty results separately from transport failures',()=>{
  const engine=require('../fetch-live-intel.js');
  const state={sourceHealth:{}};
  engine.recordSourceSuccess(state,'test',0);
  assert.equal(state.sourceHealth.test.status,'empty');
  assert.equal(state.sourceHealth.test.lastItemCount,0);
  assert.equal(state.sourceHealth.test.lastDataAt,undefined);
  assert.equal(engine.getSourceHealthReport(state).empty.length,1);
  engine.recordSourceSuccess(state,'test',3);
  assert.equal(state.sourceHealth.test.status,'ok');
  assert.equal(state.sourceHealth.test.lastItemCount,3);
  assert.equal(state.sourceHealth.test.consecutiveEmpty,0);
  assert.equal(engine.getSourceHealthReport(state).empty.length,0);
});
test('workflow gate executes after commit to preserve legitimately generated reports',()=>{
  const fs=require('node:fs');
  const path=require('node:path');
  const wf=fs.readFileSync(path.join(__dirname,'..','.github/workflows/sentinel-apex.yml'),'utf8');
  assert(wf.indexOf('Commit and push intel') < wf.indexOf('node scripts/check-intel-source-yield.cjs'));
  assert(wf.indexOf('node scripts/check-intel-source-yield.cjs') < wf.indexOf('name: "Run summary"'));
  assert.match(wf,/cancel-in-progress: false/);
});

test('scheduled publisher heartbeat never manufactures a new report timestamp or missing item evidence date',()=>{
  const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
  const source=fs.readFileSync(path.join(__dirname,'..','.github/workflows/sentinel-apex.yml'),'utf8');
  const start=source.indexOf('- name: "Ensure feed heartbeat (production stability)"');
  const end=source.indexOf('      # A timed-out publisher',start);
  assert.ok(start>=0&&end>start,'publisher heartbeat step must exist');
  const script=source.slice(start,end).match(/node -e "\n([\s\S]*?)\n          " 2>&1/);
  assert.ok(script,'embedded heartbeat program must be present and isolated');
  const prior='2026-10-23T04:58:15.799Z';
  const now='2026-11-03T16:15:00.000Z';
  const fixture={
    metadata:{generatedAt:prior,lastPipelineRun:prior},
    generatedAt:prior,
    items:[
      {id:'existing',_addedAt:'2026-10-20',pubDate:'2026-10-19'},
      {id:'dated',pubDate:'2026-10-21'},
      {id:'undated'},
      {id:'invalid',pubDate:'unknown'},
      {id:'future',pubDate:'2027-01-01'},
    ],
  };
  let output;
  class FixedDate extends Date{
    constructor(...args){super(...(args.length?args:[now]));}
    static now(){return Date.parse(now);}
  }
  const context={
    Date:FixedDate,
    require(name){
      assert.equal(name,'fs');
      return {
        readFileSync(file,encoding){assert.equal(file,'live-intel.json');assert.equal(encoding,'utf8');return JSON.stringify(fixture);},
        writeFileSync(file,content){assert.equal(file,'live-intel.json');output=JSON.parse(content);},
      };
    },
    console:{log(){},error(message){throw new Error(String(message));}},
  };
  vm.runInNewContext(script[1],context,{timeout:1000});
  assert.ok(output,'heartbeat must persist the audit-only update');
  assert.equal(output.generatedAt,prior,'top-level report timestamp preserved');
  assert.equal(output.metadata.generatedAt,prior,'report generatedAt never refreshed by heartbeat');
  assert.equal(output.metadata.lastPipelineRun,now,'pipeline heartbeat remains separately visible');
  assert.equal(output._heartbeat,now,'diagnostic heartbeat remains separately visible');
  assert.equal(output.items[0]._addedAt,'2026-10-20');
  assert.equal(Object.hasOwn(output.items[1],'_addedAt'),false,'a source article date never proves platform ingestion time');
  assert.equal(Object.hasOwn(output.items[2],'_addedAt'),false,'missing item date stays unknown');
  assert.equal(Object.hasOwn(output.items[3],'_addedAt'),false,'invalid item date stays unknown');
  assert.equal(Object.hasOwn(output.items[4],'_addedAt'),false,'future item date is not trusted');
  const missingMeta={items:[{id:'undated'}]};
  let output2;
  context.require=()=>({
    readFileSync(){return JSON.stringify(missingMeta);},
    writeFileSync(_,content){output2=JSON.parse(content);},
  });
  vm.runInNewContext(script[1],{...context},{timeout:1000});
  assert.equal(Object.hasOwn(output2.metadata,'generatedAt'),false,'missing publication timestamp is never forged');
  assert.equal(output2.metadata.lastPipelineRun,now);
});


function withCurrentSourceReceipts(state,{ok=3,empty=26,degraded=6,lagMinutes=0}={}) {
  const checkedAt=Date.parse(state.lastIngestion.checkedAt);
  const timestamp=new Date(checkedAt-lagMinutes*60000).toISOString();
  state.sourceHealth={};
  for (let i=0;i<ok+empty;i++) {
    const name='source_'+String(i).padStart(2,'0');
    state.sourceHealth[name]={
      status:i<ok?'ok':'empty',lastItemCount:i<ok?1:0,
      consecutiveFails:0,lastSuccess:timestamp,lastFetchAt:timestamp
    };
  }
  for(let i=0;i<degraded;i++){
    state.sourceHealth['denied_'+i]={
      status:'degraded',lastItemCount:0,consecutiveFails:70,
      lastError:'COMMERCIAL_USE_NOT_APPROVED'
    };
  }
  return state;
}

test('reproduce 21 Nov failure: 29 verified fresh polls, only 3 novel sources and 2 reports is a publisher success with explicit GA hold',()=>{
  const state=withCurrentSourceReceipts(fixture({
    active:3,total:35,records:158,reports:2,age:0
  }));
  const result=evaluate(state,now);
  assert.equal(result.status,'POLL_HEALTHY_LOW_YIELD');
  assert.equal(result.exitCode,0,'real report publication must not be retroactively reported as failed polling');
  assert.equal(result.code,'FRESH_SOURCE_POLLS_CONFIRMED_LOW_NEW_RECORD_DIVERSITY');
  assert.equal(result.freshSuccessfulPolls,29);
  assert.equal(result.activeSources,3,'only sources with real new data count toward source diversity');
  assert.equal(result.fetchedRecords,158);
  assert.equal(result.reportsGenerated,2);
  assert.equal(result.releaseSourceDiversityCertified,false,'never silently satisfy five-novel-source enterprise gate');
  assert.notEqual(result.status,'COVERAGE_VERIFIED');
});

test('fresh valid empty source polls are not invented report records',()=>{
  const state=withCurrentSourceReceipts(fixture({
    active:0,total:35,records:0,reports:0,age:0
  }),{ok:0,empty:29,degraded:6});
  const result=evaluate(state,now);
  assert.equal(result.status,'POLL_HEALTHY_LOW_YIELD');
  assert.equal(result.reportsGenerated,0);
  assert.equal(result.fetchedRecords,0);
  assert.equal(result.activeSources,0);
  assert.equal(result.releaseSourceDiversityCertified,false);
});

test('historical source success cannot turn a weak current run green',()=>{
  const stale=withCurrentSourceReceipts(fixture({
    active:3,total:35,records:158,reports:2,age:0
  }),{lagMinutes:30});
  const result=evaluate(stale,now);
  assert.equal(result.status,'SOURCE_COVERAGE_DEGRADED');
  assert.equal(result.exitCode,2);
  assert.equal(result.freshSuccessfulPolls,0);
});

test('unapproved/commercially blocked and 404 or 429 sources never count as healthy',()=>{
  const state=withCurrentSourceReceipts(fixture({active:3,total:35,records:158,reports:2,age:0}),
    {ok:1,empty:3,degraded:31});
  const result=evaluate(state,now);
  assert.equal(result.status,'SOURCE_COVERAGE_DEGRADED');
  assert.equal(result.freshSuccessfulPolls,4);
  assert.equal(result.exitCode,2);
});

test('fake, future, replayed and contradictory source receipts cannot bypass the source floor',()=>{
  for(const scenario of ['future','stale','inconsistent_fetch','empty_with_items','ok_without_items','failing_transport']){
    const state=withCurrentSourceReceipts(fixture({active:3,total:35,records:20,reports:1,age:0}),
      {ok:0,empty:5,degraded:30});
    for(const source of Object.values(state.sourceHealth)){
      if(source.status!=='empty')continue;
      if(scenario==='future')source.lastSuccess=new Date(now+10*60000).toISOString();
      if(scenario==='stale')source.lastSuccess=new Date(now-20*60000).toISOString();
      if(scenario==='inconsistent_fetch')source.lastFetchAt=new Date(now-20*60000).toISOString();
      if(scenario==='empty_with_items')source.lastItemCount=3;
      if(scenario==='ok_without_items'){source.status='ok';source.lastItemCount=0;}
      if(scenario==='failing_transport')source.consecutiveFails=1;
    }
    const actual=evaluate(state,now);
    assert.equal(actual.status,'SOURCE_COVERAGE_DEGRADED',scenario);
    assert.equal(actual.exitCode,2,scenario);
  }
});

test('source poll ledger cannot contain more sources than the configured source count',()=>{
  const state=withCurrentSourceReceipts(fixture({active:1,total:5,records:5,reports:1,age:0}),{
    ok:2,empty:4,degraded:0
  });
  assert.equal(evaluate(state,now).code,'SOURCE_POLL_LEDGER_INVALID');
});

test('five nonempty novel sources remain the only FULL coverage-success status',()=>{
  const state=fixture({active:5,total:35,records:5,reports:1,age:0});
  const result=evaluate(state,now);
  assert.equal(result.status,'COVERAGE_VERIFIED');
  assert.equal(result.releaseSourceDiversityCertified,true);
});

test('commercial GA and full platform-health gates continue to reject low-yield as full source verification',()=>{
  const fs=require('node:fs'),path=require('node:path');
  for(const file of ['scripts/soc-commercial-ga-gate.cjs','scripts/assess-pipeline-operational-health.cjs']){
    const source=fs.readFileSync(path.join(__dirname,'..',file),'utf8');
    assert.match(source,/source\.status\s*!==\s*'COVERAGE_VERIFIED'|yieldResult\.status\s*===\s*'COVERAGE_VERIFIED'/,
      file+' must require full five-nonempty-source coverage for platform or commercial certification');
    assert.doesNotMatch(source,/POLL_HEALTHY_LOW_YIELD/,file+' must not consider healthy empty polls a substitute for real diverse intel');
  }
});
