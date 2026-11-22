'use strict';
/** In-memory P0 authorization regression tests: no Redis/Cloudflare/customer writes. */
const mockRequireAnalyst=jest.fn();
const mockGetInvestigation=jest.fn();
const mockRedisHgetall=jest.fn();
const mockCreateSituationAssessment=jest.fn();
const mockCreateThreatActorAssessment=jest.fn();
const mockCreateTechnicalAssessment=jest.fn();
const mockCreateExecutiveAssessment=jest.fn();
const mockGenerateInformationGaps=jest.fn();

jest.mock('../../../_lib/redis',()=>({hgetall:(...a)=>mockRedisHgetall(...a)}));
jest.mock('../../../_lib/analyst-auth',()=>({
  requireAnalyst:(...a)=>mockRequireAnalyst(...a)
}));
jest.mock('../../../_lib/investigation-manager',()=>({
  InvestigationManager:jest.fn().mockImplementation(()=>({
    getInvestigation:(...a)=>mockGetInvestigation(...a)
  }))
}));
jest.mock('../../../_lib/analysis-manager',()=>({
  AnalysisManager:jest.fn().mockImplementation(()=>({
    createSituationAssessment:(...a)=>mockCreateSituationAssessment(...a),
    createThreatActorAssessment:(...a)=>mockCreateThreatActorAssessment(...a),
    createTechnicalAssessment:(...a)=>mockCreateTechnicalAssessment(...a),
    createExecutiveAssessment:(...a)=>mockCreateExecutiveAssessment(...a),
    generateInformationGaps:(...a)=>mockGenerateInformationGaps(...a),
  }))
}));
const handler=require('../assessments');
const {createNodeResponse}=require('../../../../workers/lib/node-compat');
const BASE='/api/v1/analysis/assessments';
const BODY={investigationId:'inv_123',overview:'Validated impact'};
function req(method,path,body){
  return {method,url:path,headers:body?{'content-type':'application/json'}:{},body};
}
async function call(method,path,body){
  const {res,response}=createNodeResponse();
  await handler(req(method,path,body),res);
  return response;
}
beforeEach(()=>{
  jest.clearAllMocks();
  mockRequireAnalyst.mockResolvedValue({id:'analyst1',role:'analyst'});
  mockGetInvestigation.mockResolvedValue({id:'inv_123',assignee:'analyst1'});
  mockRedisHgetall.mockResolvedValue(['investigationId','inv_123','overview','Safe case']);
  for(const f of [
    mockCreateSituationAssessment,mockCreateThreatActorAssessment,
    mockCreateTechnicalAssessment,mockCreateExecutiveAssessment
  ]) f.mockResolvedValue({success:true,assessment:{investigationId:'inv_123'},validation:{isValid:true}});
  mockGenerateInformationGaps.mockResolvedValue({investigationId:'inv_123',gaps:[]});
});
test('unauthenticated read/write rejected without any private lookup',async()=>{
  mockRequireAnalyst.mockImplementation(async(_req,res,fail)=>{
    fail(res,401,'UNAUTHORIZED','Analyst credential required');return null;
  });
  for(const [method,path,body] of [
    ['GET',BASE+'/inv_123/situation',undefined],
    ['POST',BASE+'/technical',{investigationId:'inv_123'}]
  ])expect((await call(method,path,body)).status).toBe(401);
  expect(mockGetInvestigation).not.toHaveBeenCalled();
  expect(mockRedisHgetall).not.toHaveBeenCalled();
  expect(mockCreateTechnicalAssessment).not.toHaveBeenCalled();
});
test('foreign analyst cannot read, write, or enumerate investigation',async()=>{
  mockRequireAnalyst.mockResolvedValue({id:'analyst2',role:'analyst'});
  for(const [method,path,body] of [
    ['GET',BASE+'/inv_123/situation',undefined],
    ['POST',BASE+'/situation',BODY],
    ['GET',BASE+'/inv_123/actor/actor1',undefined]
  ]) {
    const response=await call(method,path,body);
    expect(response.status).toBe(404);
    expect((await response.json()).error.code).toBe('NOT_FOUND');
  }
  expect(mockRedisHgetall).not.toHaveBeenCalled();
  expect(mockCreateSituationAssessment).not.toHaveBeenCalled();
});
test('missing investigation and unavailable authority fail closed',async()=>{
  mockGetInvestigation.mockResolvedValue(null);
  const missing=await call('POST',BASE+'/situation',BODY);
  expect(missing.status).toBe(404);
  mockGetInvestigation.mockRejectedValue(new Error('Redis unavailable'));
  const unavailable=await call('GET',BASE+'/inv_123/technical');
  expect(unavailable.status).toBe(503);
  expect(mockCreateSituationAssessment).not.toHaveBeenCalled();
  expect(mockRedisHgetall).not.toHaveBeenCalled();
});
test('owned investigation can create a technical assessment but private no-store headers persist',async()=>{
  const r=await call('POST',BASE+'/technical',{investigationId:'inv_123',iocs:[]});
  expect(r.status).toBe(201);
  expect(mockCreateTechnicalAssessment).toHaveBeenCalledWith('inv_123',expect.objectContaining({iocs:[]}));
  expect(r.headers.get('cache-control')).toMatch(/no-store/);
  expect(r.headers.get('access-control-allow-origin')).toBeNull();
  expect(r.headers.get('referrer-policy')).toBe('no-referrer');
});
test('owned investigation can read matching situation assessment',async()=>{
  const r=await call('GET',BASE+'/inv_123/situation');
  expect(r.status).toBe(200);
  expect(mockRedisHgetall).toHaveBeenCalledWith('situation:inv_123');
});
test('mismatched embedded investigation is never returned even when key matches',async()=>{
  mockRedisHgetall.mockResolvedValue(['investigationId','other_inv','overview','PRIVATE']);
  const r=await call('GET',BASE+'/inv_123/situation');
  expect(r.status).toBe(404);
  expect((await r.text())).not.toContain('PRIVATE');
});
test('new actor key is bound to requested investigation and actor ID',async()=>{
  mockRedisHgetall.mockResolvedValue(['investigationId','inv_123','actorId','actor1','attribution','known']);
  const r=await call('GET',BASE+'/inv_123/actor/actor1');
  expect(r.status).toBe(200);
  expect(mockRedisHgetall).toHaveBeenCalledWith('actor:inv_123:actor1');
  expect(mockRedisHgetall).toHaveBeenCalledTimes(1);
});
test('historical global actor key is compatible only when parent ID matches',async()=>{
  mockRedisHgetall.mockResolvedValueOnce([]).mockResolvedValueOnce([
    'investigationId','inv_123','actorId','actor1','attribution','historical']);
  const r=await call('GET',BASE+'/inv_123/actor/actor1');
  expect(r.status).toBe(200);
  expect(mockRedisHgetall).toHaveBeenNthCalledWith(1,'actor:inv_123:actor1');
  expect(mockRedisHgetall).toHaveBeenNthCalledWith(2,'actor:actor1');
});
test('historical global actor belonging to a foreign investigation is denied',async()=>{
  mockRedisHgetall.mockResolvedValueOnce([]).mockResolvedValueOnce([
    'investigationId','other_inv','actorId','actor1','attribution','PRIVATE']);
  const r=await call('GET',BASE+'/inv_123/actor/actor1');
  expect(r.status).toBe(404);
  expect((await r.text())).not.toContain('PRIVATE');
});
test('actor write is allowed only for verified parent investigation and valid ID',async()=>{
  const ok=await call('POST',BASE+'/actor',{investigationId:'inv_123',actorId:'actor1'});
  expect(ok.status).toBe(201);
  expect(mockCreateThreatActorAssessment).toHaveBeenCalledWith('inv_123','actor1',expect.any(Object));
  const invalid=await call('POST',BASE+'/actor',{investigationId:'inv_123',actorId:'../../other'});
  expect(invalid.status).toBe(400);
  expect(mockCreateThreatActorAssessment).toHaveBeenCalledTimes(1);
});
test('method, routing, body and input limits are enforced',async()=>{
  for(const [method,path,body,expected] of [
    ['DELETE',BASE+'/inv_123/situation',undefined,405],
    ['GET',BASE+'/inv_123/gaps',undefined,404],
    ['GET',BASE+'/inv_123/actor/../../other',undefined,404],
    ['POST',BASE+'/technical',{investigationId:'inv_123',overview:'x'.repeat(65537)},413],
    ['POST',BASE+'/technical',{investigationId:'../../other'},404]
  ])expect((await call(method,path,body)).status).toBe(expected);
});
test('preflight emits no wildcard CORS or analyst verification',async()=>{
  const r=await call('OPTIONS',BASE+'/inv_123/situation');
  expect(r.status).toBe(204);
  expect(r.headers.get('access-control-allow-origin')).toBeNull();
  expect(r.headers.get('access-control-allow-credentials')).toBeNull();
  expect(mockRequireAnalyst).not.toHaveBeenCalled();
});
