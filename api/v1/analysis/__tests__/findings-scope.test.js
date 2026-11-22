'use strict';

// Regression harness: all dependencies stay in-memory; no live Redis,
// Cloudflare D1, billable operations, identity providers or customer records.
const mockGetInvestigation = jest.fn();
const mockGetFinding = jest.fn();
const mockGetInvestigationFindings = jest.fn();
const mockCreateAnalyticalFinding = jest.fn();
const mockReviewFinding = jest.fn();
const mockPublishFinding = jest.fn();
const mockGetAnalysisReport = jest.fn();

jest.mock('../../../_lib/redis',()=>({}));
jest.mock('../../../_lib/investigation-manager',()=>({
  InvestigationManager: jest.fn().mockImplementation(()=>({
    getInvestigation:mockGetInvestigation
  }))
}));
jest.mock('../../../_lib/analysis-manager',()=>({
  AnalysisManager: jest.fn().mockImplementation(()=>({
    getFinding:mockGetFinding,
    getInvestigationFindings:mockGetInvestigationFindings,
    createAnalyticalFinding:mockCreateAnalyticalFinding,
    reviewFinding:mockReviewFinding,
    publishFinding:mockPublishFinding,
    getAnalysisReport:mockGetAnalysisReport,
  }))
}));
jest.mock('../../../_lib/analyst-auth',()=>({requireAnalyst:jest.fn()}));

const handler=require('../findings');
const {requireAnalyst}=require('../../../_lib/analyst-auth');
const BASE='/api/v1/analysis/findings';
const ID='a'.repeat(32);
function response(){
  const r={headers:{},statusCode:0,body:null};
  r.setHeader=jest.fn((k,v)=>{r.headers[k.toLowerCase()]=v});
  r.status=jest.fn(code=>{r.statusCode=code;return r});
  r.json=jest.fn(body=>{r.body=body;return r});
  r.end=jest.fn(()=>r);
  return r;
}
function request(method='GET',url=BASE,body=undefined,query={}){
  return {method,url,body,query,headers:body?{'content-type':'application/json'}:{}};
}
function login(id='alpha',role='analyst'){
  requireAnalyst.mockResolvedValue({id,role});
}
beforeEach(()=>{
  jest.clearAllMocks();
  login();
  mockGetInvestigation.mockResolvedValue({id:'inv_123',assignee:'alpha'});
  mockGetFinding.mockResolvedValue({id:ID,investigationId:'inv_123'});
  mockGetInvestigationFindings.mockResolvedValue([{id:ID,status:'draft'}]);
  mockCreateAnalyticalFinding.mockResolvedValue({success:true,finding:{id:ID},validation:{isValid:true},scoring:{}});
  mockReviewFinding.mockResolvedValue({success:true});
  mockPublishFinding.mockResolvedValue({success:true});
  mockGetAnalysisReport.mockResolvedValue({findings:[]});
});
test('anonymous GET and POST fail closed before reading or writing findings',async()=>{
  requireAnalyst.mockImplementation(async (_req,res,fail)=>{
    fail(res,401,'UNAUTHORIZED','Analyst access only');return null;
  });
  for(const [method,body,query] of [
    ['GET',undefined,{investigationId:'inv_123'}],
    ['POST',{investigationId:'inv_123',statement:'safe'},{}]
  ]){
    const res=response();
    await handler(request(method,BASE,body,query),res);
    expect(res.statusCode).toBe(401);
  }
  expect(mockGetInvestigation).not.toHaveBeenCalled();
  expect(mockGetInvestigationFindings).not.toHaveBeenCalled();
  expect(mockCreateAnalyticalFinding).not.toHaveBeenCalled();
});
test('assigned analyst can list within bounded scoped investigation',async()=>{
  const res=response();
  await handler(request('GET',BASE,undefined,{investigationId:'inv_123',limit:'5'}),res);
  expect(res.statusCode).toBe(200);
  expect(mockGetInvestigationFindings).toHaveBeenCalledWith('inv_123',5);
  expect(res.headers['cache-control']).toMatch(/no-store/);
  expect(res.headers['access-control-allow-origin']).toBeUndefined();
});
test('foreign analyst gets indistinguishable 404 and no data',async()=>{
  login('beta');
  for(const [method,body,query] of [
    ['GET',undefined,{investigationId:'inv_123'}],
    ['POST',{investigationId:'inv_123',statement:'untrusted'},{}]
  ]){
    const res=response();
    await handler(request(method,BASE,body,query),res);
    expect(res.statusCode).toBe(404);
    expect(res.body.error.code).toBe('NOT_FOUND');
  }
  expect(mockGetInvestigationFindings).not.toHaveBeenCalled();
  expect(mockCreateAnalyticalFinding).not.toHaveBeenCalled();
});
test('missing investigation or unavailable scope authority never publishes findings',async()=>{
  mockGetInvestigation.mockResolvedValue(null);
  let r=response();
  await handler(request('POST',BASE,{investigationId:'inv_123',statement:'none'}),r);
  expect(r.statusCode).toBe(404);
  mockGetInvestigation.mockRejectedValue(new Error('D1/Redis down'));
  r=response();
  await handler(request('GET',BASE,undefined,{investigationId:'inv_123'}),r);
  expect(r.statusCode).toBe(503);
  expect(mockGetInvestigationFindings).not.toHaveBeenCalled();
  expect(mockCreateAnalyticalFinding).not.toHaveBeenCalled();
});
test('authenticated assigned analyst may create but only after scope',async()=>{
  const r=response();
  await handler(request('POST',BASE,{investigationId:'inv_123',statement:'Validated evidence'}),r);
  expect(r.statusCode).toBe(201);
  expect(mockCreateAnalyticalFinding).toHaveBeenCalledWith('inv_123',expect.objectContaining({statement:'Validated evidence'}));
});
test('finding read also validates parent investigation ownership, not just guessed finding ID',async()=>{
  login('beta');
  const r=response();
  await handler(request('GET',BASE+'/'+ID),r);
  expect(mockGetFinding).toHaveBeenCalledWith(ID);
  expect(r.statusCode).toBe(404);
  expect(mockGetAnalysisReport).not.toHaveBeenCalled();
});
test('spoofed reviewer identity cannot override verified analyst principal',async()=>{
  const r=response();
  await handler(request('PUT',BASE+'/'+ID+'/review',{reviewer:'attacker',approved:true}),r);
  expect(r.statusCode).toBe(200);
  expect(mockReviewFinding).toHaveBeenCalledWith(ID,'alpha',true,'');
});
test('publish requires authorized internal lead and verified publisher identity',async()=>{
  let r=response();
  await handler(request('PUT',BASE+'/'+ID+'/publish',{publisher:'attacker'}),r);
  expect(r.statusCode).toBe(403);
  expect(mockPublishFinding).not.toHaveBeenCalled();
  login('lead','lead_analyst');
  r=response();
  await handler(request('PUT',BASE+'/'+ID+'/publish',{publisher:'attacker'}),r);
  expect(r.statusCode).toBe(200);
  expect(mockPublishFinding).toHaveBeenCalledWith(ID,'lead');
});
test('preflight never exposes cross-origin credentials',async()=>{
  const r=response();
  await handler(request('OPTIONS'),r);
  expect(r.statusCode).toBe(204);
  expect(r.headers['access-control-allow-origin']).toBeUndefined();
  expect(r.headers['access-control-allow-credentials']).toBeUndefined();
  expect(requireAnalyst).not.toHaveBeenCalled();
});
test('invalid object scope and unbounded list parameters fail before Redis record retrieval',async()=>{
  for(const query of [
    {investigationId:'../../other'},
    {investigationId:'inv_123',limit:'9999'},
    {investigationId:'inv_123',limit:'-1'},
    {investigationId:'inv_123',status:'bad;drop'}
  ]){
    const r=response();
    await handler(request('GET',BASE,undefined,query),r);
    expect([400,404]).toContain(r.statusCode);
  }
  expect(mockGetInvestigationFindings).not.toHaveBeenCalled();
});
test('oversized write payload blocked before authentication or state write',async()=>{
  const r=response();
  await handler(request('POST',BASE,{investigationId:'inv_123',statement:'x'.repeat(65537)}),r);
  expect(r.statusCode).toBe(413);
  expect(requireAnalyst).not.toHaveBeenCalled();
  expect(mockCreateAnalyticalFinding).not.toHaveBeenCalled();
});

test('real Worker Node response shim never injects wildcard CORS for authenticated findings',async()=>{
  const {createNodeResponse}=require('../../../../workers/lib/node-compat');
  const {res,response}=createNodeResponse();
  await handler(request('GET',BASE,undefined,{investigationId:'inv_123'}),res);
  const actual=await response;
  expect(actual.status).toBe(200);
  expect(actual.headers.get('access-control-allow-origin')).toBeNull();
  expect(actual.headers.get('access-control-allow-credentials')).toBeNull();
  expect(actual.headers.get('cache-control')).toMatch(/no-store/);
  expect(actual.headers.get('referrer-policy')).toBe('no-referrer');
  expect(actual.headers.get('content-security-policy')).toMatch(/default-src 'none'/);
});
