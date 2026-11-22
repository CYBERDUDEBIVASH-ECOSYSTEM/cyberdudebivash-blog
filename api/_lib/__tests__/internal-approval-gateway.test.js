'use strict';
/** Offline zero-trust control-plane regression; no Redis, Cloudflare, network or billing. */
const {createInternalApprovalGateway,authorizeAction,MAX_BODY_BYTES} = require('../internal-approval-gateway');
const {createNodeResponse}=require('../../../workers/lib/node-compat');
const fs=require('node:fs'),path=require('node:path');

const payload={approvalLevel:'MANAGER',approver:'spoofed',reviewer:'spoofed',
  analyst:'spoofed',submitter:'spoofed',publisher:'spoofed',role:'executive'};
function request(method,url,body,query={}){
  return {method,url,body,query,headers:body===undefined?{}:{'content-type':'application/json'}};
}
async function call(kind,method,url,body,actor={id:'analyst1',role:'lead_analyst'},query={}){
  let n=0,seen;
  const gate=createInternalApprovalGateway(async(req,res)=>{
    n++;seen={actor:req.verifiedAnalyst,body:req.body};
    res.status(200).json({ok:true,body:req.body});
  },{kind,requireAnalystFn:async(_req,res,fail)=>{
    if(!actor){fail(res,401,'UNAUTHORIZED');return null;}
    return actor;
  }});
  const {res,response}=createNodeResponse();
  await gate(request(method,url,body,query),res);
  return {result:await response,called:n,seen};
}
const PRODUCT='/api/v1/products/approvals/product1';
const QUALITY='/api/v1/quality/report1';

describe('P0 internal publication and product approval zero trust gateway',()=>{
  test.each(['quality','products'])('%s: no credential => no read or approval write',async kind=>{
    const base=kind==='quality'?QUALITY:PRODUCT;
    for(const method of ['GET','POST']){
      const x=await call(kind,method,base+'/approve',payload,null);
      expect(x.result.status).toBe(401);
      expect(x.called).toBe(0);
      expect(x.result.headers.get('cache-control')).toMatch(/no-store/);
      expect(x.result.headers.get('access-control-allow-origin')).toBeNull();
    }
  });
  test('no browser wildcard CORS on success or preflight',async()=>{
    const x=await call('quality','GET',QUALITY+'/review');
    const p=await call('quality','OPTIONS',QUALITY+'/review');
    expect(x.result.status).toBe(200);
    expect(p.result.status).toBe(204);
    for(const {result} of [x,p]){
      expect(result.headers.get('access-control-allow-origin')).toBeNull();
      expect(result.headers.get('access-control-allow-credentials')).toBeNull();
      expect(result.headers.get('content-security-policy')).toMatch(/frame-ancestors 'none'/);
      expect(result.headers.get('cache-control')).toMatch(/no-store/);
    }
  });
  test('body identities and role are overwritten by verified principal',async()=>{
    const x=await call('products','POST',PRODUCT+'/approve',payload);
    expect(x.result.status).toBe(200);
    expect(x.called).toBe(1);
    for(const f of ['approver','reviewer','analyst','submitter','publisher'])
      expect(x.seen.body[f]).toBe('analyst1');
    expect(x.seen.body.role).toBe('lead_analyst');
    expect(x.seen.actor).toEqual({id:'analyst1',role:'lead_analyst'});
  });
  test('an analyst cannot impersonate product executive or legal/compliance approval',async()=>{
    for(const level of ['EXECUTIVE','LEGAL','COMPLIANCE','__proto__','constructor']){
      const x=await call('products','POST',PRODUCT+'/approve',{...payload,approvalLevel:level});
      expect(x.result.status).toBe(403);
      expect(x.called).toBe(0);
    }
  });
  test('product levels require their corresponding configured reviewer identity',async()=>{
    const roles={MANAGER:'lead_analyst',EXECUTIVE:'executive',LEGAL:'legal',COMPLIANCE:'compliance'};
    for(const [approvalLevel,role] of Object.entries(roles)){
      const x=await call('products','POST',PRODUCT+'/approve',
        {...payload,approvalLevel},{id:role+'1',role});
      expect(x.result.status).toBe(200);
      expect(x.called).toBe(1);
    }
  });
  test('publication approval requires lead; executive approval requires executive identity',async()=>{
    for(const [action,role,expected] of [
      ['approve','analyst',403],['approve','lead_analyst',200],
      ['executive-approval','lead_analyst',403],
      ['executive-approval','soc_admin',403],
      ['executive-approval','executive',200]
    ]){
      const x=await call('quality','POST',QUALITY+'/'+action,payload,{id:'operator1',role});
      expect(x.result.status).toBe(expected);
      expect(x.called).toBe(expected===200?1:0);
    }
  });
  test('product reject requires lead but submit-review supports authenticated analyst',async()=>{
    const deny=await call('products','POST',PRODUCT+'/reject',payload,{id:'regular1',role:'analyst'});
    expect(deny.result.status).toBe(403);
    const allowed=await call('products','POST',PRODUCT+'/submit-review',payload,{id:'regular1',role:'analyst'});
    expect(allowed.result.status).toBe(200);
  });
  test('oversized body fails before the legacy handler',async()=>{
    const x=await call('quality','POST',QUALITY+'/review',{text:'X'.repeat(MAX_BODY_BYTES+10)});
    expect(x.result.status).toBe(413);
    expect(x.called).toBe(0);
  });
  test('GET limit accepts only bounded positive integers',async()=>{
    for(const limit of ['0','-1','999','100000','2x']){
      const x=await call('products','GET',PRODUCT+'/pending',undefined,{id:'analyst1',role:'analyst'},{limit});
      expect(x.result.status).toBe(400);
      expect(x.called).toBe(0);
    }
    const yes=await call('products','GET',PRODUCT+'/pending',undefined,{id:'analyst1',role:'analyst'},{limit:'20'});
    expect(yes.result.status).toBe(200);
  });
  test('unsupported methods and wrong paths cannot call internal approval handler',async()=>{
    const x=await call('products','DELETE',PRODUCT+'/approve',payload);
    const y=await call('products','GET','/api/v1/products/approvals-other/approve');
    expect(x.result.status).toBe(405);
    expect(y.result.status).toBe(404);
    expect(x.called+y.called).toBe(0);
  });
  test('malformed principal never reaches the approval control plane',async()=>{
    const x=await call('quality','POST',QUALITY+'/review',payload,{id:'',role:'executive'});
    expect(x.result.status).toBe(403);
    expect(x.called).toBe(0);
  });
  test('both live handler modules are wrapped and refuse wildcard CORS',()=>{
    const root=path.resolve(__dirname,'../../..');
    for(const [route,kind] of [
      ['api/v1/quality/index.js','quality'],
      ['api/v1/products/approvals.js','products']
    ]){
      const code=fs.readFileSync(path.join(root,route),'utf8');
      expect(code).toContain("createInternalApprovalGateway(legacyApprovalHandler, {kind:'"+kind+"'})");
      expect(code).not.toMatch(/['"]Access-Control-Allow-Origin['"]\s*:\s*['"]\*['"]/);
    }
  });
});
