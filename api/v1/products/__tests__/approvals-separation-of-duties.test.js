'use strict';
/** Regression of actual approval module with memory-only Redis and product stubs. */
const mockRequireAnalyst=jest.fn();
const mockGetProduct=jest.fn();
const mockPersistProduct=jest.fn();
const mockApprove=jest.fn();
const mockHgetall=jest.fn();
const mockHset=jest.fn();
const mockZadd=jest.fn();
const mockZrem=jest.fn();
jest.mock('../../../_lib/analyst-auth',()=>({
  requireAnalyst:(...args)=>mockRequireAnalyst(...args)
}));
jest.mock('../../../_lib/redis',()=>({
  hgetall:(...args)=>mockHgetall(...args),
  hset:(...args)=>mockHset(...args),
  zadd:(...args)=>mockZadd(...args),
  zrem:(...args)=>mockZrem(...args),
}));
jest.mock('../../../_lib/product-factory',()=>({
  ProductFactory:jest.fn().mockImplementation(()=>({
    getProduct:(...args)=>mockGetProduct(...args),
    persistProduct:(...args)=>mockPersistProduct(...args),
  }))
}));
const handler=require('../approvals');
const {createNodeResponse}=require('../../../../workers/lib/node-compat');

const ROUTE='/api/v1/products/approvals/product-01/approve';
function setWorkflow({submitter='owner1',approvals=[],status='PENDING'}={}){
  mockHgetall.mockResolvedValue([
    'submitter',submitter,
    'approvalChain',JSON.stringify(approvals),
    'status',status,
    'productId','product-01',
  ]);
}
async function approve({actor='lead1',role='lead_analyst',level='MANAGER',spoof='fake1'}={}){
  mockRequireAnalyst.mockResolvedValue({id:actor,role});
  const req={method:'POST',url:ROUTE,headers:{'content-type':'application/json'},
    query:{},body:{approvalLevel:level,approver:spoof,role:'executive'}};
  const {res,response}=createNodeResponse();
  await handler(req,res);
  return await response;
}
beforeEach(()=>{
  jest.clearAllMocks();
  mockGetProduct.mockResolvedValue({
    productId:'product-01',productType:'detection',status:'UNDER_REVIEW',
    approve:mockApprove,
  });
  mockPersistProduct.mockResolvedValue(undefined);
  mockHset.mockResolvedValue(undefined);
  mockZadd.mockResolvedValue(undefined);
  mockZrem.mockResolvedValue(undefined);
  setWorkflow();
});

test('verified reviewer is recorded instead of request-body approver',async()=>{
  const res=await approve();
  expect(res.status).toBe(200);
  expect(mockApprove).toHaveBeenCalledWith('lead1','MANAGER');
  expect(mockHset).toHaveBeenCalledTimes(1);
  const record=mockHset.mock.calls[0][1];
  const chain=JSON.parse(record[record.indexOf('approvalChain')+1]);
  expect(chain).toHaveLength(1);
  expect(chain[0].approver).toBe('lead1');
  expect(chain[0].approver).not.toBe('fake1');
  expect(res.headers.get('access-control-allow-origin')).toBeNull();
});

test('historically double-parsed Redis approval chain now supports legitimate second reviewer',async()=>{
  setWorkflow({approvals:[{approver:'lead1',level:'MANAGER',decision:'APPROVED'}]});
  const res=await approve({actor:'exec1',role:'executive',level:'EXECUTIVE'});
  expect(res.status).toBe(200);
  expect(mockApprove).toHaveBeenCalledWith('exec1','EXECUTIVE');
  const record=mockHset.mock.calls[0][1];
  const chain=JSON.parse(record[record.indexOf('approvalChain')+1]);
  expect(new Set(chain.map(x=>x.approver)).size).toBe(2);
  const saved=mockPersistProduct.mock.calls[0][0];
  expect(saved.status).toBe('APPROVED');
});

test('submitter cannot approve own product',async()=>{
  setWorkflow({submitter:'lead1'});
  const res=await approve();
  expect(res.status).toBe(409);
  expect((await res.json()).error.code).toBe('SEPARATION_OF_DUTIES_REQUIRED');
  expect(mockApprove).not.toHaveBeenCalled();
  expect(mockPersistProduct).not.toHaveBeenCalled();
});

test('same reviewer cannot approve twice',async()=>{
  setWorkflow({approvals:[{approver:'lead1',level:'MANAGER'}]});
  const res=await approve();
  expect(res.status).toBe(409);
  expect(mockApprove).not.toHaveBeenCalled();
  expect(mockHset).not.toHaveBeenCalled();
});

test('unverifiable pre-existing duplicate chain fails closed',async()=>{
  setWorkflow({approvals:[{approver:'leadA'},{approver:'leadA'}]});
  const res=await approve({actor:'exec1',role:'executive',level:'EXECUTIVE'});
  expect(res.status).toBe(409);
  expect((await res.json()).error.code).toBe('UNVERIFIED_APPROVAL_CHAIN');
  expect(mockApprove).not.toHaveBeenCalled();
});

test('missing submitter provenance fails closed',async()=>{
  setWorkflow({submitter:''});
  const res=await approve();
  expect(res.status).toBe(409);
  expect(mockApprove).not.toHaveBeenCalled();
});

test('unsupported approval-role spoofing blocked before loading product',async()=>{
  const res=await approve({actor:'lead1',role:'lead_analyst',level:'LEGAL',spoof:'legal-counsel'});
  expect(res.status).toBe(403);
  expect(mockGetProduct).not.toHaveBeenCalled();
});


test('approved and in-review products cannot reset their existing approval histories',async()=>{
  for(const status of ['APPROVED','UNDER_REVIEW','PUBLISHED','ARCHIVED','SUPERSEDED']){
    mockGetProduct.mockResolvedValue({status,productId:'product-01',approve:mockApprove});
    mockRequireAnalyst.mockResolvedValue({id:'analyst1',role:'analyst'});
    const req={method:'POST',url:'/api/v1/products/approvals/product-01/submit-review',
      headers:{'content-type':'application/json'},query:{},
      body:{submitter:'attacker',reviewLevel:'MANAGER',message:'retry'}};
    const {res,response}=createNodeResponse();
    await handler(req,res);
    const reply=await response;
    expect(reply.status).toBe(409);
    expect(mockPersistProduct).not.toHaveBeenCalled();
    expect(mockHset).not.toHaveBeenCalled();
  }
});
