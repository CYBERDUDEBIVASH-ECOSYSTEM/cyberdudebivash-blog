'use strict';
/** Threat-actor persistence must never use a globally shared actorId key. */
jest.mock('../evidence-validator',()=>({
  EvidenceValidator:jest.fn().mockImplementation(()=>({
    validateThreatActorAssessment:jest.fn(async()=>({isValid:true}))
  }))
}));
jest.mock('../confidence-scorer',()=>({
  ConfidenceScorer:jest.fn().mockImplementation(()=>({}))
}));
jest.mock('../gap-analyzer',()=>({
  GapAnalyzer:jest.fn().mockImplementation(()=>({}))
}));
const {AnalysisManager}=require('../analysis-manager');
test('same actorId in separate investigations writes isolated Redis keys',async()=>{
  const store={};
  const redis={
    hset:jest.fn(async(key,flat)=>{store[key]=flat}),
    zadd:jest.fn(async()=>1),
  };
  const svc=new AnalysisManager(redis);
  const a=await svc.createThreatActorAssessment('inv_one','shared_actor',{});
  const b=await svc.createThreatActorAssessment('inv_two','shared_actor',{});
  expect(a.success).toBe(true);
  expect(b.success).toBe(true);
  expect(redis.hset).toHaveBeenNthCalledWith(1,'actor:inv_one:shared_actor',expect.any(Array));
  expect(redis.hset).toHaveBeenNthCalledWith(2,'actor:inv_two:shared_actor',expect.any(Array));
  expect(store['actor:inv_one:shared_actor']).not.toEqual(store['actor:inv_two:shared_actor']);
  expect(store['actor:shared_actor']).toBeUndefined();
});
