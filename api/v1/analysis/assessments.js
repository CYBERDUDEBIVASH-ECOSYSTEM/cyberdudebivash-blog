'use strict';

const redis = require('../../_lib/redis');
const { AnalysisManager } = require('../../_lib/analysis-manager');
const { InvestigationManager } = require('../../_lib/investigation-manager');
const { requireAnalyst } = require('../../_lib/analyst-auth');
const { isValidObjectId, canAccessInvestigation } = require('../../_lib/workbench-object-scope');

const analysisMgr = new AnalysisManager(redis);
const investigationMgr = new InvestigationManager(redis);
const MAX_BODY_BYTES = 65536;
const BASE = '/api/v1/analysis/assessments';
const ASSESSMENT_TYPES = new Set(['situation','actor','technical','executive','gaps']);

const CORS_HEADERS = {
  // Private internal analyst control plane. No wildcard browser access.
  'Cache-Control': 'no-store, no-cache, must-revalidate',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Analyst-Key',
};

function ok(res, data, status = 200) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  res.status(status).json({
    success: true,
    meta: { timestamp: new Date().toISOString() },
    ...data,
  });
}

function fail(res, status, code, message) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  res.status(status).json({
    success: false,
    error: { code, message },
    meta: { timestamp: new Date().toISOString() },
  });
}

// Never use the shared legacy security helper: it emits Access-Control-Allow-Origin:*.
function applyInternalHeaders(res) {
  for (const [key,value] of Object.entries({
    'X-Content-Type-Options':'nosniff',
    'X-Frame-Options':'DENY',
    'Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",
    'Strict-Transport-Security':'max-age=63072000; includeSubDomains; preload',
    'Referrer-Policy':'no-referrer',
    'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
    'Cache-Control':'no-store, no-cache, must-revalidate',
  })) res.setHeader(key,value);
}

async function requireScope(res, caller, investigationId) {
  if (!isValidObjectId(investigationId)) {
    fail(res,404,'NOT_FOUND','Investigation not found');
    return false;
  }
  try {
    const investigation=await investigationMgr.getInvestigation(investigationId);
    if (!investigation || investigation.id!==investigationId ||
        !canAccessInvestigation(caller,investigation)) {
      fail(res,404,'NOT_FOUND','Investigation not found');
      return false;
    }
    return true;
  } catch (_) {
    fail(res,503,'WORKBENCH_UNAVAILABLE','Investigation authority unavailable');
    return false;
  }
}

module.exports = async (req, res) => {
  applyInternalHeaders(res);
  if (req.method==='OPTIONS') {
    Object.entries(CORS_HEADERS).forEach(([key,value])=>res.setHeader(key,value));
    return res.status(204).end();
  }
  if (!['GET','POST'].includes(req.method))
    return fail(res,405,'METHOD_NOT_ALLOWED','Unsupported method');

  // Authenticate first. Never fetch or modify private assessments anonymously.
  const caller=await requireAnalyst(req,res,fail);
  if(!caller)return;
  if(typeof caller.id!=='string' || !isValidObjectId(caller.id) ||
      typeof caller.role!=='string')
    return fail(res,403,'FORBIDDEN','Invalid analyst principal');

  const pathname=String(req.url||'').split('?')[0].replace(/\/$/,'');
  if(pathname.length>512 || !pathname.startsWith(BASE+'/'))
    return fail(res,404,'NOT_FOUND','Endpoint not found');
  const parts=pathname.slice(BASE.length+1).split('/');
  if(parts.some(p=>!p || p.length>100))
    return fail(res,404,'NOT_FOUND','Endpoint not found');

  if(req.method==='POST' && parts.length===1 && ASSESSMENT_TYPES.has(parts[0])) {
    const ct=String((req.headers||{})['content-type']||'').toLowerCase();
    if(ct && !/^application\/json(?:\s*;|$)/.test(ct))
      return fail(res,415,'UNSUPPORTED_MEDIA_TYPE','JSON required');
    const declared=(req.headers||{})['content-length'];
    if(declared!==undefined &&
        (!/^\d+$/.test(String(declared)) || Number(declared)>MAX_BODY_BYTES))
      return fail(res,413,'PAYLOAD_TOO_LARGE','Request body too large');
    let body;
    try {
      const raw=typeof req.body==='string'?req.body:JSON.stringify(req.body??{});
      if(Buffer.byteLength(raw,'utf8')>MAX_BODY_BYTES)
        return fail(res,413,'PAYLOAD_TOO_LARGE','Request body too large');
      body=JSON.parse(raw);
    } catch (_) {return fail(res,400,'INVALID_JSON','Malformed JSON');}
    if(!body || typeof body!=='object' || Array.isArray(body))
      return fail(res,400,'INVALID_BODY','JSON object required');
    if(!await requireScope(res,caller,body.investigationId))return;
    if(parts[0]==='actor' && !isValidObjectId(body.actorId))
      return fail(res,400,'INVALID_ACTOR_ID','Invalid actor ID');
    req.body=body;
    if(parts[0]==='situation')return handleCreateSituationAssessment(req,res);
    if(parts[0]==='actor')return handleCreateThreatActorAssessment(req,res);
    if(parts[0]==='technical')return handleCreateTechnicalAssessment(req,res);
    if(parts[0]==='executive')return handleCreateExecutiveAssessment(req,res);
    return handleGenerateGaps(req,res);
  }

  if(req.method==='GET' && parts.length===2 &&
     ['situation','technical','executive'].includes(parts[1])) {
    if(!await requireScope(res,caller,parts[0]))return;
    if(parts[1]==='situation')return handleGetSituationAssessment(req,res,parts[0]);
    if(parts[1]==='technical')return handleGetTechnicalAssessment(req,res,parts[0]);
    return handleGetExecutiveAssessment(req,res,parts[0]);
  }

  if(req.method==='GET' && parts.length===3 && parts[1]==='actor') {
    if(!isValidObjectId(parts[2]))
      return fail(res,404,'NOT_FOUND','Actor assessment not found');
    if(!await requireScope(res,caller,parts[0]))return;
    return handleGetThreatActorAssessment(req,res,parts[0],parts[2]);
  }
  return fail(res,404,'NOT_FOUND','Endpoint not found');
};

async function handleCreateSituationAssessment(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, overview, scope, affectedSectors, geographicContext, estimatedImpact, timelineEvents } = body;

    if (!investigationId) {
      return fail(res, 400, 'MISSING_ID', 'investigationId required');
    }

    const result = await analysisMgr.createSituationAssessment(investigationId, {
      overview,
      scope,
      affectedSectors: affectedSectors || [],
      geographicContext: geographicContext || [],
      estimatedImpact,
      timelineEvents: timelineEvents || [],
    });

    if (!result.success) {
      return fail(res, 400, 'VALIDATION_FAILED', result.error);
    }

    return ok(res, {
      assessment: result.assessment,
      validation: result.validation,
    }, 201);
  } catch (e) {
    return fail(res, 500, 'CREATE_FAILED', e.message);
  }
}

async function handleGetSituationAssessment(req, res, id) {
  try {
    const key = `situation:${id}`;
    const data = await redis.hgetall(key);

    if (!data || data.length === 0) {
      return fail(res, 404, 'NOT_FOUND', `Situation assessment not found for: ${id}`);
    }

    const assessment = {};
    for (let i = 0; i < data.length; i += 2) {
      assessment[data[i]] = data[i + 1];
    }

    if (assessment.investigationId !== id)
      return fail(res, 404, 'NOT_FOUND', 'Assessment not found');
    return ok(res, { assessment });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleCreateThreatActorAssessment(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, actorId, attribution, attributionConfidence, supportingEvidence, contradictoryEvidence, aliases, attributionGaps } = body;

    if (!investigationId || !actorId) {
      return fail(res, 400, 'MISSING_ID', 'investigationId and actorId required');
    }

    const result = await analysisMgr.createThreatActorAssessment(investigationId, actorId, {
      attribution,
      attributionConfidence,
      supportingEvidence: supportingEvidence || [],
      contradictoryEvidence: contradictoryEvidence || [],
      aliases: aliases || [],
      attributionGaps: attributionGaps || [],
    });

    if (!result.success) {
      return fail(res, 400, 'VALIDATION_FAILED', result.error);
    }

    return ok(res, {
      assessment: result.assessment,
      validation: result.validation,
    }, 201);
  } catch (e) {
    return fail(res, 500, 'CREATE_FAILED', e.message);
  }
}

async function handleGetThreatActorAssessment(req, res, investigationId, actorId) {
  try {
    // New records use per-investigation keys. Legacy unscoped records may
    // be read ONLY when their stored investigation ID matches the caller's
    // authorized parent investigation; do not migrate or overwrite history.
    let data=await redis.hgetall(`actor:${investigationId}:${actorId}`);
    if(!Array.isArray(data) || data.length===0)
      data=await redis.hgetall(`actor:${actorId}`);
    if(!Array.isArray(data) || data.length===0)
      return fail(res,404,'NOT_FOUND','Actor assessment not found');
    const assessment={};
    for(let i=0;i<data.length;i+=2)assessment[data[i]]=data[i+1];
    if(assessment.investigationId!==investigationId ||
       assessment.actorId!==actorId)
      return fail(res,404,'NOT_FOUND','Actor assessment not found');
    return ok(res,{assessment});
  } catch (_) {
    return fail(res,503,'WORKBENCH_UNAVAILABLE','Assessment unavailable');
  }
}

async function handleCreateTechnicalAssessment(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, iocs, malwareFindings, techniques, infrastructure, detectionOpportunities } = body;

    if (!investigationId) {
      return fail(res, 400, 'MISSING_ID', 'investigationId required');
    }

    const result = await analysisMgr.createTechnicalAssessment(investigationId, {
      iocs: iocs || [],
      malwareFindings: malwareFindings || [],
      techniques: techniques || [],
      infrastructure: infrastructure || [],
      detectionOpportunities: detectionOpportunities || [],
    });

    if (!result.success) {
      return fail(res, 400, 'VALIDATION_FAILED', result.error);
    }

    return ok(res, {
      assessment: result.assessment,
      validation: result.validation,
    }, 201);
  } catch (e) {
    return fail(res, 500, 'CREATE_FAILED', e.message);
  }
}

async function handleGetTechnicalAssessment(req, res, id) {
  try {
    const key = `technical:${id}`;
    const data = await redis.hgetall(key);

    if (!data || data.length === 0) {
      return fail(res, 404, 'NOT_FOUND', `Technical assessment not found for: ${id}`);
    }

    const assessment = {};
    for (let i = 0; i < data.length; i += 2) {
      assessment[data[i]] = data[i + 1];
    }

    if (assessment.investigationId !== id)
      return fail(res, 404, 'NOT_FOUND', 'Assessment not found');
    return ok(res, { assessment });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleCreateExecutiveAssessment(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, businessImpact, operationalImpact, strategicImplications, recommendedActions, priorityLevel } = body;

    if (!investigationId) {
      return fail(res, 400, 'MISSING_ID', 'investigationId required');
    }

    const result = await analysisMgr.createExecutiveAssessment(investigationId, {
      businessImpact,
      operationalImpact,
      strategicImplications: strategicImplications || [],
      recommendedActions: recommendedActions || [],
      priorityLevel: priorityLevel || 'medium',
    });

    if (!result.success) {
      return fail(res, 400, 'VALIDATION_FAILED', result.error);
    }

    return ok(res, {
      assessment: result.assessment,
      validation: result.validation,
    }, 201);
  } catch (e) {
    return fail(res, 500, 'CREATE_FAILED', e.message);
  }
}

async function handleGetExecutiveAssessment(req, res, id) {
  try {
    const key = `executive:${id}`;
    const data = await redis.hgetall(key);

    if (!data || data.length === 0) {
      return fail(res, 404, 'NOT_FOUND', `Executive assessment not found for: ${id}`);
    }

    const assessment = {};
    for (let i = 0; i < data.length; i += 2) {
      assessment[data[i]] = data[i + 1];
    }

    if (assessment.investigationId !== id)
      return fail(res, 404, 'NOT_FOUND', 'Assessment not found');
    return ok(res, { assessment });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleGenerateGaps(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, investigation } = body;

    if (!investigationId || !investigation) {
      return fail(res, 400, 'MISSING_DATA', 'investigationId and investigation object required');
    }

    const result = await analysisMgr.generateInformationGaps(investigationId, investigation);

    return ok(res, result, 201);
  } catch (e) {
    return fail(res, 500, 'GAPS_FAILED', e.message);
  }
}
