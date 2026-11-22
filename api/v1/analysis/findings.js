'use strict';

const redis = require('../../_lib/redis');
const { AnalysisManager } = require('../../_lib/analysis-manager');
const { InvestigationManager } = require('../../_lib/investigation-manager');
const { requireAnalyst } = require('../../_lib/analyst-auth');
const { isValidObjectId, canAccessInvestigation, isInternalLead } = require('../../_lib/workbench-object-scope');

const analysisMgr = new AnalysisManager(redis);
const investigationMgr = new InvestigationManager(redis);
const MAX_BODY_BYTES = 65536;

const CORS_HEADERS = {
  // Internal analyst data cannot be read by cross-origin applications.
  'Cache-Control': 'no-store, no-cache, must-revalidate',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Analyst-Key',
};

// The shared legacy applySecurityHeaders() sets Access-Control-Allow-Origin:*.
 // This private endpoint MUST NOT call it; Worker router adds its own
 // baseline for dynamic responses, and Vercel needs the same local policy.
function applyInternalHeaders(res) {
  const policy = {
    'X-Content-Type-Options':'nosniff',
    'X-Frame-Options':'DENY',
    'Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",
    'Strict-Transport-Security':'max-age=63072000; includeSubDomains; preload',
    'Referrer-Policy':'no-referrer',
    'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
    'Cache-Control':'no-store, no-cache, must-revalidate',
  };
  Object.entries(policy).forEach(([k,v])=>res.setHeader(k,v));
}
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

// Ownership must be revalidated on EVERY request, never inferred from a
// caller-controlled investigationId or a browser-supplied analyst name.
// These are internal-operator scopes, not a substitute for customer tenant RBAC.
async function requireInvestigationScope(res, caller, investigationId) {
  if (!isValidObjectId(investigationId)) {
    fail(res, 404, 'NOT_FOUND', 'Investigation not found');
    return false;
  }
  try {
    const investigation = await investigationMgr.getInvestigation(investigationId);
    if (!investigation || investigation.id !== investigationId ||
        !canAccessInvestigation(caller, investigation)) {
      fail(res, 404, 'NOT_FOUND', 'Investigation not found');
      return false;
    }
    return true;
  } catch (_) {
    fail(res, 503, 'WORKBENCH_UNAVAILABLE', 'Investigation authority unavailable');
    return false;
  }
}
async function requireFindingScope(res, caller, findingId) {
  if (!isValidObjectId(findingId)) {
    fail(res, 404, 'NOT_FOUND', 'Finding not found');
    return false;
  }
  let finding;
  try { finding = await analysisMgr.getFinding(findingId); }
  catch (_) {
    fail(res, 503, 'WORKBENCH_UNAVAILABLE', 'Finding authority unavailable');
    return false;
  }
  if (!finding || finding.id !== findingId ||
      !isValidObjectId(finding.investigationId)) {
    fail(res, 404, 'NOT_FOUND', 'Finding not found');
    return false;
  }
  return requireInvestigationScope(res, caller, finding.investigationId);
}
module.exports = async (req, res) => {
  applyInternalHeaders(res);
  if (req.method === 'OPTIONS') {
    Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
    return res.status(204).end();
  }
  if (!['GET','POST','PUT'].includes(req.method))
    return fail(res, 405, 'METHOD_NOT_ALLOWED', 'Unsupported method');

  // The legacy global request guard does not support PUT; preserve review
  // semantics while bounding request size and accepting JSON only.
  if (req.method === 'POST' || req.method === 'PUT') {
    const headers = req.headers || {};
    const ct = String(headers['content-type'] || '').toLowerCase();
    if (ct && !/^application\/json(?:\s*;|$)/.test(ct))
      return fail(res, 415, 'UNSUPPORTED_MEDIA_TYPE', 'JSON required');
    const declared = Number(headers['content-length'] || 0);
    if (!Number.isFinite(declared) || declared < 0 || declared > MAX_BODY_BYTES)
      return fail(res, 413, 'PAYLOAD_TOO_LARGE', 'Request body too large');
    try {
      const bytes = Buffer.byteLength(
        typeof req.body === 'string' ? req.body : JSON.stringify(req.body || {}),'utf8');
      if (bytes > MAX_BODY_BYTES)
        return fail(res, 413, 'PAYLOAD_TOO_LARGE', 'Request body too large');
    } catch (_) { return fail(res, 400, 'INVALID_JSON', 'Invalid request body'); }
  }

  const caller = await requireAnalyst(req, res, fail);
  if (!caller) return;
  req.verifiedAnalyst = caller;
  const pathname = String(req.url || '').split('?')[0].replace(/\/$/, '');
  const prefix = '/api/v1/analysis/findings';
  const parts = pathname.startsWith(prefix + '/') ?
    pathname.slice(prefix.length + 1).split('/') : [];

  if (pathname === prefix && req.method === 'POST') {
    let body = req.body;
    try { if (typeof body === 'string') body = JSON.parse(body); }
    catch (_) { return fail(res, 400, 'INVALID_JSON', 'Invalid request body'); }
    if (!body || typeof body !== 'object' || Array.isArray(body))
      return fail(res, 400, 'INVALID_JSON', 'JSON object required');
    if (!await requireInvestigationScope(res, caller, body.investigationId)) return;
    req.body = body;
    return handleCreateFinding(req, res);
  }
  if (pathname === prefix && req.method === 'GET') {
    const query = req.query || {};
    const rawLimit = query.limit === undefined ? '50' : String(query.limit);
    if (!/^[1-9][0-9]?$/.test(rawLimit) || Number(rawLimit)>50)
      return fail(res, 400, 'INVALID_LIMIT', 'Invalid result limit');
    if (query.status !== undefined &&
        (typeof query.status!=='string' || !/^[a-z_]{1,30}$/.test(query.status)))
      return fail(res, 400, 'INVALID_STATUS', 'Invalid finding status');
    if (!await requireInvestigationScope(res, caller, query.investigationId)) return;
    req.query = {...query, limit:rawLimit};
    return handleListFindings(req, res);
  }
  if (parts.length === 1 && req.method === 'GET') {
    if (!await requireFindingScope(res, caller, parts[0])) return;
    return handleGetFinding(req, res, parts[0]);
  }
  if (parts.length === 2 && parts[1] === 'report' && req.method === 'GET') {
    if (!await requireInvestigationScope(res, caller, parts[0])) return;
    return handleGetAnalysisReport(req, res, parts[0]);
  }
  if (parts.length === 2 && req.method === 'PUT' &&
      ['review','publish'].includes(parts[1])) {
    if (!await requireFindingScope(res, caller, parts[0])) return;
    if (parts[1] === 'publish') {
      if (!isInternalLead(caller))
        return fail(res, 403, 'FORBIDDEN', 'Lead approval required');
      return handlePublishFinding(req, res, parts[0], caller);
    }
    return handleReviewFinding(req, res, parts[0], caller);
  }
  return fail(res, 404, 'NOT_FOUND', 'Endpoint not found');
};

async function handleCreateFinding(req, res) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { investigationId, statement, confidence, evidence, reasoning, assumptions, limitations, alternativeHypotheses, tags, type } = body;

    if (!investigationId || !statement) {
      return fail(res, 400, 'MISSING_FIELD', 'investigationId and statement required');
    }

    const result = await analysisMgr.createAnalyticalFinding(investigationId, {
      statement,
      type: type || 'technical',
      confidence: confidence || 'possible',
      evidence: evidence || [],
      reasoning: reasoning || '',
      assumptions: assumptions || [],
      limitations: limitations || [],
      alternativeHypotheses: alternativeHypotheses || [],
      tags: tags || [],
    });

    if (!result.success) {
      return fail(res, 400, 'VALIDATION_FAILED', result.error);
    }

    return ok(res, {
      finding: result.finding,
      validation: result.validation,
      scoring: result.scoring,
    }, 201);
  } catch (e) {
    return fail(res, 500, 'CREATE_FAILED', e.message);
  }
}

async function handleListFindings(req, res) {
  try {
    const investigationId = req.query.investigationId;
    const status = req.query.status;
    const limit = parseInt(req.query.limit || '50', 10);

    if (!investigationId) {
      return fail(res, 400, 'MISSING_ID', 'investigationId required');
    }

    const findings = await analysisMgr.getInvestigationFindings(investigationId, limit);

    let filtered = findings;
    if (status) {
      filtered = findings.filter(f => f.status === status);
    }

    return ok(res, {
      investigationId,
      findings: filtered,
      count: filtered.length,
      totalCount: findings.length,
    });
  } catch (e) {
    return fail(res, 500, 'LIST_FAILED', e.message);
  }
}

async function handleGetFinding(req, res, id) {
  try {
    const finding = await analysisMgr.getFinding(id);
    if (!finding) {
      return fail(res, 404, 'NOT_FOUND', `Finding not found: ${id}`);
    }

    return ok(res, { finding });
  } catch (e) {
    return fail(res, 500, 'GET_FAILED', e.message);
  }
}

async function handleReviewFinding(req, res, id, caller) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    const { approved, feedback } = body;
    const result = await analysisMgr.reviewFinding(id, caller.id, approved === true, feedback || '');

    return ok(res, result);
  } catch (e) {
    return fail(res, 500, 'REVIEW_FAILED', e.message);
  }
}

async function handlePublishFinding(req, res, id, caller) {
  try {
    let body = {};
    if (req.body) {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    }

    // Signed-in lead identity is authoritative; browser publisher is ignored.
    const result = await analysisMgr.publishFinding(id, caller.id);

    if (!result.success) {
      return fail(res, 400, 'PUBLISH_FAILED', result.error);
    }

    return ok(res, result);
  } catch (e) {
    return fail(res, 500, 'PUBLISH_FAILED', e.message);
  }
}

async function handleGetAnalysisReport(req, res, id) {
  try {
    const report = await analysisMgr.getAnalysisReport(id);

    return ok(res, { report });
  } catch (e) {
    return fail(res, 500, 'REPORT_FAILED', e.message);
  }
}
