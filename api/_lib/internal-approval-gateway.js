'use strict';

/**
 * P0 internal SOC approval control-plane security boundary.
 * This is for privileged analyst/editorial workflows only, NOT customer
 * entitlement, multi-tenant authorization or a substitute for MFA/OIDC.
 * No network, storage, or billing calls occur before identity verification.
 */
const {requireAnalyst}=require('./analyst-auth');

const MAX_BODY_BYTES=65536;
const MAX_LIMIT=50;
const LEAD=new Set(['lead_analyst','soc_admin']);
const APPROVAL_ROLES=Object.freeze({
  MANAGER:new Set(['lead_analyst','soc_admin']),
  EXECUTIVE:new Set(['executive']),
  LEGAL:new Set(['legal']),
  COMPLIANCE:new Set(['compliance']),
});

function headers(res) {
  for(const [name,value] of Object.entries({
    'Cache-Control':'no-store, no-cache, must-revalidate',
    'X-Content-Type-Options':'nosniff',
    'X-Frame-Options':'DENY',
    'Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",
    'Strict-Transport-Security':'max-age=63072000; includeSubDomains; preload',
    'Referrer-Policy':'no-referrer',
    'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
    'Access-Control-Allow-Methods':'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers':'Content-Type, X-Analyst-Key',
  })) res.setHeader(name,value);
  // The common legacy security helper deliberately sets CORS '*'.
  // This gateway must never use it or add wildcard browser access.
}
function fail(res,status,code) {
  return res.status(status).json({success:false,error:{code,message:code},
    meta:{timestamp:new Date().toISOString()}});
}
function validActor(caller) {
  return caller && typeof caller.id==='string' && /^[A-Za-z0-9_.-]{1,100}$/.test(caller.id) &&
    typeof caller.role==='string' && /^[a-z_]{2,32}$/.test(caller.role);
}
function bodyObject(req,res) {
  const ct=String((req.headers||{})['content-type']||'').toLowerCase();
  if(ct && !/^application\/json(?:\s*;|$)/.test(ct)) {
    fail(res,415,'UNSUPPORTED_MEDIA_TYPE'); return null;
  }
  const stated=(req.headers||{})['content-length'];
  if(stated!==undefined && (!/^\d+$/.test(String(stated)) ||
      Number(stated)>MAX_BODY_BYTES)) {
    fail(res,413,'PAYLOAD_TOO_LARGE');return null;
  }
  let body=req.body;
  try {
    if(typeof body==='string') {
      if(Buffer.byteLength(body,'utf8')>MAX_BODY_BYTES) {
        fail(res,413,'PAYLOAD_TOO_LARGE');return null;
      }
      body=JSON.parse(body);
    } else if(Buffer.byteLength(JSON.stringify(body??{}),'utf8')>MAX_BODY_BYTES) {
      fail(res,413,'PAYLOAD_TOO_LARGE');return null;
    }
  } catch (_) {fail(res,400,'INVALID_JSON');return null;}
  if(!body||typeof body!=='object'||Array.isArray(body)) {
    fail(res,400,'INVALID_BODY');return null;
  }
  return body;
}
function authorizeAction(kind,action,caller,body) {
  if(kind==='products') {
    if(action==='approve') {
      const level=body && body.approvalLevel;
      if(typeof level!=='string'||!Object.hasOwn(APPROVAL_ROLES,level)) return false;
      return APPROVAL_ROLES[level].has(caller.role);
    }
    if(action==='reject')return LEAD.has(caller.role);
  }
  if(kind==='quality') {
    if(action==='approve')return LEAD.has(caller.role);
    if(action==='executive-approval')return caller.role==='executive';
  }
  return true; // Other actions are still authenticated analyst-only.
}
function createInternalApprovalGateway(legacyHandler,{kind,requireAnalystFn=requireAnalyst}={}) {
  if(typeof legacyHandler!=='function' || !['quality','products'].includes(kind) ||
      typeof requireAnalystFn!=='function')throw new TypeError('Invalid internal approval gateway');
  const prefix=kind==='quality'?'/api/v1/quality':'/api/v1/products/approvals';
  return async function protectedApproval(req,res) {
    headers(res);
    if(req.method==='OPTIONS')return res.status(204).end();
    if(!['GET','POST'].includes(req.method))return fail(res,405,'METHOD_NOT_ALLOWED');

    const pathname=String(req.url||'').split('?')[0].replace(/\/$/,'');
    if(pathname!==prefix && !pathname.startsWith(prefix+'/'))
      return fail(res,404,'NOT_FOUND');
    if(pathname.length>512)return fail(res,414,'URI_TOO_LONG');
    const parts=pathname.slice(prefix.length).split('/').filter(Boolean);
    const action=parts[parts.length-1]||'';
    // No control-plane data or writes before authenticated principal check.
    const caller=await requireAnalystFn(req,res,fail);
    if(!caller)return;
    if(!validActor(caller))return fail(res,403,'FORBIDDEN');
    let body={};
    if(req.method==='POST') {
      body=bodyObject(req,res);
      if(body===null)return;
      if(!authorizeAction(kind,action,caller,body))
        return fail(res,403,'INSUFFICIENT_APPROVAL_ROLE');
      // Identity and authority MUST come from the already verified principal.
      body={...body,analyst:caller.id,submitter:caller.id,reviewer:caller.id,
        approver:caller.id,publisher:caller.id,role:caller.role};
      req.body=body;
    }
    if(req.query && req.query.limit!==undefined) {
      const value=String(req.query.limit);
      if(!/^[1-9][0-9]?$/.test(value)||Number(value)>MAX_LIMIT)
        return fail(res,400,'INVALID_LIMIT');
    }
    req.verifiedAnalyst=caller;
    return legacyHandler(req,res);
  };
}

module.exports={createInternalApprovalGateway,authorizeAction,MAX_BODY_BYTES,MAX_LIMIT};
