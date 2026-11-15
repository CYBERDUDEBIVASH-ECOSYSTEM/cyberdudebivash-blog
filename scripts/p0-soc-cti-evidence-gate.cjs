'use strict';
// Offline-first, read-only SOC/CTI P0 release evidence gate.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const MAX_BYTES = 8 * 1024 * 1024;
const FUTURE_SKEW_MS = 5 * 60 * 1000;
const REPORT_MAX_AGE_MS = 180 * 60 * 1000;
const RUNTIME_MAX_AGE_MS = 120 * 60 * 1000;
const HOSTS = ['https://soc.cyberdudebivash.in', 'https://blog.cyberdudebivash.in'];
const FEEDS = ['/live-intel.json', '/api/intel/live.json'];
function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function parseUtc(value, now) {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d/.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && parsed <= now + FUTURE_SKEW_MS ? parsed : null;
}
function assessSource(state, root, s2n, now = Date.now()) {
  const problems = [];
  const fail = code => { if (!problems.includes(code)) problems.push(code); };
  if (!state || !root || !s2n || typeof state !== 'object' || typeof root !== 'object' || typeof s2n !== 'object') {
    return { status: 'NOT_CERTIFIED', problems: ['MISSING_SOURCE_INPUT'] };
  }
  const report = parseUtc(state.lastReportGeneratedAt, now);
  const run = parseUtc(state.lastRun, now);
  const rootReceipt = parseUtc(root.metadata?.lastReportGeneratedAt, now);
  const s2nReceipt = parseUtc(s2n.lastReportGeneratedAt, now);
  if (!report || now - report > REPORT_MAX_AGE_MS) fail('GENUINE_REPORT_STALE_OR_INVALID');
  if (!run || now - run > RUNTIME_MAX_AGE_MS) fail('PUBLISHER_RUNTIME_STALE_OR_INVALID');
  if (!report || !rootReceipt || !s2nReceipt || report !== rootReceipt || report !== s2nReceipt)
    fail('GENUINE_RECEIPT_PARITY_FAILURE');
  const count = state.totalPublished;
  if (!Number.isSafeInteger(count) || count < 1 || root.totalPublished !== count || s2n.total_published !== count)
    fail('PUBLICATION_COUNT_PARITY_FAILURE');
  const ingestion = state.lastIngestion;
  if (!ingestion || !Number.isSafeInteger(ingestion.activeSources) || !Number.isSafeInteger(ingestion.totalSources) ||
      !Number.isSafeInteger(ingestion.fetchedRecords) || ingestion.totalSources < 1 ||
      ingestion.activeSources < 5 || ingestion.activeSources > ingestion.totalSources ||
      ingestion.fetchedRecords < ingestion.activeSources) fail('INGESTION_SOURCE_COVERAGE_NOT_CERTIFIED');
  if (!parseUtc(ingestion?.checkedAt, now) ||
      Math.abs(Date.parse(ingestion?.checkedAt || '') - (run || 0)) > 15 * 60 * 1000)
    fail('INGESTION_RECEIPT_TIME_INVALID');
  return { status: problems.length ? 'NOT_CERTIFIED' : 'SOURCE_CERTIFIED', problems,
    totalPublished: Number.isSafeInteger(count) ? count : null,
    lastGenuineReport: state.lastReportGeneratedAt || null,
    activeSources: Number.isSafeInteger(ingestion?.activeSources) ? ingestion.activeSources : null,
    configuredSources: Number.isSafeInteger(ingestion?.totalSources) ? ingestion.totalSources : null };
}
function checkHomepage(html) {
  if (typeof html !== 'string' || !html.includes('SENTINEL APEX')) return ['UNRECOGNIZED_HOMEPAGE'];
  const problems = [];
  if (/<h[1-6][^>]*>\s*Featured Reports\s*<\/h[1-6]>/i.test(html)) problems.push('HISTORICAL_STATIC_FEATURED_REPORTS');
  if (/\bclass=["'][^"']*\bfi-badge\b[^"']*\blive-badge\b[^"']*["'][^>]*>\s*(?:&#9679;|●)?\s*LIVE\s*<\/div>/i.test(html))
    problems.push('UNVERIFIED_STATIC_LIVE_BADGE');
  return problems;
}
function getFiles(base = process.cwd()) {
  const root = path.resolve(base);
  function readJson(file) {
    const location = path.join(root, file);
    const stat = fs.statSync(location);
    if (!stat.isFile() || stat.size < 1 || stat.size > MAX_BYTES) throw Error('SOURCE_FILE_SIZE_INVALID');
    const bytes = fs.readFileSync(location);
    return { value: JSON.parse(bytes.toString('utf8')), hash: sha256(bytes), bytes };
  }
  return {state:readJson('intel-state.json'), root:readJson('live-intel.json'), s2n:readJson('api/intel/live.json')};
}
async function getPublic(url, fetchFn = fetch) {
  try {
    const response = await fetchFn(url, {method:'GET',redirect:'manual',signal:AbortSignal.timeout(10000),headers:{'Accept':'application/json,text/html;q=0.8'}});
    if (response.status >= 300 && response.status < 400) return { status:'REDIRECT', httpStatus:response.status, location:response.headers.get('location') || null };
    if (response.status !== 200) return {status:'HTTP_FAILURE',httpStatus:response.status};
    const declared = Number(response.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > MAX_BYTES) return {status:'TOO_LARGE'};
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > MAX_BYTES) return {status:'TOO_LARGE'};
    return {status:'OK',httpStatus:200,bytes,hash:sha256(bytes)};
  } catch (_) { return {status:'UNREACHABLE'}; }
}
async function audit({base = process.cwd(), now = Date.now(), online = false, fetchFn = fetch} = {}) {
  let files, source;
  try { files = getFiles(base); source = assessSource(files.state.value, files.root.value, files.s2n.value, now); }
  catch (_) { return {status:'NOT_CERTIFIED',source:{status:'NOT_CERTIFIED',problems:['LOCAL_SOURCE_UNAVAILABLE']},public:[],mode:online?'online':'offline'}; }
  const result = {status:'NOT_CERTIFIED',mode:online?'online':'offline',source,public:[]};
  if (!online) return result;
  for (const host of HOSTS) {
    const homepage = await getPublic(host+'/',fetchFn);
    const problems = homepage.status==='OK' ? checkHomepage(homepage.bytes.toString('utf8')) : ['HOMEPAGE_'+homepage.status];
    result.public.push({host,kind:'homepage',status:problems.length?'NOT_CERTIFIED':'HTML_VERIFIED',problems});
    for (const suffix of FEEDS) {
      const published = await getPublic(host+suffix,fetchFn);
      const expected = suffix===FEEDS[0]?files.root:files.s2n;
      const code = published.status==='OK' && published.hash===expected.hash ? 'BYTE_PARITY_VERIFIED' : 'NOT_CERTIFIED';
      const problems = code==='BYTE_PARITY_VERIFIED'?[]:[published.status==='OK'?'EDGE_SOURCE_BYTES_MISMATCH':published.status];
      result.public.push({host,path:suffix,kind:'feed',status:code,problems});
    }
  }
  const blogger = await getPublic('https://cti.cyberdudebivash.in/feeds/posts/default?alt=rss',fetchFn);
  result.public.push({host:'cti.cyberdudebivash.in',kind:'blogger-feed',status:'NOT_CERTIFIED',
    problems:[blogger.status==='REDIRECT'?'BLOGGER_FEED_REDIRECT':blogger.status==='OK'?'BLOGGER_PUBLICATION_AGE_NOT_VERIFIED':blogger.status]});
  // Blogger recency requires authenticated provider publication receipts + public
  // item dates, not merely successful HTTP 200 or a file hash.
  return result;
}
if (require.main===module) {
  const args = process.argv.slice(2);
  if (args.length>1 || (args[0] && !['--offline','--online'].includes(args[0]))) {
    process.stderr.write('Usage: node scripts/p0-soc-cti-evidence-gate.cjs [--offline|--online]\n');
    process.exitCode=2;
  } else {
    audit({online:args[0]==='--online'}).then(value=>{
      process.stdout.write(JSON.stringify(value,null,2)+'\n');
      process.exitCode = value.source.status==='SOURCE_CERTIFIED' &&
        value.public.length>0 && value.public.every(p=>p.status==='BYTE_PARITY_VERIFIED'||p.status==='HTML_VERIFIED') ? 0 : 2;
    }).catch(()=>{process.stderr.write('P0 evidence gate could not complete\n');process.exitCode=2;});
  }
}
module.exports={assessSource,checkHomepage,getPublic,audit,parseUtc};
