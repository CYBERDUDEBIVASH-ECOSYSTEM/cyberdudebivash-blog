'use strict';
/**
 * Minimal AWS Signature Version 4 signer for Cloudflare R2's S3-compatible API.
 * Pure functions, no network, no dependencies, so it can be verified against
 * independent known-answer vectors (see tests-js/runtime-feed-publisher.test.js).
 * Never logs or returns secrets other than the derived signature.
 */
const crypto = require('node:crypto');

const sha256Hex = (data) => crypto.createHash('sha256').update(data).digest('hex');
const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
// RFC 3986 unreserved set, as SigV4 requires.
const uriEncode = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());

/** S3-style canonical URI: each path segment encoded once, '/' preserved. */
const canonicalUri = (path) => path.split('/').map(uriEncode).join('/');

function canonicalQuery(query) {
  return Object.keys(query || {}).sort()
    .map((k) => uriEncode(k) + '=' + uriEncode(String(query[k]))).join('&');
}

const amzDateOf = (date) => date.toISOString().replace(/[:-]|\.\d{3}/g, '');

/**
 * @param {{method:string, host:string, path:string, query?:object, headers?:object,
 *   payloadHash:string, accessKeyId:string, secretAccessKey:string,
 *   region?:string, service?:string, date?:Date}} o
 * @returns {{authorization:string, amzDate:string, signature:string, signedHeaders:string, headers:object}}
 */
function sign(o) {
  const region = o.region || 'auto';
  const service = o.service || 's3';
  const amzDate = amzDateOf(o.date || new Date());
  const day = amzDate.slice(0, 8);
  const headers = {};
  for (const [k, v] of Object.entries(o.headers || {})) headers[k.toLowerCase()] = String(v).trim().replace(/\s+/g, ' ');
  headers.host = o.host;
  headers['x-amz-date'] = amzDate;
  // S3/R2 require the payload hash as a signed header; generic SigV4 vectors do not.
  if (o.includeContentSha !== false) headers['x-amz-content-sha256'] = o.payloadHash;
  const names = Object.keys(headers).sort();
  const canonicalHeaders = names.map((n) => n + ':' + headers[n] + '\n').join('');
  const signedHeaders = names.join(';');
  const canonicalRequest = [
    o.method.toUpperCase(), canonicalUri(o.path), canonicalQuery(o.query),
    canonicalHeaders, signedHeaders, o.payloadHash,
  ].join('\n');
  const scope = [day, region, service, 'aws4_request'].join('/');
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256Hex(canonicalRequest)].join('\n');
  const kDate = hmac('AWS4' + o.secretAccessKey, day);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  const kSigning = hmac(kService, 'aws4_request');
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');
  const authorization = 'AWS4-HMAC-SHA256 Credential=' + o.accessKeyId + '/' + scope +
    ', SignedHeaders=' + signedHeaders + ', Signature=' + signature;
  return { authorization, amzDate, signature, signedHeaders, headers: { ...headers, authorization } };
}

module.exports = { sign, sha256Hex, uriEncode, canonicalUri, canonicalQuery, amzDateOf };
