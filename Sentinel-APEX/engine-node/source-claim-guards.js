'use strict';
// P0 source-to-claim boundary. News-outlet/source-category labels must not be
// promoted into verified affected technology or observed incident telemetry.
// Keep NON_VENDOR_LABELS aligned with api/_lib/intelligence-hub.js (tested).
const NON_VENDOR_LABELS = new Set([
  'securityweek', 'bleepingcomputer', 'the hacker news', 'darkreading',
  'seclists', 'sans isc', 'isc', 'krebsonsecurity', 'wired_security',
  'unit42', 'reddit_cyber', 'reddit_netsec', 'threat intelligence',
  'cyberdudebivash', 'cyberdudebivash sentinel apex',
]);
const RE_CVE = /^CVE-\d{4}-\d{4,}$/i;
function validCves(item) {
  if (!item || typeof item !== 'object') return [];
  const values = Array.isArray(item.cves) ? item.cves : [];
  const inferred = typeof item.id === 'string' && RE_CVE.test(item.id) ? [item.id] : [];
  return [...new Set([...values, ...inferred].filter(v => typeof v === 'string' && RE_CVE.test(v)))];
}
function verifiedAffectedTechnology(item) {
  if (!item || typeof item !== 'object' || validCves(item).length === 0) return null;
  const vendor = typeof item.vendor === 'string' ? item.vendor.trim() : '';
  const product = typeof item.product === 'string' ? item.product.trim() : '';
  if (!vendor || NON_VENDOR_LABELS.has(vendor.toLowerCase()) || /^reddit/i.test(vendor)) return null;
  const namedProduct = NON_VENDOR_LABELS.has(product.toLowerCase()) ? '' : product;
  return [vendor, namedProduct].filter(Boolean).join(' ');
}
function sourceDescribesConcreteEncryption(item) {
  const text = String(item?.desc || '');
  return /\b(?:encrypted|encrypting)\s+(?:files|data|systems)\b|\b(?:deleted|deleting)\s+(?:volume\s+)?shadow\s+cop(?:y|ies)\b|\bvssadmin\b/i.test(text);
}
module.exports = { NON_VENDOR_LABELS, validCves, verifiedAffectedTechnology, sourceDescribesConcreteEncryption };
