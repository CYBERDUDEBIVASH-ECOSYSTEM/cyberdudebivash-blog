# SENTINEL APEX — SOC → Blogger CTI Production Delivery Runbook

**Classification:** P0 / customer-visible CTI delivery.  
**Status:** Operational release checklist, not evidence that a release has happened.  
**Scope:** \`CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog\`, \`soc.cyberdudebivash.in\`, \`blog.cyberdudebivash.in\`, \`cti.cyberdudebivash.in\`.

## Immutable production evidence chain

A single green GitHub workflow is **not** a complete customer-delivery receipt. Track the independent states and evidence below:

| State | Evidence required | Failure owner/action |
|---|---|---|
| SOURCE_GENERATED | Current \`main\` RSS, actual source report HTML, nonfabricated \`intel-state.json.lastReportGeneratedAt\` | SOC publisher: inspect source ingester and data quality |
| SOURCE_BUILD_VERIFIED | \`npm run build:cloudflare\`; predeploy feed and S2N parity; \`certify-soc-cti-source-handoff.cjs --predeploy\` | SOC build/release: repair source artifact before deploy |
| SOURCE_PUBLIC_VERIFIED | Both custom domains serve recent source reports with **200, text/html and SHA-256 exactly matching** \`dist-public\`; release SHA recorded | Cloudflare release owner: use approved deployment and rollback process |
| BLOGGER_AUTHORIZED | Explicit canary/source identity approval or separately reauthorized \`BLOGGER_OAUTH_READY=true\`; max 1–4 per bounded run | Operations owner: never bypass readiness and 16-hex source pin |
| BLOGGER_ACCEPTED | Blogger response contains live post ID/permalink; no ambiguous retry | Publisher: reconcile Blogger before any repeat attempt |
| BLOGGER_API_VERIFIED | Separate authenticated GET confirms exact certified dossier artifact | Publisher integrity gate: preserve receipt and flag discrepancy |
| BLOGGER_PUBLIC_VERIFIED | Independent permalink displays expected title; feed contains **same exact post ID** within bounded 30-entry window; state/ledger persisted | Delivery verifier: fail release without re-posting |
| SCHEDULE_CERTIFIED | Two or more consecutive scheduled freshness monitor runs PASS; customer-facing report/content age within published service threshold | SOC/CTI SRE: restore scheduling only after proof |

**Truthfulness contract:** an internal report timestamp never proves public delivery. A source citation is not independent corroboration. Never label stale/historical content LIVE. An AI-generated explanation does not establish confirmed exploitation, customer compromise, SOC 2 attestation or guaranteed service levels.

## Operator preflight — read-only

From a trusted shell with access to \`gh\` and an up-to-date local repository:

\`\`\`powershell
$Repo = 'CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog'
gh auth status
gh api "repos/$Repo/commits/main" --jq '.sha'
gh run list -R $Repo --workflow blogger-syndication.yml -L 5
gh run list -R $Repo --workflow cloudflare-production-deploy.yml -L 5
\`\`\`

Never paste token values, OAuth client secrets, release-signing secrets, billing attestations or raw customer data into chat, logs, PR descriptions or issues.

Read-only independent public inspection:

\`\`\`powershell
$Urls = @(
  'https://soc.cyberdudebivash.in/live-intel.json',
  'https://blog.cyberdudebivash.in/live-intel.json',
  'https://cti.cyberdudebivash.in/feeds/posts/default?alt=json&max-results=10'
)
foreach ($Url in $Urls) {
  try {
    $Result = Invoke-WebRequest -Uri $Url -SkipHttpErrorCheck -TimeoutSec 20 -ErrorAction Stop
    Write-Host "$($Result.StatusCode) $Url"
  } catch {
    Write-Host "FAIL $Url"
  }
}
\`\`\`

**Important:** this response-code probe is only diagnostic. Production GO requires report freshness and real content, exact asset bytes, per-post availability, paid-customer route acceptance, and the existing protected release gates. Do not print PASS unconditionally after a thrown PowerShell exception.

## Protected Cloudflare release procedure

Only after explicit owner approval for a **specific immutable 40-character current \`main\` SHA**, and fresh account-wide **zero-overage budget attestation**, use the existing manual release workflow. Do not change DNS, Cloudflare plan, R2/D1 resources, worker cron or production environment permissions merely to make a check green.

Required order:

1. Read exact \`main\` SHA and independently verify review/security CI.
2. Confirm actual SOC reports and RSS are fresh; the existing 180-minute gate checks source content, not just heartbeat.
3. Verify approved \`CDB_SOC_APPROVED_RELEASE_SHA\` matches operator input and current \`main\`; run npm dependency audit and existing customer-route/security/commercial checks.
4. Run \`npm run build:cloudflare\`, canonical feed/S2N predeploy parity, and \`node scripts/certify-soc-cti-source-handoff.cjs --predeploy\`.
5. Deploy ONLY through \`cloudflare-production-deploy.yml\` after production-environment approval; record previous known-good Worker version and rollback target.
6. Verify BOTH hostnames: root feed exact byte parity, S2N API parity, browser UI exact parity, **new source HTML dossier parity**, hostname mapping, customer/auth/payment journeys with no live charges.
7. If any postdeploy gate fails, status is **NO-GO**. Preserve failing evidence and execute the preapproved rollback procedure under operator authorization; never turn off a gate to obtain a green badge.

## One-post Blogger canary and scheduler reactivation

- First require the source URL to return 200 and match the expected content/canonical identity. The publication pipeline now rechecks actual first-party HTML delivery before any Blogger write.
- A manual canary requires \`dry_run=false\`, \`max_posts=1\`, \`live_canary_approved=true\`, and the reviewed exact HTTPS URL plus 16-hex source identity. This **publishes a public post**; use only after explicit approval.
- Validate Blogger API live receipt, exact artifact GET, public permalink title, public feed post ID and durable GitHub ledger.
- A failed public read-back **never** authorizes automatic re-post. Reconcile the original post ID and public visibility first; duplicate writes could harm customers, ranking and quota.
- Restore \`BLOGGER_OAUTH_READY=true\` only after at least two consecutive clean scheduled freshness checks, no outstanding P0 delivery issues and explicit owner authorization. Ensure default scheduled write count remains at most 4/run.
- Monitor provider errors, failed integrity gates, repeated 404s, age of last *real* report, Cloudflare source-to-edge report gap, successful/publicly verifiable publications and customer support escalations.
- If no new independently eligible intelligence exists, do not fabricate 4 posts to satisfy a volume goal. Alert on reduced service coverage instead.

## Severity, exit criteria and rollback

**P0:** public SOC report 404, stale customer-facing feed, broken paid API/checkout, Blogger auth failure, confirmed duplicate/silent publication, unverifiable published content. Hold release and/or publishing based on impact; preserve working CTI posts and customer data.

**P1:** recurring quality degradation, delayed feeds, incomplete detection artifacts, ambiguous labels, inconsistent report metadata. Quarantine affected dossiers and require evidence-backed review; do not issue unsupported IOCs or CVSS values.

**Exit criteria:** latest fresh real SOC source, exact public dual-host Cloudflare parity, public first-party HTML source, successful controlled Blogger post and API exact fetch-back, matching public permalink/feed ID, persisted ledger, consecutive clean scheduled monitor evidence, independent review of report factual/semantic quality, no open customer P0 issue, approved rollback path and cost attestations.

**Rollback boundary:** source code PRs may be reverted through reviewed commits. A successful live Blogger write must not be silently deleted or duplicated. A Cloudflare Worker release may be rolled back only to a known-good version by the authorized operator; a successful rollback must itself pass both customer host checks.

**Customer evidence package:** release SHA, Cloudflare Worker version, workflow run IDs, sample URL/HTTP status, public/expected digest comparison, publication post ID/permalink, post-generation UTC date, externally visible time, quality/classification report, subscription/payment checks, service-credit/escalation decision where contractually required. Never invent these records.
