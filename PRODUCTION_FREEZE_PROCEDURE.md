# SENTINEL APEX SOC — P0 protected release freeze (current procedure)

**Scope:** \`CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog\`,
Cloudflare Worker \`cyberdudebivash-blog\`, existing Custom Domains
\`soc.cyberdudebivash.in\` and \`blog.cyberdudebivash.in\`.

**Status: OPERATOR PROCEDURE, NOT AN EXECUTED RELEASE.**
Freezing, dispatching, deploying, changing secrets or rolling back production
requires the authorized operator's separate approval and current private
Cloudflare account-wide zero-additional-metered-cost attestation. Never
treat this document or an automated monitor as permission to do those things.

## P0 customer incident and reason for a bounded freeze

The deployed static /live-intel.json and /api/intel/live.json plus the
Worker-bundled public /api/v1/intel?action=stats were independently verified
serving October 23, 2026 snapshots while GitHub had November 23 source data.
The front-end uses the correctly configured same-origin /live-intel.json.
Both data assets and API JSON are **compiled into the Worker release**;
a successful GitHub publisher commit does NOT update the deployed Worker.
See [customer incident #433](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog/issues/433).

The existing \`.github/workflows/cloudflare-production-deploy.yml\` is
**operator-dispatched on main only**; push events deliberately SKIP. Its
\`soc-cloudflare-release-sha-gate.cjs\` requires five SHA values (owner's
protected approval, manual input, GitHub run SHA, checked-out HEAD and
**current remote main**) to match both before the build and just before
Wrangler. Meanwhile, scheduled content writers push new commits roughly
every 30 minutes. If main advances during human approval/build, the
deployment correctly **fails closed**. A short coordinated writer pause is
the current supported remedy; do not loosen this gate to accept a
different or unreviewed commit.

## 1. Current content-writer inventory (verify against main before use)

The **five** workflows below are capable of changing Git \`main\` via
explicit push steps or \`scripts/publish-intelligence-hub.sh\`.
They are the *only* candidates for an operator-approved temporary pause:

| Workflow in the current organization | Current schedule (UTC) | Git writer |
|---|---|---|
| [sentinel-apex.yml](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog/actions/workflows/sentinel-apex.yml) | :03 and :33 each hour | Yes, main intelligence publisher |
| [blogger-syndication.yml](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog/actions/workflows/blogger-syndication.yml) | :17 each hour | Yes, publication receipts; also affects CTI Blogger delivery |
| [ai-security-intel.yml](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog/actions/workflows/ai-security-intel.yml) | :07 every two hours | Yes, AI intelligence state |
| [cve-pages.yml](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog/actions/workflows/cve-pages.yml) | :19 every six hours | Yes, CVE pages and sitemap |
| [intelligence-hub.yml](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog/actions/workflows/intelligence-hub.yml) | :47 every six hours | Yes, via \`scripts/publish-intelligence-hub.sh\` |

**Do not disable**
[generate-rss.yml](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog/actions/workflows/generate-rss.yml):
it is now a **read-only RSS source-truth validator**, with
\`permissions: contents: read\`, no schedule, no commit, and no push.
The older six-workflow inventory is obsolete. Do not pause security-audit,
backup, customer alert, pipeline-integrity or emergency recovery workflows.
Check for any newly introduced Git writer before executing a future freeze.

## 2. Preconditions — HOLD if missing

1. Authorize the temporary interruption of the five writers,
   especially the **customer-facing Blogger publication workflow**.
   Confirm responsible owner, start time, exit/abort trigger and rollback.
2. Review the **entire** current code/config/binding/asset diff from the
   last approved production version: drift monitor #45109616989 noted
   259 operational/release-control paths. GitHub Compare's first 300
   returned file rows are **not** an exhaustive inventory.
3. Verify the existing Worker deployment version and rollback target
   privately from Cloudflare; inspect both approved Custom Domain mappings.
4. Verify a fresh (no more than two hours old), **all-platform** Cloudflare
   account usage/cost attestation proving **zero additional metered charges**
   with the required 20% reserve. **Do not** raise plan limits or add
   paid workers, R2, KV, D1, API gateways or queues.
5. Validate source publication receipt/ledger and generated build bytes,
   dependency security, customer entitlement/tenant controls, safe
   backup/rollback and release owner sign-off. Do not replace historical
   data with synthetic fresh timestamps or unlicensed source feeds.
6. Distinguish **degraded-service restoration** from **commercial managed-SOC
   GA certification**. The five-active-source rule in
   \`scripts/p0-soc-cti-evidence-gate.cjs\` remains required for commercial
   acceptance; it is NOT directly invoked by the protected Worker deployment
   workflow. Never claim GA readiness from a merely fresh build.

## 3. Operator-approved pause, drain, release and restore

Use the *current* repository, not the retired
\`cyberdudebivash-pvt-ltd/cyberdudebivash-blog\` path. A freeze is a
**temporary manual GitHub Actions toggle**, not a YAML edit or commit.
Do not execute these commands or disable anything without owner approval.

\`\`\`powershell
$Repo = "CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog"
$Writers = @(
  "sentinel-apex.yml",
  "blogger-syndication.yml",
  "ai-security-intel.yml",
  "cve-pages.yml",
  "intelligence-hub.yml"
)
gh auth status
# Explicit operator approval is required before any write action below.
# Once approved: pause ONLY the listed writer workflows via Actions UI,
# or equivalent authenticated gh workflow disable calls.
# Then inspect queued/running writes; a disabled workflow may already be running.
foreach ($Workflow in $Writers) {
  gh run list --repo $Repo --workflow $Workflow --limit 5
}
# After every writer is disabled AND every in-flight writing run is drained:
$FreezeSha = (gh api "repos/$Repo/git/ref/heads/main" --jq ".object.sha").Trim()
if ($FreezeSha -notmatch "^[0-9a-f]{40}$") { throw "Invalid freeze SHA" }
Write-Host "REVIEW_CANDIDATE_SHA=$FreezeSha"
\`\`\`

**Before** a manual release, re-read the exact remote main SHA after the
drain window, confirm it is unchanged, and confirm the private protected
\`CDB_SOC_APPROVED_RELEASE_SHA\` is independently authorized for that **exact**
commit. The workflow itself also revalidates this just before Wrangler.

After all protected checks, budget attestation and production-environment
approval have been satisfied by the owner, the intended **existing**
release action is:

\`\`\`powershell
# MUTATING PRODUCTION OPERATION — owner approval required.
gh workflow run cloudflare-production-deploy.yml --repo $Repo --ref main -f "approved_release_sha=$FreezeSha"
\`\`\`

The workflow must be allowed to HOLD if its dependency security,
source/asset, Cloudflare budget, native binding, DNS precondition or
SHA checks fail. Never bypass a failed check or run a direct unreviewed
\`wrangler deploy\`. No DNS cutover, record creation or legacy origin
migration is part of this recovery: both Custom Domains already exist.

**Deadline:** the genuine report source/receipt and budget attestation
expire independently (180-minute feed bound, 2-hour budget evidence).
If the freeze would exceed these bounds, abort rather than change the
timestamps. Do not pretend a 15-minute turnaround is guaranteed for a
259-path security review. Resume writers promptly on either success or
abort, and record the reason and incident status.

## 4. Postdeployment customer acceptance (mandatory)

On the exact approved build and recorded Worker version, execute the
already-wired postdeployment checks:

\`\`\`powershell
node scripts/certify-soc-public-feed-parity.cjs --release-asset
node scripts/certify-soc-s2n-api-release.cjs --release-asset
node scripts/certify-soc-dual-host-ui-release.cjs
node scripts/certify-soc-cti-source-handoff.cjs --release-asset
\`\`\`

All four public feed endpoints must expose the **approved exact built
bytes**, not merely equal cumulative counts or timestamps:

- \`https://soc.cyberdudebivash.in/live-intel.json\`
- \`https://blog.cyberdudebivash.in/live-intel.json\`
- \`https://soc.cyberdudebivash.in/api/intel/live.json\`
- \`https://blog.cyberdudebivash.in/api/intel/live.json\`

Verify \`/api/v1/intel?action=stats\` returns no archived-intel-as-live
claims and that the customer dashboard withholds historical records from
operational metrics. Accept a current, genuine but **degraded** service
only with correct disclosure; this is not managed-SOC GA. Record
entitlement, tenant isolation, customer alert receipts, backup/restore
and performance canary results separately. If deployed bytes, auth or
payment regress, **roll back to the previously verified Worker version**
under the operator's approved rollback process.

## 5. Mandatory resume / abort cleanup

Whether deployment succeeds, fails, is canceled or times out:

1. Re-enable the **same five** paused writer workflows in the current
   GitHub organization, unless the operator specifically authorizes a
   continued short HOLD to investigate a newly confirmed write-integrity
   incident.
2. Verify each writer's status and the next normal scheduled run;
   check for duplicate commits, retries or publication regressions.
3. Re-check the four public endpoints and current Worker version after
   the publisher resumes. Because the deployed Worker currently bakes
   feeds into its assets/bundle, **future publisher commits alone will
   not keep customer feeds fresh**. This release is a bounded recovery,
   not a continuous-delivery architecture fix.
4. Keep incident #433 OPEN until live delivery and customer acceptance
   actually pass. A longer-term, cost-certified continuously refreshed
   feed architecture needs separate approval and tests.

**Safety invariant:** this procedure does **not** deploy, pause
workflows, change GitHub secrets, mutate Cloudflare/DNS, change payments,
delete archives or assert customer revenue. It is a reviewable
operator-controlled plan with an abort and a restoration path.
