# SOC + CTI P0 recovery when GitHub Actions is account-disabled

**Scope:** operator-run evidence and safe recovery preparation only. **No production
deploy, workflow dispatch, Blogger publish, secret modification, migration or paid
resource is authorized by this runbook.**

## Observed dependency

- Repository Actions history last recorded a run on **2026-11-14 08:46 UTC**,
  despite later main commits. The account-level UI says **GitHub Actions is
  currently disabled for your account** and the owner reports the dispatch API
  replies **Actions has been disabled for this user**.
- An account-level restriction is **not** repaired by changing workflow YAML or
  toggling repository Actions permissions. GitHub Support must review the case.
  Existing support cases: **#5007076** (primary), **#5007087** (related).
  Avoid filing duplicate tickets or exposing tokens in public issue comments.
- Blogger's prepublication frontend receipt-contract test regression was
  corrected in **merged PR #617**. There is no post-merge hosted run proving
  publication recovery.
- Source state last genuine report: **2026-11-14T08:45:41.360Z**; ingestion
  **4/35** nonempty sources, below the minimum of five. A merge is not a fresh
  report. **SOC and CTI customer GO remain NO-GO.**

## Zero-write source and edge diagnostic on Windows / PowerShell

Use the normal local repository, in a **separate detached worktree**, so current
main and any customer/incident changes remain untouched:

~~~powershell
Set-Location C:\CDB\repos\cyberdudebivash-blog
git status --short
git remote -v
git fetch origin fix/p0-soc-cti-offline-first-evidence-gate-20261115
git worktree add --detach C:\CDB\repos\soc-p0-evidence FETCH_HEAD
Set-Location C:\CDB\repos\soc-p0-evidence
node --version
node --test tests-js/p0-soc-cti-evidence-gate.test.js
node scripts/p0-soc-cti-evidence-gate.cjs --offline
node scripts/p0-soc-cti-evidence-gate.cjs --online
~~~

- Node.js **22+** is required. The unit suite must pass; the **live/offline
  evidence gate is expected to exit 2** while source is stale, unverified, or
  public edge is different. Do not hide this exit code or force PASS.
- Offline mode reads three local JSON files only. Online mode issues at most
  seven fixed-host read-only GET requests, no credentials; these can consume a
  negligible amount of an existing Cloudflare request budget, so check account
  headroom before running. Both modes print one JSON audit to stdout; the
  command does not create a persisted report or modify tracked files.
- The public CTI hostname may redirect its Blogger feed to the flagship intel
  site. This is NOT proof of a recent Blogger post; compare the **actual**
  canonical Blogger blog/public host and per-post links via provider-approved
  read-only fetch-back. Never mistake a successful homepage GET for a
  publication receipt.
- Neither a static homepage nor this diagnostic can certify authenticated
  customer API entitlements, live Cloudflare Worker SHA or source licensing.

## Separate full local publication preflight (NO PUBLISH)

From an isolated, **clean**, exact-main worktree with Python 3.11 dependencies
already installed and without setting Blogger secrets in a log:

~~~powershell
python --version
python -m pytest tests/ automation/tests/ --tb=short --timeout=30 -q
node --test tests-js/p0-soc-cti-evidence-gate.test.js
~~~

If a required package is missing, resolve the environment explicitly; do not
remove a failed test or add a metered provider. The merged #617 fixes the
specific stale two-argument test assertion. New failing tests are separate
blocking evidence until triaged.

## Guarded future recovery sequence (owner-only)

1. Obtain GitHub Support's actual account-level Actions reinstatement, or
   separately authorize an audited **manual local publisher** path with
   provider credentials in protected local environment variables.
2. Demonstrate **real upstream source coverage >=5/35**, a newly issued
   genuine report receipt, report-source/root-S2N parity and acceptable source
   use rights. Never fabricate or re-date reports, disable TLS or bypass
   a provider's commercial-use gate.
3. Pass full offline tests, content/report quality gates, TLP and provenance
   controls; reconcile the Blogger publication ledger and idempotent post IDs
   **before** sending any external post.
4. For a separately approved exact current SHA, execute at most the existing
   **1-4 post** controlled publisher, with free-provider ceilings and no new
   paid resources. Require a real provider write receipt, successful provider
   fetch-back, and accessible, correct public Blogger article URLs. Preserve
   state and recheck deduplication after interruption or a failed Git push.
5. For SOC Cloudflare, independently verify deployed Worker + Pages revisions,
   routes and bindings, secret/budget gates, rollback artifact and authorized
   immutable release SHA. Only then run a coordinated manual release followed
   by both-domain HTML/root/S2N/API parity and authenticated paid-customer checks.
6. Require at least two successful observed scheduled publication/freshness
   cycles after automation resumes. Do not close incidents **#433, #434 or
   #525** until their separate customer acceptance gates pass.

**Never run the full publisher on an unreviewed branch, with
\`ALLOW_PAID_LLM=true\`, or by reusing a published-but-uncommitted ledger
without reconciling provider receipts first.**
