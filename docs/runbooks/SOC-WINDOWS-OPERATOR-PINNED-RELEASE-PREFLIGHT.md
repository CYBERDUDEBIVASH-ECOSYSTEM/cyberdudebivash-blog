# SENTINEL APEX SOC — Windows operator release preflight (read-only)

**Status:** Live customer feed parity and managed SOC GA remain **NO-GO** until original production approvals are witnessed. This runbook does not initiate Cloudflare deployment or customer activation.

## 1. Make a pinned, reviewed release decision

Use **Windows PowerShell**, from `C:\\CDB\\repos\\cyberdudebivash-blog`. Verify the current GitHub PR reviews, exact source commit, production drift register, and existing Worker version in the Cloudflare dashboard. There are many changed paths since the last approved Worker version; do not treat this procedure as automatic approval of those changes.

```powershell
Set-Location 'C:\CDB\repos\cyberdudebivash-blog'
git fetch --prune origin main
if ($LASTEXITCODE -ne 0) { throw 'HOLD: unable to refresh origin/main' }
git status --short
git rev-parse HEAD
git rev-parse origin/main
```

If local `HEAD` is not identical to `origin/main`, or worktree has changes, stop. Review `main` and determine the immutable **40-character** commit SHA approved for release. No `git reset --hard`, force-push or automatic switch of branches.

### 1a. Safe alternative when the Windows development checkout has uncommitted changes

Do **not** `git reset --hard`, stash unreviewed work, delete untracked files,
or release directly from the dirty checkout. Create a **new isolated detached
worktree** from the exact fetched remote commit; retain the existing Windows
checkout and all its edits. From PowerShell 7:

```powershell
$ErrorActionPreference = 'Stop'
Set-Location 'C:\CDB\repos\cyberdudebivash-blog'
git fetch --prune origin main
if ($LASTEXITCODE -ne 0) { throw 'HOLD: cannot refresh origin/main' }
$ReleaseSha = (git rev-parse refs/remotes/origin/main).Trim()
if ($LASTEXITCODE -ne 0 -or $ReleaseSha -cnotmatch '^[0-9a-f]{40}

In authorized **local private operator environment** (not GitHub issues, PowerShell command history, CI logs, screenshots, or this chat) provide:

- `CLOUDFLARE_ACCOUNT_ID`: actual account ID.
- `CDB_CF_ACCOUNT_BUDGET_ATTESTATION`: owner-reviewed *JSON string* matching the account-wide gate, with a live snapshot from the last **two hours** covering every ecosystem Worker/Pages/D1/KV/R2/Queue/log workload, unmodeled services and the required 20% reserve. The template in `docs/runbooks/templates/CLOUDFLARE-ACCOUNT-WIDE-BUDGET.template.json` is intentionally invalid.
- `CDB_SOC_APPROVED_RELEASE_SHA`: the separately reviewed exact 40-character commit, **not** a guessed current `main`.

A snapshot passing today does not impose a physical Cloudflare spending hard cap. Enforce billing alarms and escalation separately. Avoid placing the JSON or account ID in shell command arguments or files within the repository.

## 3. Build and run preflight — NO deployment

```powershell
npm ci --legacy-peer-deps --ignore-scripts
if ($LASTEXITCODE -ne 0) { throw 'HOLD: locked install failed' }
npm run check:cloudflare
if ($LASTEXITCODE -ne 0) { throw 'HOLD: Cloudflare runtime check failed' }
npm run build:cloudflare
if ($LASTEXITCODE -ne 0) { throw 'HOLD: allowlisted asset build failed' }

node scripts/soc-operator-release-preflight.cjs
if ($LASTEXITCODE -ne 0) { throw 'HOLD: operator preflight rejected source, budget or pinned commit' }
```

## 3a. Independent immutable production approval (review-only addition)

The production workflow now requires **two matching owner-held approval values** before it may mutate the Worker:

- Configure `CDB_SOC_APPROVED_RELEASE_SHA` as an independently reviewed **protected production-environment GitHub Actions secret** (a 40-character immutable Git commit SHA). Do not print the secret, substitute `main`, or create an approval automatically.
- At **Actions → Cloudflare Production Deploy → Run workflow**, choose `main` and enter the same reviewed SHA into the required `approved_release_sha` input.
- The read-only gate compares that input and protected secret with `GITHUB_SHA`, checked-out `HEAD`, and the real `origin/main` SHA retrieved via `git ls-remote` from the official GitHub repository.
- The gate runs once before `npm ci` and again immediately before `wrangler deploy`. A publisher advancing `main` after approval causes **HOLD**; review a new immutable source revision rather than auto-updating the approved SHA.
- Confirm that the `production` environment has actual required reviewers and that main branch protections are enforced; merely declaring `environment: production` in YAML is not proof of configured approvals.

This closes one code-level provenance gap only. It does not authorize a deployment, certify Cloudflare account usage, replace the separate local preflight, or prove post-deploy customer acceptance.

A **PASS means only that this local offline source/build/budget metadata is consistent**. It does not verify that the Cloudflare attestation is authentic, the production Worker mapping is correct, the actual customer receives reports, or a managed SOC has a staffed service-level agreement.

## 4. Remaining operator-only live GO sequence

Under separate explicit production change authorization: confirm actual Cloudflare current Worker version/rollback target, read-only `scripts/verify-existing-cloudflare-domain.cjs` and DNS preconditions, independent native D1 migration/tenant safety, protected production environment approvals, then pinned Wrangler dry-run. Only after the approved Cloudflare account budget and unchanged custom domain are proved may the operator run the *existing, manually authorized release workflow*. Post-deployment certify BOTH `/live-intel.json` and `/api/intel/live.json` SHA-256 bytes on BOTH approved hostnames; document rollback rehearsal, customer alert canary receipt and legal/pilot owner signoff. Do not bypass the 180-minute genuinely generated report freshness limit with heartbeat changes.

**Never use this script to automatically deploy or label managed SOC customer onboarding GO.**
) {
    throw 'HOLD: remote main SHA unavailable'
}
$Root = 'C:\CDB\release-worktrees'
$Worktree = Join-Path $Root ('soc-' + $ReleaseSha.Substring(0,12))
if (Test-Path -LiteralPath $Worktree) {
    throw 'HOLD: target release worktree already exists; inspect it, do not overwrite'
}
New-Item -ItemType Directory -Force -Path $Root | Out-Null
git worktree add --detach "$Worktree" "$ReleaseSha"
if ($LASTEXITCODE -ne 0) { throw 'HOLD: isolated worktree creation failed' }
Set-Location -LiteralPath $Worktree
$Head = (git rev-parse HEAD).Trim()
$Remote = (git rev-parse refs/remotes/origin/main).Trim()
$Dirty = @(git status --porcelain=v1 --untracked-files=normal)
$Shallow = (git rev-parse --is-shallow-repository).Trim()
if ($Head -cne $ReleaseSha -or $Remote -cne $ReleaseSha -or
    $Dirty.Count -gt 0 -or $Shallow -cne 'false') {
    throw 'HOLD: isolated checkout is not clean, complete or pinned to current main'
}
Write-Host "READ_ONLY_REVIEWED_SOURCE_SHA=$ReleaseSha"
```

**This is a source-inspection/build workspace, not production authorization.**
Before approving a deployment, separately review the exact code changes against
the last certified release and re-fetch `origin/main`: the scheduled publisher
may advance `main` while tests or finance approval are underway. Do not
auto-update a protected approved release SHA. Production environment reviewers,
fresh account-wide usage evidence, exact Worker version/rollback identity and
all existing protected release checks remain mandatory.

The owner evidence workflow provides **two separate results**: a PREDEPLOY
source/budget/domain/version prerequisite verdict and an independently checked
CURRENT PUBLIC DELIVERY verdict. An unreleased October 23 public edge can make
the latter fail even when the former passes. The read-only audit will still exit
nonzero until public delivery is independently certified. **Do not treat a
predeploy PASS as permission to deploy or as a worldwide customer GO.**

## 2. Provide CURRENT private Cloudflare finance evidence

In authorized **local private operator environment** (not GitHub issues, PowerShell command history, CI logs, screenshots, or this chat) provide:

- `CLOUDFLARE_ACCOUNT_ID`: actual account ID.
- `CDB_CF_ACCOUNT_BUDGET_ATTESTATION`: owner-reviewed *JSON string* matching the account-wide gate, with a live snapshot from the last **two hours** covering every ecosystem Worker/Pages/D1/KV/R2/Queue/log workload, unmodeled services and the required 20% reserve. The template in `docs/runbooks/templates/CLOUDFLARE-ACCOUNT-WIDE-BUDGET.template.json` is intentionally invalid.
- `CDB_SOC_APPROVED_RELEASE_SHA`: the separately reviewed exact 40-character commit, **not** a guessed current `main`.

A snapshot passing today does not impose a physical Cloudflare spending hard cap. Enforce billing alarms and escalation separately. Avoid placing the JSON or account ID in shell command arguments or files within the repository.

## 3. Build and run preflight — NO deployment

```powershell
npm ci --legacy-peer-deps --ignore-scripts
if ($LASTEXITCODE -ne 0) { throw 'HOLD: locked install failed' }
npm run check:cloudflare
if ($LASTEXITCODE -ne 0) { throw 'HOLD: Cloudflare runtime check failed' }
npm run build:cloudflare
if ($LASTEXITCODE -ne 0) { throw 'HOLD: allowlisted asset build failed' }

node scripts/soc-operator-release-preflight.cjs
if ($LASTEXITCODE -ne 0) { throw 'HOLD: operator preflight rejected source, budget or pinned commit' }
```

## 3a. Independent immutable production approval (review-only addition)

The production workflow now requires **two matching owner-held approval values** before it may mutate the Worker:

- Configure `CDB_SOC_APPROVED_RELEASE_SHA` as an independently reviewed **protected production-environment GitHub Actions secret** (a 40-character immutable Git commit SHA). Do not print the secret, substitute `main`, or create an approval automatically.
- At **Actions → Cloudflare Production Deploy → Run workflow**, choose `main` and enter the same reviewed SHA into the required `approved_release_sha` input.
- The read-only gate compares that input and protected secret with `GITHUB_SHA`, checked-out `HEAD`, and the real `origin/main` SHA retrieved via `git ls-remote` from the official GitHub repository.
- The gate runs once before `npm ci` and again immediately before `wrangler deploy`. A publisher advancing `main` after approval causes **HOLD**; review a new immutable source revision rather than auto-updating the approved SHA.
- Confirm that the `production` environment has actual required reviewers and that main branch protections are enforced; merely declaring `environment: production` in YAML is not proof of configured approvals.

This closes one code-level provenance gap only. It does not authorize a deployment, certify Cloudflare account usage, replace the separate local preflight, or prove post-deploy customer acceptance.

A **PASS means only that this local offline source/build/budget metadata is consistent**. It does not verify that the Cloudflare attestation is authentic, the production Worker mapping is correct, the actual customer receives reports, or a managed SOC has a staffed service-level agreement.

## 4. Remaining operator-only live GO sequence

Under separate explicit production change authorization: confirm actual Cloudflare current Worker version/rollback target, read-only `scripts/verify-existing-cloudflare-domain.cjs` and DNS preconditions, independent native D1 migration/tenant safety, protected production environment approvals, then pinned Wrangler dry-run. Only after the approved Cloudflare account budget and unchanged custom domain are proved may the operator run the *existing, manually authorized release workflow*. Post-deployment certify BOTH `/live-intel.json` and `/api/intel/live.json` SHA-256 bytes on BOTH approved hostnames; document rollback rehearsal, customer alert canary receipt and legal/pilot owner signoff. Do not bypass the 180-minute genuinely generated report freshness limit with heartbeat changes.

**Never use this script to automatically deploy or label managed SOC customer onboarding GO.**
