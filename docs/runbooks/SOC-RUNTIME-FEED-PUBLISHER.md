# SOC runtime feed publisher: owner setup, verification and rollback

Part of "Option A" (`docs/operations/SOC-RUNTIME-FEED-OPTION-A.md`). Nothing here runs until you complete step 4 and set `SOC_RUNTIME_FEED_ENABLED=true`. **All steps are owner-only** (they need your Cloudflare and GitHub credentials). Commands are PowerShell; `gh` must be authenticated as an owner.

## What it does
`.github/workflows/soc-runtime-feed-publisher.yml` runs `scripts/publish-runtime-feed.cjs` on every push that touches the feeds or `posts/**`, plus every 30 minutes as a safety net. It publishes `live-intel.json`, `api/intel/live.json`, `rss.xml` and recently added dossiers to a **dedicated R2 bucket** under `runtime/v1/`, **after applying the same public-build transforms the Cloudflare build applies** (CVSS corrections, RSS origin rewrite, HTML transforms), so the runtime bytes equal what the static build would serve. A file the build rejects is skipped and shown as `FEED_TRANSFORM_FAILED:` / `DOSSIER_TRANSFORM_FAILED:` in `failed[]` (exit 2); fix the source file, the next run publishes it. It is read-only toward git (it cannot move `main`, so it cannot disturb a SHA-pinned release) and never holds the Cloudflare deploy token.

## Hard cost controls (September's overage was 3M R2 Class A operations)
* Unchanged feeds (sha256) and dossiers (MD5 vs one LIST) are **not** re-uploaded; a feed is never overwritten by an older one.
* `--max-puts 400` per run and `--daily-cap 3000` Class A operations per UTC day (persisted in `runtime/v1/_counters/`), counting **every attempt including retries**. The persisted total never exceeds the cap (tested, including all-writes-fail).
* Typical load ≈ 300 writes/day (≈ 9k/month, 0.9% of the 1M included).

## 1. Create the bucket (not the premium one)
```powershell
$env:CLOUDFLARE_API_TOKEN = '<a token that may create R2 buckets; do not echo>'
npx wrangler r2 bucket create soc-runtime-feed
```
The name must **not** contain `premium`: the script refuses it, and `PREMIUM_REPORTS` holds paid artifacts.

## 2. Create a bucket-scoped token (least privilege)
Cloudflare dashboard → **R2** → **Manage API tokens** → **Create API token** → permission **Object Read & Write** → **Specify bucket(s): `soc-runtime-feed` only** → create. Copy the **Access Key ID** and **Secret Access Key** (shown once). This token cannot touch `PREMIUM_REPORTS` or any other bucket.

## 3. Add the GitHub secrets and variables (values are prompted, never put on the command line)
```powershell
$R = 'CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog'
gh secret set SOC_RUNTIME_FEED_R2_ACCESS_KEY_ID     -R $R
gh secret set SOC_RUNTIME_FEED_R2_SECRET_ACCESS_KEY -R $R
gh variable set SOC_RUNTIME_FEED_BUCKET --body soc-runtime-feed -R $R
```
`CLOUDFLARE_ACCOUNT_ID` already exists and is reused (an account id is an identifier, not a credential).

## 4. Verify before enabling anything (each step is safe and reversible)
The workflow is skipped while the master switch is off, so turn it on only for the verification, then watch the first runs:
```powershell
gh variable set SOC_RUNTIME_FEED_ENABLED --body true -R $R
gh workflow run soc-runtime-feed-publisher.yml -R $R --ref main -f check_only=true   # one signed read-only request
gh run list -R $R --workflow soc-runtime-feed-publisher.yml --limit 1                # expect success, "R2_AUTH_OK" in the log
gh workflow run soc-runtime-feed-publisher.yml -R $R --ref main -f dry_run=true      # plans only, no writes
gh workflow run soc-runtime-feed-publisher.yml -R $R --ref main -f dry_run=false     # first real upload
```
Expected log line of a real run: one JSON object with `putCount`, `failed: []`, `classAOps` and `dailyOpsUsed`. A first run uploads the 3 feeds and the dossiers from the last 12 commits (use `-f since_commits=100` once to backfill more).

Until the Worker binding exists (PR-4), **uploading is harmless**: nothing reads the bucket, so the public site is unchanged.

## 5. Recommended: bound the storage
Cloudflare dashboard → bucket `soc-runtime-feed` → **Settings** → **Object lifecycle rules** → expire objects with prefix `runtime/v1/posts/` after **30 days** (dossiers older than the last deploy are served from the static build anyway). Estimated growth without it: ~135 MB/month against 10 GB included (3.4 GB currently used, 34%).

## 6. Rollback
```powershell
gh variable set SOC_RUNTIME_FEED_ENABLED --body false -R $R   # stops all uploads immediately
```
Objects already in the bucket keep being served by the Worker (once PR-4 is active) until they age out after 6 hours, then the Worker falls back to the static build. To stop runtime serving at once, revert PR-4 and redeploy with the release runbook.

## Failure reference
| Exit / message | Meaning | Action |
|---|---|---|
| `R2_AUTH_FAILED` / HTTP 403 | wrong key pair, or token not scoped to this bucket | recreate the token (step 2), reset the two secrets |
| `COUNTER_READ_FAILED` (exit 1) | the daily counter could not be read; the script refuses to write blind | check bucket/token; re-run |
| exit 2 | some uploads failed; others succeeded | read `failed[]` in the JSON line; usually transient |
| exit 3 | daily cap reached | investigate unexpected write volume before raising the cap |
| `FEED_*_INVALID` in `failed[]` | a feed file in `main` failed validation and was **not** uploaded | the publisher produced a bad file; the Worker keeps serving the last good object (≤ 6 h) |
