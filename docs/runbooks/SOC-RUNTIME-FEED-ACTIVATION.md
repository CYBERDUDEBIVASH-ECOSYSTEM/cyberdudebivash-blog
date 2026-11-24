# SOC runtime feed (Option A): activation, verification and rollback

Activates durable freshness: after this, the public feeds (`/live-intel.json`, `/api/intel/live.json`, `/rss.xml`) and new dossiers are served from the `soc-runtime-feed` R2 bucket without a deploy, so the "Feed freshness" tile on soc.cyberdudebivash.in stays within minutes of the pipeline instead of ageing from the last release. Architecture and safety contract: `docs/operations/SOC-RUNTIME-FEED-OPTION-A.md`. Publisher setup: `docs/runbooks/SOC-RUNTIME-FEED-PUBLISHER.md`.

Confidence tags: *Verified* (checked in the repo or run in CI), *Not verified* (needs your Cloudflare/GitHub access or traffic data; commands below have not been executed by the author).

**Status (2026-11-24, *Verified* against `main` at `38895ddc`):** all code is merged (#701 to #707, including the activation config in #706). Nothing is deployed: the live Worker is still the 2026-10-23 bundle. **The next release of `main` activates runtime serving**, so every precondition in section 1 must be true before that release. The publisher has never run for real (its 4 runs were all `skipped`, flag off).

## 0. What PR-4 changes (and what it does not)
* `wrangler.jsonc` only: an `RUNTIME_FEED` R2 binding to `soc-runtime-feed`, and `assets.run_worker_first` for exactly three literal paths. *Verified:* parsed by Wrangler 4.123 (`unstable_readConfig`, `wrangler deploy --dry-run` lists `env.RUNTIME_FEED`), pinned by `tests-js/runtime-feed-activation-config.test.js` (no wildcard, no `true`, premium bucket never bound).
* **Nothing changes in production until a release deploys it.** Merging does not deploy (the deploy workflow is manual-dispatch, SHA-pinned and budget-gated; its push-triggered runs, including the one for this PR's merge, are `skipped`).
* **PR-4 is merged (#706; its title still says "DO NOT MERGE YET", kept for history).** A release must be the live `main` tip, so the next release necessarily ships the binding.
* Prerequisites, all merged: publisher serving the build's bytes (#703), provenance-aware gates (#704), runtime responses carrying the static headers (CORS, CSP) (#705), dossier miss cache (#707). Without #705 the feeds would lose CORS and dossiers would render unstyled.

## 1. Preconditions (all owner steps; PR-4 is already merged, so every box must be true before the next release)
1. #705 merged. *(Done.)*
2. Bucket and token exist and the publisher has run for real at least once (publisher runbook steps 1-4): `check_only` shows `R2_AUTH_OK`, a real run shows `failed: []`. `wrangler deploy` **fails** if the bucket does not exist. *(Not done as of 2026-11-24: no manual publisher run exists.)* A read-only way to confirm the bucket is visible to the deploy token and to count its objects: `npx wrangler r2 bucket info soc-runtime-feed`.
3. **Traffic and budget input (Not verified, owner data).** Static asset requests are free and uncounted; after activation every request to the three paths is a Worker request (about 1 ms CPU each, measured blog Worker median 0.84 ms) plus at most one R2 read per path per colo per minute (60 s Cache API). Read the last 30 days of requests for those three URLs (Cloudflare dashboard, zone analytics filtered by URI) and compute `requests x 1 ms` against the remaining CPU and request allowances. Put the result in the budget attestation under the Workers requests and CPU meters. If a single bot dominates the traffic, fix that first (rate limit) or the CPU forecast will not pass the zero-overage gate.
   **Forecast rule (*Verified* from `cloudflare-account-zero-overage-gate.cjs`):** the CPU rate measured before activation does not include this traffic, so add it to `forecastRemaining` (keep `cpuMeasurement.recentMsPerDay` as the honest measured value). With `N` = 30-day requests to the three URLs, `C` = data centres that served them and `D` = days left in the cycle: Workers requests `+ ceil(1.25 x (N/30) x D)`, Workers CPU-ms `+ ceil(1.25 x (N/30) x 1.0 x D)`, R2 Class A `+ 1.25 x 3000 x D` (the publisher's hard daily cap), R2 Class B `+ ceil(1.25 x 3 x C x 1440 x D)` (upper bound: each active data centre refreshes each path once a minute, so Class B scales with `C`, not with `N`). The gate keeps used plus forecast within 80% of each allowance (CPU alone may use the single-release exception up to 100%).
4. The release itself passes the zero-overage gate (runbook `SOC-RELEASE-RUNBOOK.md`; the CPU release exception applies as before).

## 2. Release (add these steps to the pinned-SHA runbook)
After the writer freeze and SHA pin, **before** dispatching the deploy:
1. Run the publisher at the pinned SHA and wait for success:
   ```powershell
   gh workflow run soc-runtime-feed-publisher.yml -R CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog --ref main -f dry_run=false
   ```
   *Why:* the Worker serves R2 first on the three paths. If R2 held an older object than the build, public would briefly move backwards (bounded by the 6 h age limit) until the publisher catches up. The bytes are deterministic and produced by the build's own transform, so R2 equals the build for the same commit.
2. Dispatch the deploy as usual. The in-job post-deploy gates (`--release-asset`) accept public bytes equal to the build, or runtime output **strictly newer** than the build with valid provenance. `PUBLIC_ASSET_SHA256_MISMATCH` means R2 was older or different: re-run step 1, then re-run the read-only verification.

## 3. Verify after the release (read-only; Not verified until you run it)
```powershell
curl.exe -s -D - -o NUL https://soc.cyberdudebivash.in/live-intel.json
curl.exe -s -D - -o NUL https://soc.cyberdudebivash.in/api/intel/live.json
curl.exe -s -D - -o NUL https://soc.cyberdudebivash.in/rss.xml
```
Expect on each: `x-feed-source: runtime-r2`, a 64-hex `x-feed-sha256`, `x-feed-generated-at` within minutes, `access-control-allow-origin: *`, and the same `cache-control` as before (feeds `public, max-age=60, must-revalidate`; RSS `public, max-age=3600, stale-while-revalidate=86400`). Then:
* The dashboard "Feed freshness" tile shows minutes, not days (it reads `generatedAt` from `/live-intel.json`).
* The next three publisher commits: the Production Smoke Test, `freshness-check` and `customer-release-certification` stay green; the parity/S2N output shows `provenance: runtime-r2` (a `runtime-r2-REJECTED:<reason>` label means the headers or hash did not verify: investigate, do not widen the gates).
* A newly published dossier (`/posts/<slug>.html`) returns 200 with `content-security-policy: default-src 'self' ...` and renders styled. This also lets the Blogger source-delivery guard pass first-party dossiers without a deploy.

## 4. Rollback ladder (cheapest first)
1. **Stop writes:** `gh variable set SOC_RUNTIME_FEED_ENABLED --body false -R CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog`. The Worker keeps serving the last objects for up to 6 h, then falls back to the static build.
2. **Serve static immediately (no deploy):** delete the three feed objects (`runtime/v1/live-intel.json`, `runtime/v1/api/intel/live.json`, `runtime/v1/rss.xml`) from the bucket, for example `npx wrangler r2 object delete soc-runtime-feed/runtime/v1/live-intel.json --remote` for each (command form checked with `--help`, *Not verified* by execution). The Worker falls open to the static asset on the next request (within the 60 s cache). Requests still invoke the Worker (about 1 ms) until step 3.
3. **Remove the activation:** revert this PR and release with the pinned-SHA runbook (needs a budget-gate pass; the exception is single-release and expires 2026-12-01).

## 5. Known limits
* After activation, every request to the three paths is a Worker request. This is the only new recurring cost; the budget input in section 1.3 decides whether it is acceptable. *Not verified against real traffic.*
* CORS preflight (`OPTIONS`) is not served from the runtime store; it falls through to the static asset as before.
* The RSS public `Cache-Control` stays 1 h (unchanged from today), so downstream caches can hold an RSS copy up to an hour even though the origin is fresh.
* **Correction (2026-11-24, *Verified*):** the release itself makes every dossier in the pinned commit public, because the build ships all of `posts/` (9,444 built = 9,444 in the repo at `38895ddc`, of which 1,846 are dated 2026-10-23 or later by their own timestamps). **No `since_commits=300` backfill is needed for the release.** The backfill only matters for dossiers newer than the pinned build. Reports older than the Blogger 72 h window are still not delivered to Blogger automatically.
* A runtime object is trusted for at most 6 h. If the publisher stops, the site degrades to the static build, not to an error.
* Dossier lookups that find nothing are remembered for 60 s per data center (R2 Class B cost control). A dossier uploaded right after a miss can therefore 404 for up to a minute; the next Blogger run or reload picks it up. A flood of distinct valid slugs still costs one read each (bounded by request rate).
