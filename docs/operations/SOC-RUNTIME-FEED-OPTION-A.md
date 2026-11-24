# SOC runtime feed ("Option A"): durable freshness without a deploy

**Status:** PR-1 (Worker read-through) is **inert until activated**. Nothing here changes production behaviour by itself.
**Decision record:** owner chose Option A (2026-11-24) over B (relabel as snapshot) and C (scheduled auto-deploy).

| PR | Scope | Activates anything? |
|---|---|---|
| **PR-1 (this)** | Worker read-through `workers/lib/runtime-feed.js` + router hook + tests | **No.** No binding and no `run_worker_first`, so nothing reaches it for the feeds; dossier fallback only runs after a static 404 and only if a binding exists. |
| PR-2 | R2 uploader + flag-gated workflow (`vars.SOC_RUNTIME_FEED_ENABLED`) | No: skipped while the flag is off. |
| PR-3 | Parity gates and monitors accept runtime provenance (bounded propagation grace) | Only for responses that carry valid runtime provenance (none exist until PR-4). |
| PR-1b | Runtime responses carry the static build's exact headers (CORS, CSP, cache) | No (same inert contract as PR-1). **Must merge before PR-4.** |
| PR-2b | Publisher uploads the public-build bytes, not raw source | No. Merged (#703). |
| PR-4 | `wrangler.jsonc`: R2 binding + `run_worker_first`, config pin test, activation runbook (`docs/runbooks/SOC-RUNTIME-FEED-ACTIVATION.md`). **Merge only after PR-1b and after the owner creates the bucket and the publisher has run once.** | **Yes.** This is the activation switch (still needs a release to deploy). |

## Current architecture
The feeds (`/live-intel.json`, `/api/intel/live.json`, `/rss.xml`) and every `/posts/*.html` dossier are static assets baked into the Worker at deploy time (`wrangler.jsonc` `assets`, no `run_worker_first`, so they cost no Worker CPU). Deploys are manual, SHA-pinned (5-way match against a `main` that moves every ~29 min) and budget-gated, so the public feed passes the 180-minute freshness limit shortly after any release, and new dossiers return 404 until the next release.

## Proposed architecture
The publisher writes the feeds and the new dossiers to a **dedicated R2 bucket** (`runtime/v1/…`). The Worker serves the three feed paths live from it and uses it as a fallback for dossiers missing from the static build. **Deploys ship code only.** The git repository stays the system of record; R2 is a derived serving store.

## Reason
Manual releases cannot keep a 3-hour freshness SLO. Relabelling (B) keeps the product honest but not live; scheduled deploys (C) conflict with the manual-deploy, SHA and budget controls.

## Safety contract (enforced by `tests-js/runtime-feed.test.js`, 8 deliberate regressions mutation-tested)
1. **Fail-open to static.** No binding, missing object, invalid/stale/future metadata, oversize, any exception: return `null` and serve the static asset exactly as before.
2. **Allowlist only.** Three feed paths; `/posts/<slug>.html` (strict grammar) only after a static 404. Keys are constants or a validated slug under `runtime/v1/`.
3. **Route precedence preserved.** The hook runs only for unrouted (static) paths and `asset` routes; `blocked`, `redirect` and `handler` routes never consult the bucket.
4. **GET/HEAD only**, no cookies, `If-None-Match` honoured, baseline security headers applied.
5. **Separate bucket.** Never `PREMIUM_REPORTS` (paid artifacts); a publisher token scoped to the runtime bucket cannot touch them.
6. **Integrity at the edges.** Objects carry `sha256` and `generated-at` metadata written by the publisher; the Worker does not hash per request (CPU), and the release/monitor gates (PR-3) verify the served bytes against that sha256.
7. **The bytes uploaded are the bytes the public build would serve, never raw source (PR-2b).** The publisher calls the build's own `copyFileForPublicBuild` (single source of truth), so the runtime objects carry the certified transforms: approved CVSS corrections on the JSON feeds (the live API feed differs from raw source by about 3.5 KB today), the RSS origin rewrite, and the HTML claim/structure/SEO transforms for dossiers. A file the build would reject is not uploaded and is reported (exit 2). The `sha256` metadata describes the served bytes. The output is deterministic, so unchanged files are never re-uploaded (cost control). *Found in review before activation: the first publisher (PR-2) uploaded raw files; it was inert (flag off, no binding), so no customer saw it.*

## Data contract
`runtime/v1/live-intel.json`, `runtime/v1/api/intel/live.json`, `runtime/v1/rss.xml`, `runtime/v1/posts/<slug>.html`. Custom metadata: `sha256` (64 hex), `generated-at` (ISO-8601 UTC, feeds only). Feed objects older than **6 h** are ignored (fall back to static); objects dated more than 5 min in the future are ignored.

## Budget model (Not verified against live traffic; the zero-overage gate decides)
* **R2 Class A (writes):** publisher runs ~48/day; typical ≈ 300 PUT/day (3 feeds + new dossiers), hard-capped in PR-2. ≈ 9k/month vs 1M included (0.9%). September's overage was 3M Class A operations, hence the hard cap.
* **Workers requests/CPU:** only the three feed paths are intercepted (`run_worker_first`, PR-4). Measured blog Worker median ≈ 0.84 ms/request, so 1M feed requests/month ≈ 1M CPU-ms (≈ 3.3% of 30M). A 60-second Cache API layer limits R2 reads (Class B) to ~one per path per colo per minute.
* **Gateway CPU:** the gateway fix (2026-11-24 03:50 UTC) is what creates the headroom; the release exception measures it.

## Compatibility
All existing URLs, headers semantics (feeds gain `X-Feed-*` provenance), routes and exports are unchanged. The static assets remain the baseline and the fallback.

## Migration
1. Merge PR-1, PR-2, PR-3 (all inert). 2. Owner creates the bucket and a **bucket-scoped** token, sets secrets/variables (PR-4 runbook). 3. Merge PR-4 and release with the pinned-SHA runbook. 4. Set `SOC_RUNTIME_FEED_ENABLED=true`; watch monitors.

## Rollback
Set `SOC_RUNTIME_FEED_ENABLED=false` (uploads stop; the Worker keeps serving the last object until it ages out after 6 h, then static). To stop runtime serving immediately: revert PR-4 and redeploy (or delete the objects). PR-1/2/3 are inert without PR-4.

## Known limits / residual risks
* Dossier HTML for reports newer than the last deploy is served from R2 only after PR-2 uploads it; a dossier never uploaded still 404s (the Blogger guard still blocks, correctly).
* The Cache API adds up to 60 s of propagation; monitors need the bounded grace added in PR-3.
* A runtime object older than the static baseline (publisher stopped after a deploy) can be served for up to 6 h; the 6 h age limit bounds it.

## PR-3 (BUILT; must be merged BEFORE activation, i.e. before PR-4)

**Implemented:** `scripts/lib/runtime-feed-provenance.cjs` (new, pure) + `check()` in `certify-soc-public-feed-parity.cjs` + `monitorPublic()` / `verifyPublic()` in `certify-soc-s2n-api-release.cjs`. Deviations from the design below, all deliberate and stricter: (a) the equality waiver applies only when the response was generated at a **different instant** than the source (same instant stays exact); (b) the corpus must move in the direction of time (an older feed cannot have a larger `total_published`; a newer one cannot have a smaller one), else `*_RUNTIME_*_INCONSISTENT`; (c) in `--release-asset` mode, other bytes pass only if the runtime object is **strictly newer** than the build asset (same instant with other bytes is drift, not "not older"); (d) results carry a `provenance` label (`runtime-r2`, `static`, or `runtime-r2-REJECTED:<reason>`) so a rejected claim is visible. Static behaviour is byte-for-byte unchanged and tested. Verified: 16 new tests, the existing gate suites (167) pass, 21/21 deliberate regressions caught.

### Original design

**Why it is required (Verified from code).** Once public feeds are served from R2 they can differ from the checked-in source for a short propagation window, and the existing gates tolerate almost none of it:
* `scripts/certify-soc-s2n-api-release.cjs` `monitorPublic()` requires **exact** `total_published` and **exact item-ID equality** with source, and rejects public ahead of source by more than 5 min (`PUBLIC_S2N_API_REPORT_IDENTITY_DRIFT`). Public behind source by more than 5 min fails (`PUBLIC_S2N_API_BEHIND_SOURCE`).
* `scripts/certify-soc-public-feed-parity.cjs` `assess()` fails if public is more than 5 min behind source (`PUBLIC_SOURCE_DEPLOYMENT_DRIFT`) or has a lower `totalPublished` (`PUBLIC_CORPUS_BEHIND_SOURCE`).
* The Production Smoke Test is **push-triggered**, so it samples roughly a minute after every publisher commit, inside the propagation window. Without a bounded grace it would flap on essentially every publisher commit, whichever side leads (upload after push: public behind; upload before push: public ahead, which fails ID equality).
* `--release-asset` (post-deploy) demands public bytes == built bytes; a runtime feed newer than the build would fail it.

**Design (provenance-gated, bounded, strict by default).**
1. `check()` / `verifyPublic()` / `monitorPublic()` read the response headers `X-Feed-Source`, `X-Feed-Sha256`, `X-Feed-Generated-At`.
2. A response counts as **runtime-provenanced** only if ALL hold: `X-Feed-Source == runtime-r2`; `sha256(body)` equals `X-Feed-Sha256` (the certifier recomputes it); `X-Feed-Generated-At` equals the feed's own pipeline timestamp (same precedence as `publish-runtime-feed.cjs`); age <= 180 min.
3. Only for a runtime-provenanced response: allow public to be **behind** source by up to `RUNTIME_PROPAGATION_GRACE_MINUTES = 10` (skip the exact total/ID equality inside that window, but still require internal validity, freshness <= 180 min and that public is never *ahead* of source by more than 5 min); in `--release-asset` mode accept bytes different from the build only if the runtime object is **not older** than the build asset and passes (2).
4. Everything else is unchanged and strict: no provenance header, wrong sha, mismatching timestamp, or lag beyond 10 min keeps the current failure codes.
5. Tests: provenance accepted/rejected matrix (each failing condition individually), grace boundary at exactly 10 min and 10 min + 1 s, ahead-of-source still fails, header spoofing without a matching body hash fails, static (no header) behaviour byte-for-byte unchanged; mutation-test each rule.

## PR-4 (BUILT as a draft; implementation and step-by-step runbook: `docs/runbooks/SOC-RUNTIME-FEED-ACTIVATION.md`; merge ONLY after PR-1, PR-1b, PR-2, PR-2b, PR-3 and the owner's bucket/token/secrets)
Original design, kept for the record:
* `wrangler.jsonc`: add `r2_buckets` `{ "binding": "RUNTIME_FEED", "bucket_name": "soc-runtime-feed" }` and `assets.run_worker_first: ["/live-intel.json", "/api/intel/live.json", "/rss.xml"]` (exact paths only; every other static asset stays free).
* `wrangler deploy` fails if the bucket does not exist, so PR-4 must not merge first.
* Update the release runbook: with the writer freeze, R2 equals the pinned build bytes; verify `X-Feed-Source` after deploy.
* Add the new meters (Worker requests/CPU for three paths, R2 Class A/B) to the budget attestation inputs.
* Sequencing guard: **never activate before PR-3**, or the monitors flap on every publisher commit.
