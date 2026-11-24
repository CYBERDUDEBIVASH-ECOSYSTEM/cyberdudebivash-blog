# SOC runtime feed ("Option A"): durable freshness without a deploy

**Status:** PR-1 (Worker read-through) is **inert until activated**. Nothing here changes production behaviour by itself.
**Decision record:** owner chose Option A (2026-11-24) over B (relabel as snapshot) and C (scheduled auto-deploy).

| PR | Scope | Activates anything? |
|---|---|---|
| **PR-1 (this)** | Worker read-through `workers/lib/runtime-feed.js` + router hook + tests | **No.** No binding and no `run_worker_first`, so nothing reaches it for the feeds; dossier fallback only runs after a static 404 and only if a binding exists. |
| PR-2 | R2 uploader + flag-gated workflow (`vars.SOC_RUNTIME_FEED_ENABLED`) | No: skipped while the flag is off. |
| PR-3 | Parity gates and monitors accept runtime provenance (bounded propagation grace) | Only for responses that carry valid runtime provenance. |
| PR-4 | `wrangler.jsonc`: R2 binding + `run_worker_first`. **Merge only after the owner creates the bucket.** | **Yes.** This is the activation switch. |

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
