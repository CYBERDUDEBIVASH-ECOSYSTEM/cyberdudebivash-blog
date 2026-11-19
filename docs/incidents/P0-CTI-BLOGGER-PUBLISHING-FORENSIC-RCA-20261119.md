# P0 forensic RCA — CTI Blogger publishing stopped
**Date:** 2026-11-19 (UTC)  
**Repository:** `CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog`  
**Customer surface:** `https://cti.cyberdudebivash.in`  
**Incident:** [#434](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/cyberdudebivash-blog/issues/434)  
**Baseline inspected:** `b6dd7605d28e22c596ae629effe4ab4eeb2f5add`  
**Verdict:** **P0 OPEN / production customer release NO-GO**

## 1. Confirmed outage trigger

The GitHub Actions workflow `.github/workflows/blogger-syndication.yml` schedules `17 * * * *` but guards its *entire publisher job* with:

```yaml
if: ${{ github.ref == 'refs/heads/main' && (github.event_name == 'workflow_dispatch' || vars.BLOGGER_OAUTH_READY == 'true') }}
```

On 2026-11-18 an authenticated organization-owner `gh api repos/.../actions/variables` listing succeeded and returned `BLOGGER_OAUTH_READY=MISSING`. Five recent schedule runs were all `completed/skipped`, newest #44346725400, 2026-11-18T16:23:43Z. The job is **never started**, meaning no in-job content discovery, token exchange, Blogger posts.insert, fetch-back, or publication-state write can occur on those scheduled invocations. This is a configuration/authorization gate, not a Python stack trace.

**State qualification:** The above was the authenticated observation at 2026-11-18. A newer variable listing has not been collected in this review; recheck immediately before approving activation.

## 2. Independent publication and delivery evidence

- Historical certified dry run #44341896628: success, `published=0`, no repository mutations.
- Read-only authenticated Blogger provider audit #44448918002: `PROVIDER_STALE`, latest real provider post `2026-11-13T19:08:09Z`, ID `9098788539239953995`, `age_minutes=7677.29` at audit. Feed and desktop `MATCHES_PROVIDER`, mobile `HTTP_302` (redirect destination requires independent inspection). The audit deliberately exits 2 on staleness.
- User HTTP feed check on 2026-11-18 17:56 UTC: Blogger `302` from `/feeds/posts/default?alt=rss` to `https://intel.cyberdudebivash.com`; Blogger settings screenshot showed this URL configured as Post feed redirect. User rechecked on 2026-11-18 17:59 UTC: `HTTP 200`, `application/rss+xml`. The RSS path was repaired for that direct client; global propagation not fully certified.
- Parsed RSS: 14 reports, newest `2026-11-13T19:08:09Z`. An RSS `Last-Modified` header is *not* an article publication timestamp.
- Fresh manual one-post dry run #44451505298: success, `selected=1`, `published=0`, `integrity_blocked=0`, `DRY_RUN_GIT_MUTATIONS=NONE`. The chosen first-party AttackIQ/Dark Reading record was independently found to contain unsupported affected-entity and event-specific ransomware assertions. Dry-run success does *not* authorize publishing.
- PR #645's exact-source editorial quarantine and PR #646's Node source-to-claim integrity fix were subsequently merged (in current `main` ancestry). Neither proves that a new live Blogger post exists, nor corrects historical HTML by itself.

## 3. Causality matrix

| Component | Evidence | Interpretation |
|---|---|---|
| GitHub schedule | Cron hourly; job-level readiness guard | Entry point exists but is disabled if variable not `true` |
| Readiness configuration | Authenticated owner list: variable missing | **Confirmed proximal non-execution cause at the time of observation** |
| OAuth | Authenticated refresh/read-only Blog API PASS | Credentials are sufficient to read; **live write scope NOT proven** |
| Candidate discovery | Manual dry-run found 230 candidates, selected one | Source ingestion not categorically down |
| Editorial integrity | Selected dossier had unsafe assertions | Quality of selected source is a separate release blocker |
| Blogger API | Provider audit shows last real post Nov 13 | Customer publishing actually stale; not only a cache issue |
| Blogger feed | 302 corrected to 200 RSS for operator | Routing repair does not create posts |
| Recovery monitor | `freshness-check.yml` guards automatic Blogger recovery on `BLOGGER_OAUTH_READY=true` | Same missing readiness prevents self-heal |
| Mobile endpoint | Provider audit `HTTP_302` | Destination/visibility unknown; do not misclassify as unavailable |
| Publication ledger | Updated by pipeline after Blogger create; persisted via Git commit+push | Write/commit reconciliation is **not yet proven in a live canary** |

## 4. Latent safety failures and protective controls

**Observed live dispatch policy gap:** Before PR #647, manual `workflow_dispatch` bypassed `BLOGGER_OAUTH_READY` for either a 1-post or a 4-post live batch. This could cause premature multi-post publication and social amplification while the scheduler was intentionally paused.

**PR #647 (isolated, no live change):** early Bash authorization gate before Python dependencies and a second immediate pre-publish check; explicit `live_canary_approved=true` required for a manual 1-post live run; larger manual or automated writes require `BLOGGER_OAUTH_READY=true`. Existing twice-hourly monitor reports `BLOGGER_SCHEDULE_GATE=READY|MISSING|DISABLED|INVALID` without extra schedules or HTTP calls.

**Preserve current duplicate safety:** `automation/blogger_publisher.py` suppresses automatic replay of ambiguous `posts.insert` network/5xx outcomes. Do not replace it with blind retries. `VerifiedBloggerPublisher` does live GET/fetch-back and bounded repair/revert; only a live canary can certify those paths. A subsequent Git push failure can leave a provider post ahead of the local state ledger; reconcile provider post IDs and exact source URL before any retry or scheduled reactivation.

## 5. Bounded operational recovery and rollback

1. **Read-only configuration and freshness snapshot.** Confirm branch/main SHA, GH identity, `BLOGGER_OAUTH_READY` variable, latest schedule statuses, latest provider post via authenticated read-only audit, RSS GUID/date and desktop/mobile permalink. Avoid writing to Blogger.
2. **Approve and merge PR #647 after full CI** and review. Confirm new merge SHA; verify source `main` includes PRs #645/#646. Do not enable schedule yet.
3. **One-post dry run** on merged main, `dry_run=true,max_posts=1`. Review the *new* candidate's original source, timestamps, entity mapping, CVE/ATT&CK claims, editorial classification, duplicate status, and free-model cost. Reject unsupported text.
4. **Separately authorize one live canary:** `dry_run=false,max_posts=1,live_canary_approved=true` on reviewed main. The guard must suppress X/Twitter automatic amplification. Stop immediately if OAuth write-scope, quality, quota, provider insert, live fetch-back or publication-state persist fails.
5. **Independent customer fetch-back:** exact provider post ID/status=LIVE, persisted content title/labels, HTTPS public permalink, RSS GUID/date/link, desktop and mobile visibility (follow expected same-host canonical redirects), local ledger and Git push all consistent. No duplicates.
6. **Controlled schedule enablement:** only after canary proof, set `BLOGGER_OAUTH_READY=true`, confirm one bounded scheduled run then the second healthy cycle with freshness SLO and no unsupported claims; no backlog flood.
7. **Rollback:** if unexpected live writes/stale data recur, set `BLOGGER_OAUTH_READY=false` (or remove it if originally absent). This pauses schedule/push and monitor-driven recovery. Do not delete already-published articles without separate approval. Revert PR #647 only if its strict authorization contract causes a verified regression.

## 6. Release acceptance and unknowns

**Release NO-GO until:** a new genuine report is LIVE in Blogger, provider read-back matches submitted data, customer RSS and desktop/mobile visibility are checked, publication ledger is durable, and two later scheduled runs meet the approved freshness SLO.

**Still unverified:** current GitHub readiness value after Nov 18; current provider latest post after authenticated audit; OAuth *write* capability, Blogger insert quota on live execution, actual public mobile redirect target, candidate editorial quality after quarantine, and Git ledger push durability after live publish.

**Do not confuse:** a green repository CI, manual dry-run, RSS HTTP 200, or successful Google OAuth read with a successfully published and delivered customer report.
