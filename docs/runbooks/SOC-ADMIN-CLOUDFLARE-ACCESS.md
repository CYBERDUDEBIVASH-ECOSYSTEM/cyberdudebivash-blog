# Cloudflare Access for the admin API: setup, staged rollout and rollback

Puts a named, MFA-backed identity in front of the endpoints that approve and reject payments, and records who did what. The Worker verifies the signed Access token itself (`api/_lib/admin-access.js`), so a missing or wrong Access policy cannot silently expose the admin API. The shared `X-Admin-Key` stays as a second factor.

Confidence tags: *Verified* (checked in the repo or by tests in CI) · *Not verified* (needs your Cloudflare account; steps below have not been executed by the author).

## 0. What is protected, and how it behaves

| Endpoint | Gate | Token source |
|---|---|---|
| `/api/v1/admin` and `/api/v1/admin/payments/*` (pending, approve, reject, audit, razorpay-orders, product-orders, gumroad-sales) | Access identity, then `X-Admin-Key` | `Cf-Access-Jwt-Assertion` header only |
| `/api/v1/detections/performance?action=review-queue` | Access identity, then `X-Admin-Key` | header **or** the `CF_Authorization` cookie (this action shares its URL path with customer actions, so an Access application cannot isolate it by path) |

*Verified:* these are the only two places that check the admin key; the only page that calls an admin API is `review-queue.html`; no workflow or script calls the admin API.

`ADMIN_ACCESS_MODE` controls everything and **defaults to off**, so merging and releasing this change alters nothing until you turn it on:

| Value | Behaviour |
|---|---|
| unset or `off` | Exactly the previous behaviour. No token is read. |
| `audit` | Verify and record every admin request (`ADMIN_ACCESS_AUDIT`), never block. |
| `enforce` | A valid Access token is **required**; the key is still required. Misconfiguration or a typo in the mode denies (503), it never disables the check. |

Three Worker settings: `ADMIN_ACCESS_MODE`, `CF_ACCESS_TEAM_DOMAIN` (`<team>` or `<team>.cloudflareaccess.com`), `CF_ACCESS_AUD` (the application's 64-hex Audience tag; comma-separate several).

## 1. Cloudflare Zero Trust setup (owner; dashboard) *Not verified*
1. **Zero Trust, Settings, Authentication:** enable a login method with MFA (an identity provider that enforces MFA is strongly preferred over one-time PIN). Note your **team domain** (`<team>.cloudflareaccess.com`).
2. **Access, Applications, Add application, Self-hosted.** Create **one** application (one AUD tag) with these destinations:
   * `blog.cyberdudebivash.in` path `api/v1/admin*` (covers `/api/v1/admin` and `/api/v1/admin/payments/*`)
   * `blog.cyberdudebivash.in` path `review-queue.html`
   * the same two on `soc.cyberdudebivash.in` (the Worker serves both hostnames)
   * Session duration: short (for example 8 hours).
3. **Policy:** Action **Allow**; Include only the named operators (emails or an IdP group); Require MFA if your IdP exposes it. Anything not matching is denied.
4. **Service token (only if automation will call the admin API).** None does today. If needed: Service Auth, create a token, add a policy with Action **Service Auth** for it; clients send `CF-Access-Client-Id` and `CF-Access-Client-Secret`. The Worker records these as `service:<client id>`.
5. Copy the **Application Audience (AUD) Tag** from the application's overview.
6. **Check and close the bypass:** in Workers and Pages, `cyberdudebivash-blog`, Settings, Domains and Routes, make sure the `workers.dev` route and preview URLs are **disabled** (`wrangler.jsonc` does not set `workers_dev`, so its default applies: *Not verified* which). In `enforce` mode the Worker refuses admin requests without a valid token even if a request arrives on such a hostname.

## 2. Worker configuration *Not verified*
Set these as Worker **secrets** (secrets persist across `wrangler deploy`; a plain dashboard variable that is not in `wrangler.jsonc` can be removed by the next deploy: documented Cloudflare behaviour, not verified here). Values are prompted, never put on the command line:
```powershell
npx wrangler secret put CF_ACCESS_TEAM_DOMAIN --name cyberdudebivash-blog
npx wrangler secret put CF_ACCESS_AUD         --name cyberdudebivash-blog
npx wrangler secret put ADMIN_ACCESS_MODE     --name cyberdudebivash-blog   # enter: audit
```
Setting a secret creates a new deployment of the current version within seconds. **This code must already be deployed** (it ships with the next release of `main`): before that, these secrets are simply ignored.

## 3. Staged rollout
**Stage 1: `audit` (at least a week of real operations).** Use the admin pages and API as normal. Then read the trail:
```
GET /api/v1/admin?action=audit&filter=ADMIN_ACCESS      (with your Access session and X-Admin-Key)
```
Expect only `ADMIN_ACCESS_AUDIT` entries with `result: ACCESS_OK` and `actor: user:<email>`. Any other `result` is a caller that is **not** coming through Access (a stale bookmark, a script, a direct route): find it before enforcing. Codes are short and never contain token data: `ACCESS_TOKEN_MISSING`, `..._MALFORMED`, `..._ALG`, `..._KID_UNKNOWN`, `..._SIGNATURE`, `..._ISSUER`, `..._AUDIENCE`, `..._EXPIRED`, `..._NOT_YET_VALID`, `..._CLAIMS`, `..._NO_IDENTITY`, `ACCESS_JWKS_UNAVAILABLE`, `ACCESS_MODE_INVALID`, `ACCESS_TEAM_INVALID`, `ACCESS_AUD_INVALID`.

**Stage 2: `enforce`.** When Stage 1 is clean, `npx wrangler secret put ADMIN_ACCESS_MODE` and enter `enforce`. Verify (read-only):
1. Without a session: `curl.exe -sI https://blog.cyberdudebivash.in/api/v1/admin?action=audit` should answer with a redirect to `<team>.cloudflareaccess.com` from the edge. It must **not** reach the Worker.
2. Bypass probe (only if a `workers.dev` hostname exists): the same request with a correct `X-Admin-Key` but no Access token must return `401` with `ACCESS_REQUIRED`.
3. With your session (or a service token): the request returns `200`.
4. Approve or reject a test transaction and confirm the `PAYMENT_APPROVED` or `PAYMENT_REJECTED` audit entry carries `actor: user:<your email>`.

## 4. Rollback (no deploy needed)
```powershell
npx wrangler secret put ADMIN_ACCESS_MODE --name cyberdudebivash-blog     # enter: audit  (stop blocking, keep observing)
npx wrangler secret delete ADMIN_ACCESS_MODE --name cyberdudebivash-blog  # back to off
```
Use this if an operator is locked out, Access has an outage, or a policy is wrong. **Keep at least two people able to run it:** recovery uses your Cloudflare or `wrangler` credentials, not Access. If Cloudflare's key endpoint is briefly unreachable, the Worker reuses its last good key set for up to 24 hours; beyond that `enforce` denies with 503 until you roll back to `audit` or Cloudflare recovers.

## 5. Cost and limits
* **No metered spend added (by design):** the check runs only on admin requests (low volume): one RSA verification per request and one key-set fetch per Worker instance per hour (a free subrequest). CPU per verification was not measured on Workers (*Not verified*; a few ms at most is expected).
* **Zero Trust seats:** the free plan allows up to 50 users (*Not verified for your account*); seats count account-wide across all your platforms.
* **Not covered by this change:** the analyst APIs (`analyst-auth.js`), the Gumroad webhook (vendor-unsigned), and an allow-list of emails inside the Worker (the Access policy is the single place that decides who is an operator).
* **Audit-log labels:** `ADMIN_AUTH_FAIL` entries written before the `auditLog` fix are stored under the requested admin action (for example `action: "approve"`) instead of the event name, so a filter on `ADMIN_AUTH_FAIL` will not find them; they still carry the IP, endpoint and user agent. Entries written after the fix use the event name and keep the requested action as `requested`, like the new `ADMIN_ACCESS_*` events.
