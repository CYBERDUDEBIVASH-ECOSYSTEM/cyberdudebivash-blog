#!/usr/bin/env python3
"""P0 read-only Blogger provider-vs-public-delivery audit.

Uses a Google OAuth refresh-token *exchange* but ONLY Blogger GET endpoints.
No Blogger create/update/delete, no repository writes, and no secret output.
Requires BLOGGER_{CLIENT_ID,CLIENT_SECRET,REFRESH_TOKEN,BLOG_ID} in environment.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser

BLOG_ID = "2163240462341298251"
HOST = "cti.cyberdudebivash.in"
ROOT = f"https://{HOST}"
MAX_BYTES = 1024 * 1024
FRESHNESS_MINUTES = 75
TIMEOUT = 12


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class LinkPaths(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.paths: set[str] = set()

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href") or ""
        url = urllib.parse.urlsplit(href)
        if (not url.netloc and href.startswith("/")) or (
            url.scheme == "https" and url.hostname == HOST and url.port is None
        ):
            self.paths.add(url.path)


class AuditFailure(Exception):
    pass


def request(url: str, *, method="GET", payload=None, authorization=None):
    """Read a size-bounded response without automatically following redirects."""
    headers = {"Accept": "application/json, text/html;q=0.8", "User-Agent": "CDB-Blogger-Provider-Audit/1.0"}
    if authorization:
        headers["Authorization"] = "Bearer " + authorization
    if payload is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=payload, method=method, headers=headers)
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(req, timeout=TIMEOUT) as response:
            data = response.read(MAX_BYTES + 1)
            if len(data) > MAX_BYTES:
                raise AuditFailure("response_size_limit")
            return response.status, response.headers.get("Content-Type", ""), data, ""
    except urllib.error.HTTPError as exc:
        # Do not read or print error response bodies; they could include OAuth details.
        location = exc.headers.get("Location", "") if 300 <= exc.code < 400 else ""
        exc.close()
        return exc.code, "", b"", location
    except (urllib.error.URLError, TimeoutError, OSError):
        raise AuditFailure("network_or_tls_failure") from None



def mobile_public_get() -> tuple[int, bytes, str]:
    """Read mobile homepage, following at most ONE validated same-host redirect.

    Blogger mobile rendering can canonicalize /?m=1 to / or /?m=0.
    The destination is never trusted blindly: no HTTP downgrade, off-host,
    alternate port, arbitrary path, credentials or second redirect is followed.
    Final page must still contain the exact latest provider permalink.
    """
    requested = ROOT + "/?m=1"
    status, _, body, location = request(requested)
    if status not in (301, 302, 303, 307, 308):
        return status, body, "DIRECT"
    if not location:
        return status, b"", "REDIRECT_MISSING_LOCATION"
    destination = urllib.parse.urljoin(requested, location)
    parts = urllib.parse.urlsplit(destination)
    params = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
    if (parts.scheme != "https" or parts.hostname != HOST or
            parts.port is not None or parts.username or parts.password or
            parts.path != "/" or parts.fragment or
            (set(params) - {"m"}) or len(params.get("m", [])) > 1 or
            (params.get("m", ["0"])[0] not in ("0", "1")) or
            destination == requested):
        return status, b"", "REDIRECT_UNTRUSTED"
    follow_status, _, follow_body, _ = request(destination)
    # One hop maximum; a second redirect stays a failing HTTP_3xx verdict.
    return follow_status, follow_body, "SAME_HOST_ONE_HOP"


def parse_utc(value: object) -> datetime:
    if not isinstance(value, str) or not (value.endswith("Z") or value[-6:-5] in ("+", "-")):
        raise AuditFailure("post_timestamp_missing_explicit_timezone")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.utcoffset() is None:
            raise ValueError("naive")
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        raise AuditFailure("post_timestamp_invalid") from None


def validate_post(items: object, now: datetime) -> dict:
    if not isinstance(items, list) or not items:
        raise AuditFailure("provider_has_no_live_posts")
    posts = []
    for post in items:
        if not isinstance(post, dict):
            raise AuditFailure("provider_item_invalid")
        pid = post.get("id")
        u = urllib.parse.urlsplit(str(post.get("url") or ""))
        if not str(pid).isdigit() or u.scheme != "https" or u.hostname != HOST or u.port is not None or not u.path.endswith(".html"):
            raise AuditFailure("provider_post_identity_or_url_invalid")
        when = parse_utc(post.get("published"))
        posts.append((when, str(pid), u.path))
    when, pid, path = max(posts)
    age = (now - when).total_seconds() / 60.0
    if age < -5:
        raise AuditFailure("provider_post_timestamp_in_future")
    if age < 0:
        age = 0.0
    return {"post_id": pid, "published_at": when.isoformat(), "path": path,
            "age_minutes": round(age, 2), "fresh": age <= FRESHNESS_MINUTES}


def evaluate_public(*, provider: dict, feed_status: int, feed_location: str,
                    feed_body: bytes, desktop_status: int, desktop_body: bytes,
                    mobile_status: int, mobile_body: bytes) -> dict:
    result = {"feed": "UNVERIFIED", "desktop": "UNVERIFIED", "mobile": "UNVERIFIED"}
    if 300 <= feed_status < 400:
        destination = urllib.parse.urlsplit(feed_location)
        result["feed"] = "REDIRECT_OFF_BLOGGER" if destination.hostname != HOST else "REDIRECT"
    elif feed_status != 200:
        result["feed"] = f"HTTP_{feed_status}"
    else:
        try:
            document = json.loads(feed_body)
            entries = document.get("feed", {}).get("entry", [])
            if not isinstance(entries, list) or not entries:
                raise ValueError("no_entries")
            # Blogger Atom IDs end in .post-<provider post ID>.
            expected = ".post-" + provider["post_id"]
            if any(str(e.get("id", {}).get("$t", "")).endswith(expected) for e in entries if isinstance(e, dict)):
                result["feed"] = "MATCHES_PROVIDER"
            else:
                result["feed"] = "POST_MISSING_OR_STALE"
        except (ValueError, TypeError, AttributeError):
            result["feed"] = "INVALID_JSON_FEED"
    for name, status, body in (("desktop", desktop_status, desktop_body), ("mobile", mobile_status, mobile_body)):
        if status != 200:
            result[name] = f"HTTP_{status}"
            continue
        try:
            links = LinkPaths()
            links.feed(body.decode("utf-8-sig"))
            result[name] = "MATCHES_PROVIDER" if provider["path"] in links.paths else "LATEST_LINK_MISSING"
        except (ValueError, UnicodeDecodeError):
            result[name] = "INVALID_HTML"
    return result


def provider_get(access: str, url: str) -> dict:
    status, ct, raw, _ = request(url, authorization=access)
    if status != 200 or "json" not in ct.lower():
        raise AuditFailure("blogger_provider_read_failed")
    try:
        value = json.loads(raw)
    except ValueError:
        raise AuditFailure("blogger_provider_json_invalid") from None
    if not isinstance(value, dict):
        raise AuditFailure("blogger_provider_json_invalid")
    return value


def run() -> dict:
    keys = ("BLOGGER_CLIENT_ID", "BLOGGER_CLIENT_SECRET", "BLOGGER_REFRESH_TOKEN", "BLOGGER_BLOG_ID")
    if any(not os.getenv(k, "").strip() for k in keys):
        raise AuditFailure("missing_credential_environment")
    if os.environ["BLOGGER_BLOG_ID"] != BLOG_ID:
        raise AuditFailure("blog_id_environment_mismatch")
    form = urllib.parse.urlencode({
        "client_id": os.environ["BLOGGER_CLIENT_ID"],
        "client_secret": os.environ["BLOGGER_CLIENT_SECRET"],
        "refresh_token": os.environ["BLOGGER_REFRESH_TOKEN"],
        "grant_type": "refresh_token",
    }).encode("utf-8")
    status, ct, payload, _ = request("https://oauth2.googleapis.com/token", method="POST", payload=form)
    if status != 200:
        raise AuditFailure("oauth_refresh_failed")
    try:
        token = json.loads(payload).get("access_token")
    except ValueError:
        raise AuditFailure("oauth_refresh_invalid_json") from None
    if not isinstance(token, str) or len(token) < 8:
        raise AuditFailure("oauth_access_token_invalid")

    base = f"https://www.googleapis.com/blogger/v3/blogs/{BLOG_ID}"
    blog = provider_get(token, base)
    if str(blog.get("id")) != BLOG_ID or urllib.parse.urlsplit(str(blog.get("url", ""))).hostname != HOST:
        raise AuditFailure("provider_blog_identity_mismatch")
    posts = provider_get(token, base + "/posts?" + urllib.parse.urlencode({
        "status": "live", "maxResults": 5, "fetchBodies": "false", "orderBy": "published"
    }))
    now = datetime.now(timezone.utc)
    provider = validate_post(posts.get("items"), now)

    feed = request(ROOT + "/feeds/posts/summary?alt=json&max-results=5&orderby=published")
    desktop = request(ROOT + "/")
    mobile_status, mobile_body, mobile_redirect = mobile_public_get()
    public = evaluate_public(provider=provider, feed_status=feed[0], feed_location=feed[3], feed_body=feed[2],
                             desktop_status=desktop[0], desktop_body=desktop[2],
                             mobile_status=mobile_status, mobile_body=mobile_body)
    delivery_ok = all(v == "MATCHES_PROVIDER" for v in public.values())
    status = "PUBLIC_DELIVERY_VERIFIED" if provider["fresh"] and delivery_ok else (
        "PROVIDER_STALE" if not provider["fresh"] else "PROVIDER_FRESH_PUBLIC_DELIVERY_BLOCKED"
    )
    return {"status": status, "provider": provider, "public": public,
            "mobile_redirect": mobile_redirect, "blog_id": BLOG_ID,
            "checked_at": now.isoformat(),
            "blogger_publication": "NOT_ATTEMPTED", "production_deployment": "NONE"}


def main() -> int:
    try:
        result = run()
    except AuditFailure as exc:
        result = {"status": "AUDIT_INCONCLUSIVE", "reason": str(exc), "blogger_publication": "NOT_ATTEMPTED", "production_deployment": "NONE"}
    except Exception:
        # Never print raw exception bodies: token requests can contain secrets.
        result = {"status": "AUDIT_INCONCLUSIVE", "reason": "unexpected_exception", "blogger_publication": "NOT_ATTEMPTED", "production_deployment": "NONE"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PUBLIC_DELIVERY_VERIFIED" else 2


if __name__ == "__main__":
    sys.exit(main())
