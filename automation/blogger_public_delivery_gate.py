"""Independent public read-back for newly published Blogger posts.

Blogger's authenticated API fetch-back is necessary but not sufficient:
public permalinks and the public Atom/JSON feed must also expose the new IDs.
This module performs read-only HTTP and never retries writes or edits posts.
"""
from __future__ import annotations

import argparse
import json
import re
import time
from html import unescape
from pathlib import Path
from urllib.parse import urlsplit

import requests

_PUBLIC_HOST = "cti.cyberdudebivash.in"
_FEED_URL = f"https://{_PUBLIC_HOST}/feeds/posts/default?alt=json&max-results=10"
_MAX_PAGE_BYTES = 768 * 1024
_MAX_FEED_BYTES = 5 * 1024 * 1024
# A post may move off the first ten feed entries between API write and
# independent public verification. Never retry writes to compensate for
# legitimate concurrent posts; inspect at most 30 recent read-only records.
_MAX_FEED_PAGES = 3
_FEED_PAGE_SIZE = 10


def _feed_page_url(page_index: int) -> str:
    if page_index == 0:
        return _FEED_URL
    return f"{_FEED_URL}&start-index={1 + page_index * _FEED_PAGE_SIZE}"


def _normalize(value: str) -> str:
    return re.sub(r"\W+", " ", unescape(value).casefold(), flags=re.UNICODE).strip()


def _read_public(url: str, *, get) -> requests.Response:
    response = get(url, timeout=(4, 12), allow_redirects=False,
                   headers={"User-Agent": "CYBERDUDEBIVASH-CTI-DeliveryVerifier/1.0",
                            "Cache-Control": "no-cache"})
    if response.status_code != 200:
        raise ValueError(f"public_http_{response.status_code}")
    return response


def verify_public_delivery(report: dict, *, http_get=None,
                           attempts: int = 4, sleep_seconds: int = 8,
                           sleeper=time.sleep) -> dict:
    """Return PASS/FAIL with bounded retries and no side effects.

    Run status is separate from API success; an actual post can be live even
    when independent public delivery is temporarily degraded. This function
    never republishes or marks the ledger as rolled back.
    """
    if report.get("dry_run"):
        return {"status": "SKIPPED_DRY_RUN", "verified": 0}
    posts = [p for p in report.get("posts", []) if p.get("status") == "published"]
    if not posts or len(posts) != int(report.get("published", 0)):
        return {"status": "FAIL", "reason": "no_consistent_live_publication_receipts", "verified": 0}
    for post in posts:
        url = str(post.get("blogger_url") or "")
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname != _PUBLIC_HOST
                or not re.fullmatch(r"/20\d\d/\d\d/[a-z0-9-]+\.html", parsed.path)
                or parsed.query or parsed.fragment or parsed.username or parsed.password
                or parsed.port is not None or not str(post.get("blogger_post_id") or "").isdigit()):
            return {"status": "FAIL", "reason": "invalid_public_receipt_url_or_id", "verified": 0}

    get = http_get or requests.get
    last_reason = "public_delivery_unverified"
    for attempt in range(1, max(1, min(6, attempts)) + 1):
        verified = 0
        try:
            for post in posts:
                page = _read_public(post["blogger_url"], get=get)
                if "text/html" not in page.headers.get("Content-Type", "").lower():
                    raise ValueError("public_post_wrong_content_type")
                if not page.content or len(page.content) > _MAX_PAGE_BYTES:
                    raise ValueError("public_post_invalid_body_size")
                expected = " ".join(_normalize(str(post.get("blogger_title") or post.get("title") or "")).split()[:8])
                if not expected or expected not in _normalize(page.text):
                    raise ValueError("public_post_title_mismatch")
                verified += 1
            expected_ids = {str(post["blogger_post_id"]) for post in posts}
            observed_ids = set()
            for page_index in range(_MAX_FEED_PAGES):
                feed = _read_public(_feed_page_url(page_index), get=get)
                if not feed.content or len(feed.content) > _MAX_FEED_BYTES:
                    raise ValueError("public_feed_invalid_body_size")
                # Distinguish a malformed feed from an honest not-yet-indexed
                # record. Never accept a 200 HTML error page as feed delivery.
                entries = feed.json().get("feed", {}).get("entry", [])
                if not isinstance(entries, list):
                    raise ValueError("public_feed_invalid_entry_shape")
                observed_ids.update(
                    str(item.get("id", {}).get("$t", ""))
                    for item in entries if isinstance(item, dict)
                )
                if all(any(
                    entry.endswith("post-" + post_id) for entry in observed_ids
                ) for post_id in expected_ids):
                    break
                if not entries:
                    break
            else:
                # The bounded 30-entry window is an availability check, not
                # permission to generate more writes to force a feed match.
                pass
            if not all(any(
                entry.endswith("post-" + post_id) for entry in observed_ids
            ) for post_id in expected_ids):
                raise ValueError("public_feed_missing_new_post_id")
            return {"status": "PASS", "verified": verified, "feed": "MATCH", "attempts": attempt}
        except (requests.RequestException, ValueError, TypeError, AttributeError, KeyError, json.JSONDecodeError) as exc:
            last_reason = str(exc)[:100] if isinstance(exc, ValueError) else "public_delivery_probe_error"
            if attempt < max(1, min(6, attempts)):
                sleeper(sleep_seconds)
    return {"status": "FAIL", "verified": 0, "reason": last_reason, "attempts": max(1, min(6, attempts))}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--logs-dir", type=Path, default=Path("logs"))
    parser.add_argument("--marker", type=Path, default=Path(".current-syndication-start"))
    args = parser.parse_args()
    if not args.marker.is_file():
        print(json.dumps({"status": "FAIL", "reason": "missing_current_run_marker"}))
        return 2
    current = sorted((p for p in args.logs_dir.glob("run-*.json")
                      if p.stat().st_mtime_ns > args.marker.stat().st_mtime_ns),
                     key=lambda p: p.stat().st_mtime_ns)
    if len(current) != 1:
        print(json.dumps({"status": "FAIL", "reason": "current_run_receipt_not_unique"}))
        return 2
    try:
        report = json.loads(current[0].read_text(encoding="utf-8"))
        result = verify_public_delivery(report)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        result = {"status": "FAIL", "reason": "current_run_receipt_unreadable"}
    print("P0_BLOGGER_PUBLIC_DELIVERY=" + json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
