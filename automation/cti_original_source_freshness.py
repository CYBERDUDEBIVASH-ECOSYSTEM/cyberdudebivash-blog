"""Fail-closed original-source date admission for first-party CTI RSS posts.

A locally generated SOC report can have a NEW RSS pubDate despite relying
solely on an older third-party story. That syndication/ingestion clock is not
the original source's publication clock and MUST NOT certify breaking intel.

This is only an eligibility filter; it never rewrites timestamps, publishes,
calls an external API or mutates the Blogger publication ledger.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

_ORIGIN_HOST = "blog.cyberdudebivash.in"
_POST_PATH = re.compile(r"^/posts/([a-z0-9][a-z0-9-]{0,119}\.html)$")
_SOURCE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MAX_POST_BYTES = 256 * 1024
_MAX_CLOCK_SKEW = timedelta(minutes=5)


def original_source_is_current(article, max_age_hours: int, *,
                               now: datetime | None = None,
                               repo_root: Path | None = None) -> bool:
    """Check original provenance, not just the first-party repost timestamp.

    Only SOC-origin '/posts/*.html' RSS/live-intel handoffs need local HTML
    provenance inspection. Other source families keep their independent
    authoritative timestamp validators and existing quality gates.
    """
    if str(getattr(article, "source", "")).lower() not in {"rss", "live_intel"}:
        return True
    try:
        url = urlsplit(str(getattr(article, "url", "")))
        if url.hostname != _ORIGIN_HOST:
            return True  # No first-party post URL: this scoped rule does not assert provenance.
        # First-party /posts paths MUST carry a valid local original-source
        # date; a missing page is NOT evidence that a repost is new.
        if not url.path.startswith("/posts/"):
            return True  # Legacy non-post URLs retain their existing admission contract.
        match = _POST_PATH.fullmatch(url.path)
        if (url.scheme != "https" or match is None or url.query or url.fragment
                or url.username is not None or url.password is not None
                or url.port is not None):
            return False
        root = (repo_root or Path(__file__).resolve().parents[1]).resolve()
        post_dir = (root / "posts").resolve()
        post_path = post_dir / match.group(1)
        if post_path.is_symlink() or not post_path.is_file():
            return False
        resolved = post_path.resolve()
        if resolved.parent != post_dir:
            return False
        size = resolved.stat().st_size
        if not (0 < size <= _MAX_POST_BYTES):
            return False
        soup = BeautifulSoup(resolved.read_text(encoding="utf-8"), "html.parser")

        # Source record label from the independent first-party SOC dossier,
        # NOT <meta article:published_time> (that is the repost clock).
        label = soup.find(
            "small", string=lambda value:
            bool(value) and value.strip().upper() == "SOURCE PUBLICATION DATE"
        )
        if label is None or label.parent is None:
            return False
        value = label.parent.find("strong")
        raw = value.get_text(strip=True) if value else ""
        if not _SOURCE_DATE.fullmatch(raw):
            return False
        source_day = datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        raw_rss = str(getattr(article, "published_at", "")).strip()
        syndication_time = datetime.fromisoformat(raw_rss.replace("Z", "+00:00"))
        if syndication_time.tzinfo is None:
            return False
        syndication_time = syndication_time.astimezone(timezone.utc)

        if now is None:
            now = datetime.now(timezone.utc)
        if now.tzinfo is None or not (0 < max_age_hours <= 24 * 30):
            return False
        now = now.astimezone(timezone.utc)
        cutoff = now - timedelta(hours=max_age_hours)

        # Both the original source day and the RSS transport date must be
        # within the allowed window. Source is date-only: use 00:00 UTC,
        # conservatively, not an invented time later in the day.
        return (
            cutoff <= source_day <= now
            and cutoff <= syndication_time <= now + _MAX_CLOCK_SKEW
            and source_day <= syndication_time
        )
    except (ValueError, OSError, UnicodeError, TypeError, OverflowError):
        return False


def retry_item_is_current(article, max_age_hours: int, *, now: datetime | None = None) -> bool:
    """Apply the discovery age limit to THIRD-PARTY items waiting in the retry queue.

    Fresh ``global_rss`` discovery drops anything older than ``max_age_hours`` (72 h), but an item
    that failed to publish is persisted and later re-selected from the retry queue with no age
    check: ``original_source_is_current`` above only inspects first-party ``rss``/``live_intel``
    handoffs. After the Nov 13-21 outage, items with source dates 7-8 days old were therefore
    published as new intelligence. The age is measured from the item's own ``published_at`` (the
    source publication time; discovery time when the feed gave none), never rewritten.

    Only ``global_rss`` is judged here: first-party handoffs keep their provenance check and typed
    connectors (NVD, CISA, ransomware/breach intel) keep their own validators. An item whose date is
    missing or unparseable is kept (same policy as discovery's ``_is_recent``). Eligibility filter
    only: no I/O, no network, no mutation.
    """
    if str(getattr(article, "source", "") or "").strip().lower() != "global_rss":
        return True
    try:
        published = datetime.fromisoformat(str(getattr(article, "published_at", "") or "").strip().replace("Z", "+00:00"))
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)  # naive stamps are written in UTC by discovery
        reference = (now or datetime.now(timezone.utc))
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
        return published.astimezone(timezone.utc) >= reference.astimezone(timezone.utc) - timedelta(hours=max_age_hours)
    except (ValueError, TypeError, OverflowError):
        return True
