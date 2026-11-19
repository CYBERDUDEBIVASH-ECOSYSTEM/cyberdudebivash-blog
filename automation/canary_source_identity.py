"""P0: pin a manual one-post live Blogger canary to a reviewed dry-run source.

This matches first-party discovery's 16-hex URL+title identity hash. It is
NOT a rendered-artifact SHA; the existing exact artifact certification and
provider fetch-back remain separate mandatory release checks.
"""
from __future__ import annotations

import os
import re
from collections.abc import Sequence

_ID_RE = re.compile(r"^[0-9a-f]{16}$")


def live_canary_pin_required(*, dry_run: bool, max_posts: int) -> bool:
    return (
        not dry_run
        and max_posts == 1
        and os.getenv("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and os.getenv("CDB_BLOGGER_CANARY_APPROVED") == "true"
    )


def verify_reviewed_source_identity(
    articles: Sequence,
    expected_url: str,
    expected_hash: str,
) -> str | None:
    """Return a reason to fail closed; no network access or Blogger writes."""
    if not expected_url.startswith("https://") or not _ID_RE.fullmatch(expected_hash):
        return "missing or invalid approved canary source URL/identity hash"
    if len(articles) != 1:
        return "one-post canary requires exactly one selected source"
    candidate = articles[0]
    if str(candidate.url) != expected_url or str(candidate.content_hash) != expected_hash:
        return "selected source identity differs from the reviewed dry-run candidate"
    return None
