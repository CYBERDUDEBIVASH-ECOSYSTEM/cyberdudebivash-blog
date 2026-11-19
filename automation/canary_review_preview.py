"""Prepare inspectable non-publishing evidence for one reviewed Blogger canary.

The preview is NOT a publication approval or a reusable certified artifact.
It records the exact HTML produced by this specific dry-run for editorial
review. Production still regenerates and re-certifies its own HTML.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from .report_integrity import PublicationIntegrityError, compute_artifact_hash


def write_canary_dry_run_review(article, transformed: dict, logs_dir: str, family: str) -> dict:
    """Write one local, untracked HTML-as-text preview and provenance manifest."""
    source_url = str(article.url or "")
    parsed = urlsplit(source_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise PublicationIntegrityError(["review preview requires an HTTPS source URL"])

    html = transformed.get("content")
    if not isinstance(html, str) or not html:
        raise PublicationIntegrityError(["review preview requires non-empty certified HTML"])

    computed_sha256 = compute_artifact_hash(html)
    certified_sha256 = transformed.get("certified_artifact_hash")
    if computed_sha256 != certified_sha256:
        raise PublicationIntegrityError(["review preview artifact differs from certified HTML"])

    source_identity = str(article.content_hash or "")
    if len(source_identity) != 16 or any(ch not in "0123456789abcdef" for ch in source_identity):
        raise PublicationIntegrityError(["review preview requires an exact 16-hex source identity"])

    manifest = {
        "status": "DRY_RUN_REVIEW_ONLY",
        "blogger_write_attempted": False,
        "source_url": source_url,
        "source_title": str(article.title or ""),
        "source_published_at": str(article.published_at or ""),
        "source_publisher": str(article.source_publisher or ""),
        "source_identity_hash": source_identity,
        "scheduler_family": str(family or ""),
        "blogger_title": str(transformed.get("title") or ""),
        "blogger_labels": list(transformed.get("labels") or []),
        "generated_at": str(transformed.get("generated_at") or ""),
        "report_id": str(transformed.get("report_id") or ""),
        "achieved_tier": str(transformed.get("achieved_tier") or ""),
        "content_source": str(transformed.get("content_source") or ""),
        "reviewed_html_sha256": computed_sha256,
        "certified_artifact_hash_match": True,
        "content_length_bytes": len(html.encode("utf-8")),
        "approval": "NOT_GRANTED",
        "note": (
            "This records the exact dry-run output; a later live run may generate "
            "different content. Its output must independently pass final integrity "
            "checks, source-pinning and public fetch-back. No authorization implied."
        ),
    }
    target = Path(logs_dir) / "canary-review"
    target.mkdir(parents=True, exist_ok=True)
    # .txt prevents accidental execution of untrusted HTML if opened locally.
    (target / "rendered-article.html.txt").write_text(html, encoding="utf-8")
    (target / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return manifest
