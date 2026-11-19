"""Incident-scoped, read-only quarantine of explicitly reviewed unsafe CTI records.

Containment is a separate operator decision from the automated quality score.
Each entry must carry an evidence-backed reason and be removed only after
editorial remediation, independent review and a new successful dry run.
"""
from __future__ import annotations

from urllib.parse import unquote, urlsplit

_P0_HOLDS: dict[tuple[str, str], str] = {
    (
        "blog.cyberdudebivash.in",
        "/posts/attackiq-research-reveals-how-iranian-cyber-groups-hand-off.html",
    ): (
        "P0 editorial hold: source dossier conflates the reporting outlet "
        "Dark Reading with affected technology and makes unsupported "
        "event-specific ransomware/encryption assertions"
    ),
}


def editorial_quarantine_reason(source_url: str) -> str | None:
    """Return a recorded hold reason for one canonical first-party report URL.

    Ignore query/fragment so tracking parameters cannot bypass the hold.
    Never quarantine another origin or a merely similar source title.
    """
    if not isinstance(source_url, str):
        return None
    try:
        parsed = urlsplit(source_url.strip())
        if parsed.scheme.lower() != "https" or parsed.port not in (None, 443):
            return None
        return _P0_HOLDS.get(((parsed.hostname or "").lower(), unquote(parsed.path)))
    except ValueError:
        return None
