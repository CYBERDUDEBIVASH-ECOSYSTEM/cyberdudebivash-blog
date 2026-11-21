"""Fail closed on publicly missing first-party SOC sources before a Blogger write.

Local RSS/source identity is not customer-facing delivery evidence. Only the
known SOC /posts/*.html origin is probed; external publishers are not crawled
or filtered here. All requests are bounded and never follow redirects.
"""
from __future__ import annotations

import re
from html import unescape
from urllib.parse import urlsplit

import requests
from bs4 import BeautifulSoup

from .cti_original_source_freshness import _ORIGIN_HOST, _POST_PATH

_MAX_SOURCE_BYTES = 384 * 1024


def _normalized(value: str) -> str:
    return re.sub(r"\W+", " ", unescape(value).casefold(), flags=re.UNICODE).strip()


def verify_public_first_party_source(article, *, http_get=None) -> str | None:
    """Return a concise block reason, or None for a verified/inapplicable URL.

    A missing or stale Worker deployment can make a locally generated SOC
    dossier visible in git/RSS while its public URL returns 404. No Blogger
    post referencing that unpublished first-party dossier is safe to release.
    """
    source_url = str(getattr(article, "url", "") or "")
    parsed = urlsplit(source_url)
    # This gate only covers canonical first-party HTML dossiers. Historical
    # non-HTML /posts/ endpoints keep their existing admission contract.
    if (parsed.hostname != _ORIGIN_HOST or not parsed.path.startswith("/posts/")
            or not parsed.path.endswith(".html")):
        return None
    if (parsed.scheme != "https" or not _POST_PATH.fullmatch(parsed.path)
            or parsed.query or parsed.fragment or parsed.username is not None
            or parsed.password is not None or parsed.port is not None):
        return "invalid_first_party_source_url"
    try:
        get = http_get or requests.get
        response = get(
            source_url, timeout=(3, 8), allow_redirects=False,
            headers={"User-Agent": "CYBERDUDEBIVASH-SyndicationBot/1.0",
                     "Cache-Control": "no-cache"},
        )
    except requests.RequestException:
        return "first_party_source_unreachable"
    except (ValueError, TypeError):
        return "first_party_source_probe_error"
    if response.status_code != 200:
        return f"first_party_source_http_{response.status_code}"
    if "text/html" not in response.headers.get("Content-Type", "").lower():
        return "first_party_source_wrong_content_type"
    body = response.content
    if not body or len(body) > _MAX_SOURCE_BYTES:
        return "first_party_source_invalid_body_size"
    try:
        soup = BeautifulSoup(body, "html.parser")
        meta = soup.find("meta", attrs={"property": "og:url"})
        canonical = soup.find("link", rel="canonical")
        claimed_urls = {
            str(node.get(attr, "")) for node, attr in (
                (meta, "content"), (canonical, "href")
            ) if node is not None
        }
        if source_url not in claimed_urls:
            return "first_party_source_canonical_mismatch"
        expected = " ".join(_normalized(str(getattr(article, "title", ""))).split()[:8])
        if not expected or expected not in _normalized(soup.get_text(" ", strip=True)):
            return "first_party_source_title_mismatch"
    except (UnicodeError, ValueError, TypeError, AttributeError):
        return "first_party_source_content_invalid"
    return None
