from types import SimpleNamespace
import requests

from automation.source_delivery_guard import verify_public_first_party_source

URL = "https://blog.cyberdudebivash.in/posts/byod-ransomware-hackers-play-audio-ransom-messages-on-comput.html"
TITLE = "BYOD Ransomware Hackers Play Audio Ransom Messages on Computers Across Hospitals and Universities"
HTML = f'<html><head><meta property="og:url" content="{URL}"></head><body><h1>{TITLE}</h1></body></html>'


def article(url=URL):
    return SimpleNamespace(url=url, title=TITLE)


def response(status=200, html=HTML, mime="text/html; charset=UTF-8"):
    return SimpleNamespace(status_code=status, headers={"Content-Type": mime}, content=html.encode())


def test_valid_first_party_report_requires_public_title_and_canonical():
    opts = []
    def get(url, **kwargs):
        opts.append(kwargs)
        return response()
    assert verify_public_first_party_source(article(), http_get=get) is None
    assert opts[0]["allow_redirects"] is False
    assert opts[0]["timeout"] == (3, 8)


def test_missing_first_party_post_blocks_before_publication():
    assert verify_public_first_party_source(article(), http_get=lambda *_a, **_k: response(404)) == "first_party_source_http_404"


def test_redirect_mismatch_and_fallback_page_fail_closed():
    assert verify_public_first_party_source(article(), http_get=lambda *_a, **_k: response(302)) == "first_party_source_http_302"
    assert verify_public_first_party_source(article(), http_get=lambda *_a, **_k: response(html="<html><h1>Homepage</h1></html>")) == "first_party_source_canonical_mismatch"


def test_other_host_remains_outside_scoped_first_party_gate():
    def must_not_fetch(*_a, **_k):
        raise AssertionError("unexpected external call")
    assert verify_public_first_party_source(article("https://www.cisa.gov/news-events/alerts"), http_get=must_not_fetch) is None


def test_transient_origin_failure_is_not_mistaken_for_a_live_source():
    def timeout(*_a, **_k):
        raise requests.Timeout("private diagnostics")
    assert verify_public_first_party_source(article(), http_get=timeout) == "first_party_source_unreachable"


def test_wrong_mime_and_mismatched_title_are_blocked():
    assert verify_public_first_party_source(article(), http_get=lambda *_a, **_k: response(mime="application/json")) == "first_party_source_wrong_content_type"
    broken = HTML.replace(TITLE, "Completely different title")
    assert verify_public_first_party_source(article(), http_get=lambda *_a, **_k: response(html=broken)) == "first_party_source_title_mismatch"


def test_malformed_first_party_url_rejected_without_network():
    invalid = URL + "?redirect=https://evil.example"
    assert verify_public_first_party_source(article(invalid), http_get=lambda *_a, **_k: (_ for _ in ()).throw(AssertionError())) == "invalid_first_party_source_url"
