import json
from types import SimpleNamespace

from automation.blogger_public_delivery_gate import verify_public_delivery, _FEED_URL

URL = "https://cti.cyberdudebivash.in/2026/11/byod-ransomware-hackers-play-audio.html"
TITLE = "BYOD Ransomware Hackers Play Audio Ransom Messages on Computers Across Hospitals and Universities"
ID = "1801047306538323680"
POST = {"status": "published", "blogger_url": URL, "blogger_post_id": ID, "blogger_title": TITLE}
REPORT = {"dry_run": False, "published": 1, "posts": [POST]}


def resp(payload, mime="text/html; charset=UTF-8", status=200):
    content = payload.encode("utf-8")
    return SimpleNamespace(status_code=status, headers={"Content-Type": mime}, content=content, text=payload,
                           json=lambda: json.loads(payload))


def test_public_permalink_and_feed_need_exact_id():
    seen = []
    def get(url, **kw):
        seen.append((url,kw))
        if url == _FEED_URL:
            return resp(json.dumps({"feed": {"entry": [{"id": {"$t": "tag:blogger.com,1999:blog-999.post-" + ID}}]}}), "application/json")
        return resp(f"<html><h1>{TITLE}</h1></html>")
    result = verify_public_delivery(REPORT, http_get=get)
    assert result["status"] == "PASS" and result["verified"] == 1
    assert all(kw["allow_redirects"] is False for _url,kw in seen)


def test_api_success_does_not_hide_public_404():
    def get(url, **kwargs):
        if url == URL:
            return resp("Not found", status=404)
        raise AssertionError("feed should not be queried after broken permalink")
    result = verify_public_delivery(REPORT, http_get=get, attempts=1)
    assert result["status"] == "FAIL" and "404" in result["reason"]


def test_public_feed_must_contain_same_new_post_id():
    def get(url, **kwargs):
        if url.startswith(_FEED_URL):
            return resp(json.dumps({"feed": {"entry": [{"id": {"$t": "tag:blogger.com,1999:blog-123.post-9999"}}]}}), "application/json")
        return resp(f"<html><h1>{TITLE}</h1></html>")
    result = verify_public_delivery(REPORT, http_get=get, attempts=1)
    assert result["reason"] == "public_feed_missing_new_post_id"


def test_zero_posts_never_report_healthy_delivery():
    assert verify_public_delivery({"published": 0, "posts": [], "dry_run": False}, http_get=lambda *_a,**_k: None)["status"] == "FAIL"
    assert verify_public_delivery({"published": 0, "posts": [], "dry_run": True}, http_get=lambda *_a,**_k: None)["status"] == "SKIPPED_DRY_RUN"


def test_invalid_egress_host_is_rejected_before_network():
    bad = {"published": 1, "posts": [{**POST, "blogger_url": "https://evil.example/2026/11/bad.html"}]}
    assert verify_public_delivery(bad, http_get=lambda *_a, **_k: (_ for _ in ()).throw(AssertionError()))["reason"] == "invalid_public_receipt_url_or_id"


def test_public_probe_retries_then_verifies():
    calls = [0]
    def get(url, **kw):
        if url == _FEED_URL:
            return resp(json.dumps({"feed": {"entry": [{"id": {"$t": "tag:blogger.com,1999:blog-123.post-"+ID}}]}}),"application/json")
        calls[0] += 1
        if calls[0] == 1:
            return resp("404", status=404)
        return resp(f"<html>{TITLE}</html>")
    result = verify_public_delivery(REPORT, http_get=get, attempts=2, sleep_seconds=0, sleeper=lambda *_a: None)
    assert result["status"] == "PASS" and result["attempts"] == 2



def test_bounded_pagination_recognizes_concurrently_displaced_post():
    from automation.blogger_public_delivery_gate import _feed_page_url
    checked = []
    def get(url, **kwargs):
        checked.append(url)
        if url == _FEED_URL:
            return resp(json.dumps({"feed": {"entry": [{"id": {"$t": "tag:blogger.com,1999:blog-123.post-9999"}}]}}), "application/json")
        if url == _feed_page_url(1):
            return resp(json.dumps({"feed": {"entry": [{"id": {"$t": "tag:blogger.com,1999:blog-123.post-" + ID}}]}}), "application/json")
        assert url == URL
        return resp(f"<html><h1>{TITLE}</h1></html>")
    result = verify_public_delivery(REPORT, http_get=get, attempts=1)
    assert result["status"] == "PASS"
    assert _feed_page_url(1) in checked and _feed_page_url(2) not in checked


def test_feed_search_is_bounded_to_three_read_only_pages():
    from automation.blogger_public_delivery_gate import _feed_page_url
    checked = []
    def get(url, **kwargs):
        checked.append(url)
        if url.startswith(_FEED_URL):
            return resp(json.dumps({"feed": {"entry": [{"id": {"$t": "tag:blogger.com,1999:blog-123.post-9999"}}]}}), "application/json")
        return resp(f"<html><h1>{TITLE}</h1></html>")
    result = verify_public_delivery(REPORT, http_get=get, attempts=1)
    assert result["status"] == "FAIL"
    assert result["reason"] == "public_feed_missing_new_post_id"
    assert len(checked) == 4
    assert checked[1:] == [_feed_page_url(0), _feed_page_url(1), _feed_page_url(2)]


# --- Blogger permalink disambiguation (run 9310, 2026-11-25) ------------------------------------------------
# When two posts in the same month would share a truncated slug, Blogger keeps the first slug and gives the
# next one a "_<digits>" suffix (e.g. ...-new-victim_0276498592.html). The gate used to reject that shape as
# an invalid receipt, which failed the whole run (and skipped public verification of the run's OTHER posts)
# even though the post was live and correct. About 12% of published permalinks have this shape.
import pytest  # noqa: E402

REAL_DISAMBIGUATED_PERMALINKS = [
    # Shapes taken from real published receipts in logs/run-*.json.
    "/2026/07/cisa-adds-one-known-exploited_01329694327.html",
    "/2026/07/thegentlemen-ransomware-claims-new_0766487583.html",
    "/2026/11/pixelleaks-ransomware-claims-new-victim_0276498592.html",
]


def _healthy_get(post_id, title):
    def get(url, **kw):
        if url == _FEED_URL:
            return resp(json.dumps({"feed": {"entry": [{"id": {"$t": "tag:blogger.com,1999:blog-1.post-" + post_id}}]}}),
                        "application/json")
        return resp(f"<html><h1>{title}</h1></html>")
    return get


@pytest.mark.parametrize("path", REAL_DISAMBIGUATED_PERMALINKS)
def test_blogger_disambiguated_permalink_is_a_valid_receipt(path):
    url = "https://cti.cyberdudebivash.in" + path
    report = {"dry_run": False, "published": 1,
              "posts": [{**POST, "blogger_url": url}]}
    result = verify_public_delivery(report, http_get=_healthy_get(ID, TITLE), attempts=1)
    assert result["status"] == "PASS" and result["verified"] == 1, result


@pytest.mark.parametrize("path", [
    "/2026/11/Upper-Case.html",            # slug stays lower-case
    "/2026/11/bad_.html",                  # suffix needs digits
    "/2026/11/bad_abc.html",               # suffix is digits only
    "/2026/11/bad_1_2.html",               # at most one suffix
    "/2026/11/_1.html",                    # a slug is required before the suffix
    "/2026/11/a/b.html",                   # no extra path segment
    "/2026/11/../x.html",                  # no traversal
    "/2026/11/bad.html/",                  # no trailing slash
    "/2026/11/bad.htm",                    # extension is fixed
])
def test_other_malformed_permalinks_are_still_rejected_before_any_network_call(path):
    def never(*_a, **_k):
        raise AssertionError("network must not be touched for an invalid receipt")
    report = {"dry_run": False, "published": 1,
              "posts": [{**POST, "blogger_url": "https://cti.cyberdudebivash.in" + path}]}
    result = verify_public_delivery(report, http_get=never, attempts=1)
    assert result == {"status": "FAIL", "reason": "invalid_public_receipt_url_or_id", "verified": 0}


def test_a_disambiguated_permalink_does_not_disable_checks_on_the_run_s_other_posts():
    # One run, two posts: a plain permalink and a disambiguated one. A feed that lacks the second id must still FAIL
    # (the gate is relaxed for the URL shape only, never for the public-feed identity check).
    other_id = "4708022282893144074"
    report = {"dry_run": False, "published": 2, "posts": [
        {**POST},
        {**POST, "blogger_post_id": other_id,
         "blogger_url": "https://cti.cyberdudebivash.in/2026/11/pixelleaks-ransomware-claims-new-victim_0276498592.html"},
    ]}
    def get(url, **kw):
        if url.startswith(_FEED_URL):
            return resp(json.dumps({"feed": {"entry": [{"id": {"$t": "tag:blogger.com,1999:blog-1.post-" + ID}}]}}),
                        "application/json")
        return resp(f"<html><h1>{TITLE}</h1></html>")
    result = verify_public_delivery(report, http_get=get, attempts=1)
    assert result["status"] == "FAIL" and result["reason"] == "public_feed_missing_new_post_id", result
