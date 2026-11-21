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
        if url == _FEED_URL:
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
