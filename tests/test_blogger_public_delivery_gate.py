import json
import re
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


# --- Blogger public-propagation latency (run 45586615239, 2026-11-25 09:39Z) ------------------------------------
# A brand-new post can answer its public permalink with a redirect (HTTP 302) for longer than the gate's old fixed
# 4 x 8 s patience. Evidence: four runs verified in under 2 s, one needed the 4th of 4 attempts, and one failed all 4
# with `public_http_302` although the posts were live, 200, and in the public feed an hour later. The read-back must
# wait out Blogger's variable propagation (bounded backoff) and still fail closed if delivery really does not appear.
from types import SimpleNamespace as _NS  # noqa: E402


def _redirect(location="https://cti.cyberdudebivash.in/search?updated-max=2026-11-25"):
    return _NS(status_code=302, headers={"Location": location}, content=b"", text="", json=lambda: {})


def _lagging_get(not_ready_reads, *, not_ready=None):
    """Public permalink answers `not_ready` for the first N reads, then the real page; the feed always has the id."""
    state = {"reads": 0}
    def get(url, **kw):
        if url.startswith(_FEED_URL):
            return resp(json.dumps({"feed": {"entry": [{"id": {"$t": "tag:blogger.com,1999:blog-1.post-" + ID}}]}}),
                        "application/json")
        state["reads"] += 1
        if state["reads"] <= not_ready_reads:
            return not_ready() if callable(not_ready) else _redirect()
        return resp(f"<html><h1>{TITLE}</h1></html>")
    get.state = state
    return get


def _run(get, **kw):
    slept = []
    result = verify_public_delivery(REPORT, http_get=get, sleeper=slept.append, **kw)
    return result, slept


@pytest.mark.parametrize("not_ready_reads", [0, 1, 3, 4, 5])
def test_default_budget_rides_out_blogger_propagation_lag(not_ready_reads):
    # 4 not-ready reads is exactly the observed failure (> 24 s of lag); 5 is the last read the budget allows.
    result, slept = _run(_lagging_get(not_ready_reads))
    assert result["status"] == "PASS", (result, slept)
    assert result["attempts"] == not_ready_reads + 1
    assert len(slept) == not_ready_reads


def test_a_read_that_never_succeeds_still_fails_closed_after_a_bounded_budget():
    result, slept = _run(_lagging_get(99))
    assert result["status"] == "FAIL" and result["verified"] == 0
    assert result["attempts"] == 6
    assert slept == [8, 16, 30, 30, 30]          # literal schedule, 114 s in total
    assert sum(slept) == 114
    assert result["reason"].startswith("public_http_302")


def test_retry_delays_double_from_the_base_and_are_capped_at_30_seconds():
    _result, slept = _run(_lagging_get(99), attempts=6, sleep_seconds=5)
    assert slept == [5, 10, 20, 30, 30]
    _result, slept = _run(_lagging_get(99), attempts=3, sleep_seconds=0)
    assert slept == [0, 0]                        # a zero base (as the existing tests use) never sleeps


def test_a_first_attempt_success_never_sleeps():
    result, slept = _run(_lagging_get(0))
    assert result["status"] == "PASS" and result["attempts"] == 1 and slept == []


def test_attempts_remain_hard_capped_at_six():
    result, slept = _run(_lagging_get(99), attempts=50)
    assert result["attempts"] == 6 and len(slept) == 5


def test_failure_reason_names_the_redirect_destination_without_its_query():
    result, _slept = _run(_lagging_get(99), attempts=1)
    assert result["reason"] == "public_http_302 -> cti.cyberdudebivash.in/search"
    assert "updated-max" not in result["reason"]


def test_redirect_destination_is_sanitised_before_it_reaches_the_log():
    # The payload comes FIRST so it survives the length bound and really reaches the sanitiser.
    hostile = "https://evil.example/a\r\nX-Injected: 1 %0d%0a <b>script</b>"
    result, _slept = _run(_lagging_get(99, not_ready=lambda: _redirect(hostile)), attempts=1)
    destination = result["reason"].split(" -> ", 1)[1]
    assert destination == "evil.example/aX-Injected10d0abscript/b"
    assert re.fullmatch(r"[A-Za-z0-9._/~-]+", destination)


def test_redirect_destination_is_length_bounded():
    result, _slept = _run(_lagging_get(99, not_ready=lambda: _redirect("https://evil.example/" + "a" * 500)), attempts=1)
    destination = result["reason"].split(" -> ", 1)[1]
    assert len(destination) == 60 and len(result["reason"]) <= 100


def test_only_redirects_get_a_destination_hint():
    not_found = lambda: _NS(status_code=404, headers={"Location": "https://x.example/p"}, content=b"", text="", json=lambda: {})
    result, _slept = _run(_lagging_get(99, not_ready=not_found), attempts=1)
    assert result["reason"] == "public_http_404"
    no_location = lambda: _NS(status_code=302, headers={}, content=b"", text="", json=lambda: {})
    result, _slept = _run(_lagging_get(99, not_ready=no_location), attempts=1)
    assert result["reason"] == "public_http_302"


def test_slow_or_hung_requests_cannot_stretch_a_failure_past_the_total_time_budget():
    # Fake clock: every request takes 60 s and the sleeper advances time. Budget 150 s:
    #   attempt 1 ends t=60, +8 -> 68 ok;  attempt 2 ends t=128, +16 -> 144 ok;  attempt 3 ends t=204, +30 > 150 -> stop.
    clock = {"t": 0.0}
    inner = _lagging_get(99)
    def slow_get(url, **kw):
        clock["t"] += 60
        return inner(url, **kw)
    slept = []
    def sleeper(seconds):
        slept.append(seconds)
        clock["t"] += seconds
    result = verify_public_delivery(REPORT, http_get=slow_get, sleeper=sleeper, clock=lambda: clock["t"])
    assert result["status"] == "FAIL" and result["attempts"] == 3
    assert result["time_budget_exhausted"] is True
    assert result["reason"].startswith("public_http_302")
    assert slept == [8, 16]


def test_the_time_budget_does_not_interfere_with_normal_backoff():
    result, slept = _run(_lagging_get(99))
    assert result["attempts"] == 6 and "time_budget_exhausted" not in result and slept == [8, 16, 30, 30, 30]


def test_the_time_budget_is_a_plain_parameter_with_a_150_second_default():
    import inspect
    from automation import blogger_public_delivery_gate as gate
    assert inspect.signature(gate.verify_public_delivery).parameters["max_total_seconds"].default == 150


def _timed(request_seconds, **kw):
    clock = {"t": 0.0}
    inner = _lagging_get(99)
    def get(url, **k):
        clock["t"] += request_seconds
        return inner(url, **k)
    slept = []
    def sleeper(seconds):
        slept.append(seconds); clock["t"] += seconds
    return verify_public_delivery(REPORT, http_get=get, sleeper=sleeper, clock=lambda: clock["t"], **kw), slept


def test_time_budget_boundary_exactly_at_the_limit_still_retries():
    # attempt 1 ends t=142; 142 + 8 = 150 is NOT over the 150 s budget, so it sleeps and tries again.
    result, slept = _timed(142)
    assert slept[:1] == [8] and result["attempts"] == 2 and result["time_budget_exhausted"] is True


def test_the_upcoming_delay_counts_towards_the_time_budget():
    # attempt 1 ends t=140 (still under 150) but the next delay (16 s) would end at 156 > 150, so it must not sleep.
    result, slept = _timed(140, sleep_seconds=16)
    assert slept == [] and result["attempts"] == 1 and result["time_budget_exhausted"] is True
