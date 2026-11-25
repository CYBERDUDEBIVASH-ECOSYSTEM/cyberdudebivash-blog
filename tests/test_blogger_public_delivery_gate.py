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


# --- Google's anti-abuse interstitial (runs 9317/9318/9320/9321, 2026-11-25) -------------------------------------
# The "propagation lag" diagnosis was wrong. The redirect destination added to the failure reason by the previous
# change showed what the runner actually receives: `public_http_302 -> www.google.com/sorry/index`, Google's "unusual
# traffic" interstitial, which lasted longer than the whole 114 s backoff. The posts were live and correct (200 from any
# other network, exact content match through the authenticated Blogger API). A provider's bot challenge against a CI
# runner is inconclusive, not proof of a failed delivery (the same convention freshness-check.yml already applies to
# HTTP 429). Only that exact condition is downgraded, and only when the pipeline's own authenticated fetch-back
# verified every post with an exact content match. Everything else still fails closed.
import sys  # noqa: E402

from automation import blogger_public_delivery_gate as gate  # noqa: E402

SORRY = "https://www.google.com/sorry/index?continue=https://cti.cyberdudebivash.in/2026/11/x.html&q=EgQ"


def _fb(**over):
    base = {"post_id": ID, "fetched": True, "verified": True, "defects": [], "intended_content_length": 150448,
            "live_content_length": 150448, "exact_content_match": True, "error": ""}
    base.update(over)
    return base


def _api_report(fetch_back=None, discrepancies=0, drop=()):
    fb = _fb() if fetch_back is None else fetch_back
    fb = {k: v for k, v in fb.items() if k not in drop} if isinstance(fb, dict) else fb
    return {"dry_run": False, "published": 1, "fetch_back_discrepancies": discrepancies,
            "posts": [{**POST, "fetch_back": fb}]}


def _blocked(location=SORRY):
    return _lagging_get(99, not_ready=lambda: _redirect(location))


def _verify(report, get, **kw):
    slept = []
    return verify_public_delivery(report, http_get=get, sleeper=slept.append, **kw), slept


def test_google_block_with_api_verified_posts_is_a_degraded_pass_with_no_hammering():
    get = _blocked()
    result, slept = _verify(_api_report(), get)
    assert result["status"] == "PASS_DEGRADED"
    assert result["public_edge"] == "blocked_by_provider" and result["api_verified"] == 1 and result["verified"] == 0
    assert result["reason"] == "public_http_302 -> www.google.com/sorry/index"
    assert result["attempts"] == 3 and slept == [8, 16]
    assert get.state["reads"] == 3, "a bot challenge must not be hammered"


@pytest.mark.parametrize("report", [
    pytest.param(_api_report(fetch_back=False), id="no fetch_back at all"),
    pytest.param(_api_report(drop=("fetched",)), id="fetched missing"),
    pytest.param(_api_report(fetch_back=_fb(fetched=False)), id="not fetched"),
    pytest.param(_api_report(fetch_back=_fb(verified=False)), id="not verified"),
    pytest.param(_api_report(fetch_back=_fb(exact_content_match=False)), id="content mismatch"),
    pytest.param(_api_report(drop=("exact_content_match",)), id="match flag missing"),
    pytest.param(_api_report(fetch_back=_fb(defects=["truncated"])), id="defects present"),
    pytest.param(_api_report(fetch_back=_fb(post_id="999")), id="verified a different post id"),
    pytest.param(_api_report(discrepancies=1), id="run-level discrepancy"),
    pytest.param(_api_report(fetch_back=_fb(verified="true")), id="truthy but not boolean True"),
])
def test_a_block_without_exact_api_evidence_fails_closed(report):
    result, _slept = _verify(report, _blocked())
    assert result["status"] == "FAIL" and result["api_fetch_back"] == "unverified"
    assert result["reason"] == "public_http_302 -> www.google.com/sorry/index"


def test_a_redirect_anywhere_else_still_fails_closed_after_the_full_backoff_even_with_api_evidence():
    result, slept = _verify(_api_report(), _blocked("https://cti.cyberdudebivash.in/search"))
    assert result["status"] == "FAIL" and result["attempts"] == 6
    assert slept == [8, 16, 30, 30, 30] and "api_fetch_back" not in result


@pytest.mark.parametrize("location", [
    "https://www.google.com.evil.example/sorry/index",
    "https://evilgoogle.com/sorry/index",
    "https://accounts.google.com/sorry/index",
    "https://www.google.com/search?q=sorry",
    "https://www.google.com/sorrynot/index",
    "https://www.google.com/",
    "/sorry/index",                                  # relative: no host to trust
    "ftp://www.google.com/sorry/index",
])
def test_look_alike_and_other_google_redirects_are_not_treated_as_the_block(location):
    result, _slept = _verify(_api_report(), _blocked(location))
    assert result["status"] == "FAIL" and result["attempts"] == 6 and "public_edge" not in result


def test_both_google_hosts_and_the_bare_sorry_path_count_as_the_block():
    for location in ("https://google.com/sorry/index", "http://www.google.com/sorry", "https://WWW.GOOGLE.COM/sorry/index?x=1"):
        result, _slept = _verify(_api_report(), _blocked(location))
        assert result["status"] == "PASS_DEGRADED", location


def test_a_block_that_clears_gives_a_real_public_pass_not_a_degraded_one():
    result, slept = _verify(_api_report(), _lagging_get(2, not_ready=lambda: _redirect(SORRY)))
    assert result["status"] == "PASS" and result["verified"] == 1 and result["feed"] == "MATCH"
    assert result["attempts"] == 3 and slept == [8, 16]


def test_only_the_last_failure_decides_a_block_followed_by_a_real_failure_stays_a_failure():
    state = {"n": 0}
    def get(url, **kw):
        state["n"] += 1
        return _redirect(SORRY) if state["n"] == 1 else _NS(status_code=404, headers={}, content=b"", text="", json=lambda: {})
    result, _slept = _verify(_api_report(), get)
    assert result["status"] == "FAIL" and result["reason"] == "public_http_404" and result["attempts"] == 6


def _write_run(tmp_path):
    logs = tmp_path / "logs"
    logs.mkdir()
    marker = tmp_path / "marker"
    marker.write_text("x")
    run = logs / "run-20261125-000000.json"
    run.write_text(json.dumps(_api_report()))
    import os
    os.utime(marker, ns=(1, 1))                       # the receipt is newer than the marker
    return logs, marker


@pytest.mark.parametrize("verdict, code, warns", [
    ({"status": "PASS", "verified": 1}, 0, False),
    ({"status": "PASS_DEGRADED", "verified": 0, "api_verified": 4, "public_edge": "blocked_by_provider",
      "reason": "public_http_302 -> www.google.com/sorry/index", "attempts": 3}, 0, True),
    ({"status": "FAIL", "verified": 0, "reason": "public_http_404", "attempts": 6}, 2, False),
])
def test_cli_exit_code_and_provider_block_warning(tmp_path, monkeypatch, capsys, verdict, code, warns):
    logs, marker = _write_run(tmp_path)
    monkeypatch.setattr(gate, "verify_public_delivery", lambda report: verdict)
    monkeypatch.setattr(sys, "argv", ["gate", "--logs-dir", str(logs), "--marker", str(marker)])
    assert gate.main() == code
    out = capsys.readouterr().out
    assert "P0_BLOGGER_PUBLIC_DELIVERY=" in out
    assert ("::warning title=Blogger public read-back blocked by provider" in out) is warns
    if warns:
        assert "not proof of a failed delivery" in out and "4" in out


def test_block_concluded_by_a_smaller_attempt_budget_or_the_time_budget_gets_the_same_decision():
    degraded, slept = _verify(_api_report(), _blocked(), attempts=2)
    assert degraded["status"] == "PASS_DEGRADED" and degraded["attempts"] == 2 and slept == [8]
    ticks = iter(range(0, 10_000, 200))               # every clock() call advances 200 s: budget gone after attempt 1
    timed, slept = _verify(_api_report(), _blocked(), clock=lambda: next(ticks))
    assert timed["status"] == "PASS_DEGRADED" and timed["attempts"] == 1 and timed["time_budget_exhausted"] is True
    assert slept == []
    ticks = iter(range(0, 10_000, 200))
    unproven, _ = _verify(_api_report(fetch_back=False), _blocked(), clock=lambda: next(ticks))
    assert unproven["status"] == "FAIL" and unproven["api_fetch_back"] == "unverified"


def test_missing_defects_list_is_not_evidence():
    result, _slept = _verify(_api_report(drop=("defects",)), _blocked())
    assert result["status"] == "FAIL" and result["api_fetch_back"] == "unverified"


def test_every_post_needs_its_own_evidence_when_several_were_published():
    second = {**POST, "blogger_post_id": "2222222222222222222", "blogger_url": URL.replace(".html", "-b.html")}
    good, bad = {**POST, "fetch_back": _fb()}, {**second, "fetch_back": _fb(post_id="2222222222222222222", verified=False)}
    report = {"dry_run": False, "published": 2, "fetch_back_discrepancies": 0, "posts": [good, bad]}
    assert _verify(report, _blocked())[0]["status"] == "FAIL"
    bad["fetch_back"] = _fb(post_id="2222222222222222222")
    result, _slept = _verify(report, _blocked())
    assert result["status"] == "PASS_DEGRADED" and result["api_verified"] == 2


@pytest.mark.parametrize("fetch_back", [
    pytest.param(_fb(fetched="yes"), id="fetched truthy string"),
    pytest.param(_fb(fetched=1), id="fetched integer 1"),
    pytest.param(_fb(exact_content_match=1), id="match integer 1"),
])
def test_evidence_flags_must_be_the_boolean_true(fetch_back):
    result, _slept = _verify(_api_report(fetch_back=fetch_back), _blocked())
    assert result["status"] == "FAIL" and result["api_fetch_back"] == "unverified"


@pytest.mark.parametrize("discrepancies", [None, False, "0", 0.0, "", []])
def test_run_level_discrepancy_counter_must_be_present_and_the_integer_zero(discrepancies):
    report = _api_report()
    if discrepancies is None:
        report.pop("fetch_back_discrepancies")
    else:
        report["fetch_back_discrepancies"] = discrepancies
    result, _slept = _verify(report, _blocked())
    assert result["status"] == "FAIL" and result["api_fetch_back"] == "unverified", discrepancies


@pytest.mark.parametrize("status", [200 + 99, 403, 429, 503])
def test_only_a_3xx_redirect_to_the_interstitial_is_the_block(status):
    def get(url, **kw):
        return _NS(status_code=status, headers={"Location": SORRY}, content=b"", text="", json=lambda: {})
    result, _slept = _verify(_api_report(), get)
    assert result["status"] == "FAIL" and result["attempts"] == 6 and "public_edge" not in result


def test_the_warning_annotation_never_echoes_remote_derived_text(tmp_path, monkeypatch, capsys):
    logs, marker = _write_run(tmp_path)
    verdict = {"status": "PASS_DEGRADED", "verified": 0, "api_verified": 1, "public_edge": "blocked_by_provider",
               "reason": "INJECTED_MARKER\n::error::pwned", "attempts": 3}
    monkeypatch.setattr(gate, "verify_public_delivery", lambda report: verdict)
    monkeypatch.setattr(sys, "argv", ["gate", "--logs-dir", str(logs), "--marker", str(marker)])
    assert gate.main() == 0
    lines = capsys.readouterr().out.splitlines()
    assert [ln for ln in lines if "INJECTED_MARKER" in ln] == [ln for ln in lines if ln.startswith("P0_BLOGGER_PUBLIC_DELIVERY=")]
    assert not any(ln.startswith("::error") for ln in lines)
