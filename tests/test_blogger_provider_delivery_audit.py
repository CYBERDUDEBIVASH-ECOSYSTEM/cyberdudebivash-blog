"""Offline zero-trust tests for the read-only Blogger provider/delivery audit."""
import importlib.util
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/blogger_provider_delivery_audit.py"
spec = importlib.util.spec_from_file_location("blogger_provider_delivery_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
NOW = datetime(2026, 11, 18, 16, 0, tzinfo=timezone.utc)
PID = "123456789"
URL = f"https://{audit.HOST}/2026/11/verified-story.html"


def post(age_minutes=15, *, url=URL, stamp=None):
    dt = stamp if stamp is not None else (NOW - timedelta(minutes=age_minutes)).isoformat()
    return {"id": PID, "url": url, "published": dt}


def feed(pid=PID):
    return ('{"feed":{"entry":[{"id":{"$t":"tag:blogger.com,1999:blog-2163240462341298251.post-' + pid + '"}}]}}').encode()


def public(provider, **kwargs):
    body = f'<html><a href="{URL}">report</a></html>'.encode()
    return audit.evaluate_public(provider=provider, feed_status=200, feed_location="", feed_body=feed(),
                                 desktop_status=200, desktop_body=body, mobile_status=200, mobile_body=body, **kwargs)


def test_provider_fresh_post_identity_and_utc_age():
    result = audit.validate_post([post()], NOW)
    assert result["fresh"] is True
    assert result["age_minutes"] == 15.0
    assert result["post_id"] == PID


def test_provider_staleness_and_future_timestamp_fail_closed():
    assert audit.validate_post([post(76)], NOW)["fresh"] is False
    with pytest.raises(audit.AuditFailure, match="future"):
        audit.validate_post([post(-6)], NOW)


def test_non_blogger_host_and_http_url_rejected_without_fetch():
    for url in ["https://intel.cyberdudebivash.com/x.html", "http://cti.cyberdudebivash.in/x.html", "https://cti.cyberdudebivash.in:444/x.html"]:
        with pytest.raises(audit.AuditFailure, match="identity_or_url"):
            audit.validate_post([post(url=url)], NOW)


def test_feed_and_homepage_parity():
    result = public(audit.validate_post([post()], NOW))
    assert result == {"feed":"MATCHES_PROVIDER","desktop":"MATCHES_PROVIDER","mobile":"MATCHES_PROVIDER"}


def test_feed_off_host_redirect_detected_without_follow():
    p = audit.validate_post([post()], NOW)
    body = f'<html><a href="{URL}">report</a></html>'.encode()
    result = audit.evaluate_public(provider=p, feed_status=302, feed_location="https://intel.cyberdudebivash.com/", feed_body=b"",
                                   desktop_status=200, desktop_body=body, mobile_status=200, mobile_body=body)
    assert result["feed"] == "REDIRECT_OFF_BLOGGER"


def test_missing_feed_id_or_homepage_link_not_success():
    p = audit.validate_post([post()], NOW)
    bad = audit.evaluate_public(provider=p, feed_status=200, feed_location="", feed_body=feed("987"),
                                desktop_status=200, desktop_body=b"<html></html>",
                                mobile_status=200, mobile_body=b"<html></html>")
    assert bad == {"feed":"POST_MISSING_OR_STALE","desktop":"LATEST_LINK_MISSING","mobile":"LATEST_LINK_MISSING"}


def test_missing_secrets_prevent_network_access():
    with patch.dict(audit.os.environ, {}, clear=True), patch.object(audit, "request") as req:
        with pytest.raises(audit.AuditFailure, match="missing_credential"):
            audit.run()
        req.assert_not_called()


def test_utc_without_timezone_rejected():
    with pytest.raises(audit.AuditFailure, match="timezone"):
        audit.parse_utc("2026-11-18T16:00:00")


def test_script_has_no_blogger_write_request_method():
    source = SCRIPT.read_text()
    assert 'method="POST", payload=form' in source  # Google OAuth exchange only
    assert 'urlencode({' in source
    assert '"status": "live"' in source
    assert 'method="DELETE"' not in source
    assert '/posts' in source
    assert 'method="PUT"' not in source
    assert 'method="PATCH"' not in source


def test_mobile_same_host_canonical_redirect_has_one_bounded_fetch():
    latest = audit.validate_post([post()], NOW)
    html = f'<html><a href="{URL}">report</a></html>'.encode()
    with patch.object(audit, "request", side_effect=[
        (302, "", b"", "https://cti.cyberdudebivash.in/?m=0"),
        (200, "text/html", html, ""),
    ]) as req:
        status, body, reason = audit.mobile_public_get()
    assert (status, reason) == (200, "SAME_HOST_ONE_HOP")
    assert req.call_count == 2
    result = audit.evaluate_public(
        provider=latest, feed_status=200, feed_location="", feed_body=feed(),
        desktop_status=200, desktop_body=html,
        mobile_status=status, mobile_body=body,
    )
    assert result == {
        "feed": "MATCHES_PROVIDER",
        "desktop": "MATCHES_PROVIDER",
        "mobile": "MATCHES_PROVIDER",
    }


@pytest.mark.parametrize("location", [
    "https://intel.cyberdudebivash.com/",
    "http://cti.cyberdudebivash.in/",
    "https://cti.cyberdudebivash.in:444/",
    "https://evil.example/fake",
    "https://cti.cyberdudebivash.in/2026/11/other.html",
    "https://cti.cyberdudebivash.in/?m=0&next=https://evil.example",
    "https://cti.cyberdudebivash.in/?m=1",
    "",
])
def test_mobile_untrusted_redirect_never_follows(location):
    with patch.object(audit, "request", return_value=(302, "", b"", location)) as req:
        status, body, reason = audit.mobile_public_get()
    assert status == 302
    assert body == b""
    assert reason in {"REDIRECT_UNTRUSTED", "REDIRECT_MISSING_LOCATION"}
    req.assert_called_once_with(audit.ROOT + "/?m=1")


def test_mobile_redirect_second_hop_remains_blocked():
    with patch.object(audit, "request", side_effect=[
        (302, "", b"", "/?m=0"),
        (302, "", b"", "/"),
    ]) as req:
        status, body, reason = audit.mobile_public_get()
    assert status == 302
    assert reason == "SAME_HOST_ONE_HOP"
    assert req.call_count == 2


def test_mobile_canonical_destination_without_latest_link_still_fails():
    p = audit.validate_post([post()], NOW)
    with patch.object(audit, "request", side_effect=[
        (302, "", b"", "/"),
        (200, "text/html", b"<html><a href='/old'>old</a></html>", ""),
    ]):
        status, body, _ = audit.mobile_public_get()
    result = audit.evaluate_public(
        provider=p, feed_status=200, feed_location="", feed_body=feed(),
        desktop_status=200, desktop_body=f'<a href="{URL}">new</a>'.encode(),
        mobile_status=status, mobile_body=body
    )
    assert result["mobile"] == "LATEST_LINK_MISSING"
