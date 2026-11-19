from automation.editorial_quarantine import editorial_quarantine_reason as reason

URL = "https://blog.cyberdudebivash.in/posts/attackiq-research-reveals-how-iranian-cyber-groups-hand-off.html"


def test_known_unreviewed_record_held():
    assert "P0 editorial hold" in reason(URL)


def test_tracking_query_does_not_bypass_hold():
    assert reason(URL + "?utm_medium=rss#report") == reason(URL)


def test_unrelated_report_not_blocked():
    assert reason("https://blog.cyberdudebivash.in/posts/another-verified-story.html") is None


def test_external_primary_source_not_blocked():
    assert reason("https://www.attackiq.com/resources/press-release/iranian-cyber-groups-network-access-handoffs-destructive-attacks/") is None


def test_hostname_spoof_or_transport_change_not_bypass():
    assert reason("https://blog.cyberdudebivash.in.attacker.example" + URL.split(".in", 1)[1]) is None
    assert reason(URL.replace("https://", "http://")) is None


def test_invalid_source_url_is_safe():
    assert reason("https://blog.cyberdudebivash.in:444" + URL.split(".in", 1)[1]) is None
    assert reason("not a URL") is None
    assert reason(None) is None


def test_main_filters_quarantine_before_scheduling():
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "automation" / "main.py"
    script = path.read_text(encoding="utf-8")
    anchor = "selection = select_publication_batch(\n        retry_articles,\n        fresh_articles,\n        config.max_posts_per_run,"
    assert "from .editorial_quarantine import editorial_quarantine_reason" in script
    assert script.index('report["editorial_quarantined"]') < script.index(anchor)
    assert script.count("if not editorial_quarantine_reason(article.url)") == 2
