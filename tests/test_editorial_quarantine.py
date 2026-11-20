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

# P0 #434 run 44666151995: the 20-Nov report passed transformation but its
# source permalink was 404 and four CISA KEV CVEs were absent from the
# public dossier, replaced by unrelated CVE links. Do not publish this exact
# canonical record via dry-run selection, retry or backfill until repaired.
CISA_CANARY = (
    "https://blog.cyberdudebivash.in/posts/"
    "cisa-warns-of-4-exploited-flaws-linked-to-ransomware-crypto.html"
)


def test_proven_unverifiable_cisa_canary_is_quarantined_exactly():
    assert "P0 editorial hold #434" in reason(CISA_CANARY)
    assert "HTTP 404" in reason(CISA_CANARY)
    assert reason(CISA_CANARY + "?utm_medium=rss#preview") == reason(CISA_CANARY)


def test_quarantine_does_not_block_other_cisa_sources_or_original_publisher():
    assert reason("https://thehackernews.com/2026/11/cisa-warns-of-4-exploited-flaws-linked.html") is None
    assert reason(CISA_CANARY.replace("/cisa-warns-", "/other-warns-")) is None
    assert reason("https://blog.cyberdudebivash.in.attacker.example" +
                  CISA_CANARY.split(".in", 1)[1]) is None
    assert reason(CISA_CANARY.replace("https://", "http://")) is None


def test_both_fresh_and_retry_queues_apply_exact_editorial_hold_before_scheduling():
    from pathlib import Path
    src = (Path(__file__).resolve().parents[1] / "automation" / "main.py").read_text(
        encoding="utf-8")
    assert src.count("if not editorial_quarantine_reason(article.url)") == 2
    assert src.index('report["editorial_quarantined"]') < src.index("selection = select_publication_batch(")
