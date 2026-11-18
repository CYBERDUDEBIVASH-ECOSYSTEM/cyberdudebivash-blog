"""P0: first-party syndication time must never launder old source dates."""
from datetime import datetime, timezone
from pathlib import Path
import inspect

from automation.content_discovery import DiscoveredArticle
from automation.cti_original_source_freshness import original_source_is_current
from automation import main as main_module

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 18, 8, 0, tzinfo=timezone.utc)


def article(*, url, rss_at="2026-11-17T12:00:00+00:00", source="rss"):
    return DiscoveredArticle(
        url=url,
        title="Example verified threat report",
        summary="Source-backed threat guidance",
        published_at=rss_at,
        content_hash="offline-test-hash",
        labels=["Threat Intelligence"],
        source=source,
    )


def page(path, original_date):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "<html><body><div><small>SOURCE PUBLICATION DATE</small>"
        f"<strong>{original_date}</strong></div></body></html>",
        encoding="utf-8",
    )


def test_actual_nov14_wired_repost_is_not_fresh_on_nov18():
    # Real observed repo artifact: own RSS says Nov 17; report's source
    # evidence independently says Nov 14; do not publish as fresh 72h CTI.
    url = ("https://blog.cyberdudebivash.in/posts/"
           "beware-the-new-ai-fueled-ransomware-boom.html")
    assert (ROOT / "posts/beware-the-new-ai-fueled-ransomware-boom.html").is_file()
    assert not original_source_is_current(
        article(url=url), 72, now=NOW, repo_root=ROOT,
    )


def test_true_recent_original_source_can_still_be_syndicated(tmp_path):
    url = "https://blog.cyberdudebivash.in/posts/new-verified-campaign.html"
    page(tmp_path / "posts/new-verified-campaign.html", "2026-11-17")
    assert original_source_is_current(
        article(url=url), 72, now=NOW, repo_root=tmp_path,
    )


def test_syndication_falls_back_to_verified_authoritative_candidate():
    from automation.publication_scheduler import select_publication_batch
    stale = article(
        url="https://blog.cyberdudebivash.in/posts/"
            "beware-the-new-ai-fueled-ransomware-boom.html"
    )
    # CISA/other source families retain their own date authority and must
    # remain eligible when a stale canonical repost is filtered.
    cisa = article(
        url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        source="cisa_kev", rss_at="2026-11-18T00:00:00+00:00",
    )
    eligible = [
        entry for entry in [stale, cisa]
        if original_source_is_current(entry, 72, now=NOW, repo_root=ROOT)
    ]
    result = select_publication_batch([], eligible, 1)
    assert result.articles == [cisa]
    assert result.metrics["canonical_selected"] == 0


def test_missing_original_date_fails_closed(tmp_path):
    path = tmp_path / "posts/no-provenance.html"
    path.parent.mkdir(parents=True)
    path.write_text("<html><body><article>Missing original evidence</article></body></html>")
    url = "https://blog.cyberdudebivash.in/posts/no-provenance.html"
    assert not original_source_is_current(article(url=url), 72, now=NOW, repo_root=tmp_path)


def test_missing_page_and_malformed_original_dates_fail_closed(tmp_path):
    url = "https://blog.cyberdudebivash.in/posts/synthetic-report.html"
    assert not original_source_is_current(article(url=url), 72, now=NOW, repo_root=tmp_path)
    path = tmp_path / "posts/synthetic-report.html"
    for raw in ("", "2026-11-99", "Nov 18 2026", "2026-11-14"):
        page(path, raw)
        assert not original_source_is_current(
            article(url=url), 72, now=NOW, repo_root=tmp_path,
        )


def test_future_source_or_repost_timestamp_denied(tmp_path):
    path = tmp_path / "posts/future.html"
    url = "https://blog.cyberdudebivash.in/posts/future.html"
    page(path, "2026-11-19")
    assert not original_source_is_current(
        article(url=url), 72, now=NOW, repo_root=tmp_path,
    )
    page(path, "2026-11-17")
    assert not original_source_is_current(
        article(url=url, rss_at="2026-11-19T12:00:00+00:00"),
        72, now=NOW, repo_root=tmp_path,
    )


def test_old_rss_clock_denied_even_if_source_is_recent(tmp_path):
    url = "https://blog.cyberdudebivash.in/posts/source-timestamp.html"
    page(tmp_path / "posts/source-timestamp.html", "2026-11-17")
    assert not original_source_is_current(
        article(url=url, rss_at="2026-11-14T12:00:00+00:00"),
        72, now=NOW, repo_root=tmp_path,
    )


def test_untrusted_first_party_url_paths_are_denied_without_file_access(tmp_path):
    for path in (
        "/posts/../secrets.html",
        "/posts/%2e%2e%2fsecrets.html",
        "/posts/this.html?leak=1",
        "/posts/this.html#fragment",
        "/posts/../../data/published_posts.json",
    ):
        url = "https://blog.cyberdudebivash.in" + path
        assert not original_source_is_current(
            article(url=url), 72, now=NOW, repo_root=tmp_path,
        )


def test_oversize_local_provenance_is_denied(tmp_path):
    url = "https://blog.cyberdudebivash.in/posts/oversized.html"
    path = tmp_path / "posts/oversized.html"
    page(path, "2026-11-17")
    path.write_text(path.read_text() + ("A" * (300 * 1024)))
    assert not original_source_is_current(
        article(url=url), 72, now=NOW, repo_root=tmp_path,
    )


def test_external_authoritative_source_is_unaffected(tmp_path):
    cisa = article(
        url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        source="cisa_kev",
    )
    assert original_source_is_current(cisa, 72, now=NOW, repo_root=tmp_path)


def test_provenance_filter_precedes_all_scheduling_and_backfill_in_runtime():
    text = inspect.getsource(main_module.run_pipeline)
    gate = text.index("original_source_is_current(article, config.max_article_age_hours)")
    selection = text.index("selection = select_publication_batch(")
    backfill = text.index("def _enqueue_quality_backfill")
    publish = text.index("# --- Transform and Publish ---")
    assert gate < selection < backfill < publish
    # Both fresh and retry pools must go through the exact same gate.
    guarded = text[text.index("original_fresh_count ="):selection]
    assert "fresh_articles = [" in guarded
    assert "retry_articles = [" in guarded
    assert guarded.count("original_source_is_current(") == 2
