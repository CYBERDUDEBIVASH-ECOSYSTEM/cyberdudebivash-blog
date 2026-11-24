"""P0 regression: third-party items waiting in the retry queue obey the same source age limit as fresh discovery.

Incident (2026-11-24, CTI Blogger, audit F7): after the Nov 13-21 outage, stories whose source dates were 7-8
days old were published as new intelligence. Fresh `global_rss` discovery drops anything older than 72 h, but a
failed item is persisted and later re-selected from the retry queue, and `original_source_is_current` only
inspects first-party `rss`/`live_intel` handoffs, so the queue bypassed the age limit.
"""
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from automation.config import Config
from automation.content_discovery import ContentDiscoveryEngine, DiscoveredArticle
from automation.cti_original_source_freshness import retry_item_is_current
from automation.main import run_pipeline

NOW = datetime(2026, 11, 24, 18, 0, 0, tzinfo=timezone.utc)
H = timedelta(hours=1)


def item(published_at, source="global_rss", n=1, title="Ransomware gang breaches a regional hospital network"):
    return DiscoveredArticle(
        url=f"https://news.example.test/story-{n}",
        title=title,
        summary="Operators posted victim data after an intrusion.",
        published_at=published_at,
        content_hash=f"retryage{n}",
        labels=["CYBERDUDEBIVASH", "Threat Intelligence"],
        source=source,
        source_publisher="Example Publisher",
    )


def iso(dt):
    return dt.isoformat()


class TestRetryItemIsCurrent(unittest.TestCase):
    def check(self, article, hours=72, now=NOW):
        return retry_item_is_current(article, hours, now=now)

    def test_a_week_old_third_party_item_is_dropped(self):
        self.assertFalse(self.check(item(iso(NOW - 8 * 24 * H))))
        self.assertFalse(self.check(item(iso(NOW - 7 * 24 * H))))

    def test_a_recent_third_party_item_is_kept(self):
        self.assertTrue(self.check(item(iso(NOW - 2 * H))))
        self.assertTrue(self.check(item(iso(NOW - 71 * H))))

    def test_the_boundary_is_exactly_the_limit_like_discovery(self):
        self.assertTrue(self.check(item(iso(NOW - 72 * H))), "exactly 72 h is still current (discovery: pub_date >= cutoff)")
        self.assertFalse(self.check(item(iso(NOW - 72 * H - timedelta(seconds=1)))))

    def test_the_limit_is_the_configured_one(self):
        old = item(iso(NOW - 30 * H))
        self.assertTrue(self.check(old, hours=48))
        self.assertFalse(self.check(old, hours=24))

    def test_timestamp_formats_discovery_can_write(self):
        def formats(moment):
            ist = timezone(timedelta(hours=5, minutes=30))
            return (moment.isoformat(), moment.isoformat().replace("+00:00", "Z"),
                    moment.astimezone(ist).isoformat(), moment.replace(tzinfo=None).isoformat())
        for text in formats(NOW - 10 * 24 * H):
            self.assertFalse(self.check(item(text)), text)
        for text in formats(NOW - 2 * H):
            self.assertTrue(self.check(item(text)), text)

    def test_missing_or_unparseable_dates_are_kept_like_discovery(self):
        for bad in ("", None, "not a date", "2026-13-45T99:00:00Z"):
            self.assertTrue(self.check(item(bad)), repr(bad))

    def test_a_future_dated_item_is_kept(self):
        self.assertTrue(self.check(item(iso(NOW + 3 * H))))

    def test_other_sources_are_untouched_by_this_rule(self):
        stale = iso(NOW - 30 * 24 * H)
        for source in ("nvd", "cisa_kev", "cisa_advisory", "ransomware_intel", "breach_intel", "threat_actor_intel", "rss", "live_intel"):
            self.assertTrue(self.check(item(stale, source=source)), source)

    def test_a_naive_reference_time_is_treated_as_utc(self):
        self.assertFalse(retry_item_is_current(item(iso(NOW - 10 * 24 * H)), 72, now=NOW.replace(tzinfo=None)))
        self.assertTrue(retry_item_is_current(item(iso(NOW - H)), 72, now=NOW.replace(tzinfo=None)))

    def test_the_source_field_is_case_and_whitespace_insensitive(self):
        self.assertFalse(self.check(item(iso(NOW - 10 * 24 * H), source=" Global_RSS ")))


EMPTY_FEED = """<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>empty</title></channel></rss>"""


def make_config(tmpdir):
    cfg = Config()
    cfg.blogger_client_id = "test-client-id"
    cfg.blogger_client_secret = "test-secret"
    cfg.blogger_refresh_token = "test-refresh"
    cfg.blogger_blog_id = "test-blog-id"
    cfg.anthropic_api_key = ""
    cfg.state_file = os.path.join(tmpdir, "state.json")
    cfg.logs_dir = os.path.join(tmpdir, "logs")
    cfg.max_posts_per_run = 3
    cfg.retry_attempts = 2
    cfg.retry_base_delay = 0.01
    return cfg


class TestPipelineDropsStaleRetryItems(unittest.TestCase):
    def test_a_stale_third_party_retry_item_is_not_selected_and_is_counted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = make_config(tmpdir)
            now = datetime.now(timezone.utc)
            state = ContentDiscoveryEngine(config).state
            state.add_to_retry_queue(item(iso(now - 10 * 24 * H), n=1, title="Ransomware gang breaches a hospital (old story)"), "outage")
            state.add_to_retry_queue(item(iso(now - 2 * H), n=2, title="Backdoor found in a popular npm package"), "outage")
            state.add_to_retry_queue(item(iso(now - 200 * H), source="ransomware_intel", n=3, title="Akira victim claim against enterprise"), "outage")

            feed = MagicMock()
            feed.text = EMPTY_FEED
            feed.raise_for_status = MagicMock()
            with patch("requests.get", return_value=feed), patch("requests.post"):
                report = run_pipeline(config, dry_run=True)

            self.assertEqual(report["retry_stale_dropped"], 1)
            self.assertEqual(report["retry_candidates"], 2, "the stale global_rss item is gone; the fresh one and the typed source remain")

    def test_nothing_is_dropped_when_the_queue_is_current(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = make_config(tmpdir)
            now = datetime.now(timezone.utc)
            ContentDiscoveryEngine(config).state.add_to_retry_queue(item(iso(now - H), n=9), "transient")
            feed = MagicMock()
            feed.text = EMPTY_FEED
            feed.raise_for_status = MagicMock()
            with patch("requests.get", return_value=feed), patch("requests.post"):
                report = run_pipeline(config, dry_run=True)
            self.assertEqual(report["retry_stale_dropped"], 0)
            self.assertEqual(report["retry_candidates"], 1)


if __name__ == "__main__":
    unittest.main()
