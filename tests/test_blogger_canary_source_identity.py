"""P0 Blogger reviewed-source identity pin tests."""
from pathlib import Path
from types import SimpleNamespace

from automation.canary_source_identity import (
    live_canary_pin_required,
    verify_reviewed_source_identity,
)

URL = "https://blog.talosintelligence.com/the-challenge-of-defending-against-bulletproof-dead-drops-on-public-blockchains/"
HASH = "0123456789abcdef"


def test_canary_gate_only_approved_manual_live_one_post(monkeypatch):
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("CDB_BLOGGER_CANARY_APPROVED", "true")
    assert live_canary_pin_required(dry_run=False, max_posts=1)
    assert not live_canary_pin_required(dry_run=True, max_posts=1)
    assert not live_canary_pin_required(dry_run=False, max_posts=4)
    monkeypatch.setenv("CDB_BLOGGER_CANARY_APPROVED", "false")
    assert not live_canary_pin_required(dry_run=False, max_posts=1)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "schedule")
    assert not live_canary_pin_required(dry_run=False, max_posts=1)


def test_exact_selected_canonical_source_identity_passes():
    items = [SimpleNamespace(url=URL, content_hash=HASH)]
    assert verify_reviewed_source_identity(items, URL, HASH) is None


def test_canary_fails_closed_if_scheduler_selects_another_source():
    items = [SimpleNamespace(url=URL + "changed", content_hash=HASH)]
    assert "differs" in verify_reviewed_source_identity(items, URL, HASH)


def test_canary_fails_closed_if_title_source_identity_changed():
    items = [SimpleNamespace(url=URL, content_hash="f" * 16)]
    assert "differs" in verify_reviewed_source_identity(items, URL, HASH)


def test_canary_fails_closed_for_zero_or_multiple_candidates():
    assert "exactly one" in verify_reviewed_source_identity([], URL, HASH)
    articles = [SimpleNamespace(url=URL, content_hash=HASH)] * 2
    assert "exactly one" in verify_reviewed_source_identity(articles, URL, HASH)


def test_canary_fails_closed_for_missing_or_malformed_pins():
    items = [SimpleNamespace(url=URL, content_hash=HASH)]
    assert "invalid" in verify_reviewed_source_identity(items, "", HASH)
    assert "invalid" in verify_reviewed_source_identity(items, URL, "")
    assert "invalid" in verify_reviewed_source_identity(items, URL, "x" * 16)
    assert "invalid" in verify_reviewed_source_identity(items, "http://example.org/", HASH)


def test_live_canary_fails_before_transform_and_cannot_backfill():
    main = (Path(__file__).resolve().parents[1] / "automation" / "main.py").read_text(encoding="utf-8")
    assert "if dry_run or canary_pin_required:" in main
    assert main.index("if canary_pin_required:\n        mismatch") < main.index("    # --- Transform and Publish ---")
    assert '"source_identity_hash": article.content_hash' in main
    assert "P0 Blogger canary identity mismatch; no publication attempted" in main
