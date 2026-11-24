"""P0 regression: a single incidental ransomware mention must never make a post a ransomware report.

Production incident (2026-11-24, CTI Blogger): the Elastic Security 9.6 release-notes post was published
as "SOC ANALYST BRIEF / RANSOMWARE INTELLIGENCE" with a ransomware-assessment call to action. The only
mention in the vendor text was one product-feature clause ("...and Linux ransomware protection").
Root cause: three places treated a mention anywhere in the prose as primary-topic evidence, directly or
via a label that content_discovery._infer_labels derives from that same prose.
"""
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from automation.content_discovery import DiscoveredArticle, _infer_labels
from automation.premium_factory_throughput import (
    _delivery_class_from_fields,
    classify_delivery_class,
    classify_factory_family,
)
from automation.publication_scheduler import (
    classify_publication_family,
    ransomware_is_primary_topic,
    ransomware_primary_fields,
)
from automation.report_integrity import _family, build_report_context

ELASTIC_TITLE = "Press play on Elastic Security 9.6, banger after banger"
# The only vendor-supplied sentence in the published post that mentions ransomware (verified on the live page).
ELASTIC_SUMMARY = (
    "AlertZero works your alert queue in the background and nothing consequential it proposes runs until you "
    "approve it. 9.6 also brings entity resolution, MITRE ATLAS mappings, 143 AI detection rules, and Linux "
    "ransomware protection."
)


def article(title, summary="", *, labels=None, source="global_rss", publisher="Elastic Security Labs", **kw):
    return DiscoveredArticle(
        url="https://www.elastic.co/security-labs/blog/elastic-security-9-6-release-highlights",
        title=title,
        summary=summary,
        published_at=datetime.now(timezone.utc).isoformat(),
        content_hash="p0ransomwareprimary",
        labels=_infer_labels(title, summary) if labels is None else labels,
        source=source,
        source_publisher=publisher,
        **kw,
    )


def test_the_elastic_release_note_is_not_a_ransomware_report_anywhere_in_the_pipeline():
    a = article(ELASTIC_TITLE, ELASTIC_SUMMARY)
    # Precondition that made the bug: the inferred labels DO contain "Ransomware".
    assert "Ransomware" in a.labels
    assert not ransomware_is_primary_topic(a)
    assert classify_publication_family(a) != "ransomware"
    assert classify_factory_family(a) != "ransomware"
    assert classify_delivery_class(a) != "ransomware"
    family, label = _family(a)
    assert family != "ransomware_reporting" and label != "Ransomware Intelligence"
    assert build_report_context(a).family_label == "Cyber Threat Intelligence"


def test_delivery_class_fields_helper_discounts_prose_derived_labels_too():
    labels = _infer_labels(ELASTIC_TITLE, ELASTIC_SUMMARY)
    assert _delivery_class_from_fields(title=ELASTIC_TITLE, summary=ELASTIC_SUMMARY, labels=labels, source="global_rss") != "ransomware"


def test_an_explicit_ransomware_title_is_still_a_ransomware_report_in_every_classifier():
    for title in ("Ransomware gang claims attack on regional hospital", "Double extortion operation disrupts a manufacturer",
                  "New Linux ransomware targets ESXi servers"):
        a = article(title, "Details of the incident.")
        assert ransomware_is_primary_topic(a), title
        assert classify_publication_family(a) == "ransomware"
        assert classify_factory_family(a) == "ransomware"
        assert _family(a) == ("ransomware_reporting", "Ransomware Intelligence")


def test_the_typed_ransomware_source_is_unchanged():
    a = article("Akira victim claim against enterprise", "", source="ransomware_intel", labels=[])
    assert ransomware_is_primary_topic(a)
    assert _family(a) == ("ransomware_claim", "Ransomware Claim Intelligence")


def test_a_label_independent_of_the_prose_is_still_primary_evidence():
    # No ransomware wording in the title or summary, so the label cannot have been derived from them.
    a = article("Akira criminal infrastructure bulletin", "Infrastructure notes.", labels=["Threat Intelligence", "Ransomware"])
    assert ransomware_is_primary_topic(a)
    assert _family(a) == ("ransomware_reporting", "Ransomware Intelligence")


def test_a_label_that_restates_a_prose_mention_is_not_independent_even_if_it_looks_editorial():
    # Conservative by design: when the prose also says it, the label is not independent evidence.
    a = article("Platform release notes", "New this month: ransomware protection.", labels=["Threat Intelligence", "Ransomware"])
    assert not ransomware_is_primary_topic(a)


def test_callers_that_cannot_supply_text_keep_the_previous_label_behaviour():
    # summary=None (the pre-existing call shape) honours labels exactly as before.
    assert ransomware_primary_fields(title="Release notes", source="global_rss", labels=["Ransomware"])
    assert not ransomware_primary_fields(title="Release notes", source="global_rss", labels=["Threat Intelligence"])
    assert not ransomware_primary_fields(title="Release notes", source="global_rss", labels=["Ransomware"], summary="mentions ransomware once")


def test_ransomware_only_in_the_summary_stays_general_intelligence_not_ransomware():
    a = article("Defending the data center in 2027", "Backups matter because ransomware is common.")
    assert "Ransomware" in a.labels and not ransomware_is_primary_topic(a)
    assert _family(a) == ("general_intelligence", "Cyber Threat Intelligence")


def test_importing_report_integrity_first_has_no_circular_import():
    root = Path(__file__).resolve().parents[1]
    for module in ("automation.report_integrity", "automation.publication_scheduler", "automation.premium_factory_throughput"):
        done = subprocess.run([sys.executable, "-c", f"import {module}"], cwd=root, capture_output=True, text=True)
        assert done.returncode == 0, module + ": " + done.stderr[-300:]
