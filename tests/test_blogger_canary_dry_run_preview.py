"""Review-only Blogger dry-run provenance and exact certified HTML tests."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from automation.canary_review_preview import write_canary_dry_run_review
from automation.report_integrity import compute_artifact_hash, PublicationIntegrityError


ARTICLE = SimpleNamespace(
    url="https://blog.talosintelligence.com/the-challenge-of-defending-against-bulletproof-dead-drops-on-public-blockchains/",
    title="The challenge of defending against bulletproof dead drops on public blockchains",
    published_at="2026-11-18T06:00:00Z",
    source_publisher="Cisco Talos",
    content_hash="0123456789abcdef",
)


def generated(content="<h3>Research on blockchain C2</h3><p>Source-linked summary.</p>"):
    return {
        "content": content,
        "title": "Blockchain-based malware C2 - CyberdudeBivash CTI",
        "labels": ["Malware", "Rapid Intelligence"],
        "certified_artifact_hash": compute_artifact_hash(content),
        "generated_at": "2026-11-19T09:00:00Z",
        "report_id": "CDB-CTI-REVIEW-1",
        "achieved_tier": "FLASH_READY",
        "content_source": "reportx_composer",
    }


def test_preview_exact_html_and_source_provenance_with_no_blog_state_write(tmp_path):
    data = generated()
    manifest = write_canary_dry_run_review(ARTICLE, data, str(tmp_path), "malware")
    path = tmp_path / "canary-review"
    assert (path / "rendered-article.html.txt").read_text("utf-8") == data["content"]
    loaded = json.loads((path / "manifest.json").read_text("utf-8"))
    assert manifest == loaded
    assert manifest["source_url"] == ARTICLE.url
    assert manifest["source_identity_hash"] == ARTICLE.content_hash
    assert manifest["source_published_at"] == ARTICLE.published_at
    assert manifest["scheduler_family"] == "malware"
    assert manifest["reviewed_html_sha256"] == compute_artifact_hash(data["content"])
    assert manifest["certified_artifact_hash_match"] is True
    assert manifest["approval"] == "NOT_GRANTED"
    assert manifest["blogger_write_attempted"] is False
    assert not (tmp_path / "published_posts.json").exists()


def test_mismatched_certification_fails_before_review_file_write(tmp_path):
    data = generated()
    data["certified_artifact_hash"] = "0" * 64
    with pytest.raises(PublicationIntegrityError, match="differs from certified HTML"):
        write_canary_dry_run_review(ARTICLE, data, str(tmp_path), "malware")
    assert not (tmp_path / "canary-review").exists()


def test_missing_html_fails_closed(tmp_path):
    with pytest.raises(PublicationIntegrityError, match="non-empty certified HTML"):
        write_canary_dry_run_review(ARTICLE, generated(""), str(tmp_path), "malware")
    assert not (tmp_path / "canary-review").exists()


def test_bad_source_url_or_identity_fails_closed(tmp_path):
    with pytest.raises(PublicationIntegrityError, match="HTTPS source"):
        write_canary_dry_run_review(
            SimpleNamespace(**{**vars(ARTICLE), "url": "http://example.test"}),
            generated(), str(tmp_path), "malware"
        )
    with pytest.raises(PublicationIntegrityError, match="16-hex source identity"):
        write_canary_dry_run_review(
            SimpleNamespace(**{**vars(ARTICLE), "content_hash": "invalid"}),
            generated(), str(tmp_path), "malware"
        )
    assert not (tmp_path / "canary-review").exists()


def test_manual_single_post_dry_run_is_the_only_preview_caller():
    main = (Path(__file__).resolve().parents[1] / "automation" / "main.py").read_text("utf-8")
    assert 'if publish_target == 1 and os.getenv("GITHUB_EVENT_NAME") == "workflow_dispatch":' in main
    assert main.index('if dry_run:\n                # P0: expose') < main.index('                post_result["status"] = "dry_run"')
    assert "write_canary_dry_run_review(" in main


def test_workflow_upload_is_read_only_single_post_and_short_retention():
    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/blogger-syndication.yml").read_text("utf-8")
    name = 'P0 attach source-linked canary review preview (dry run only)'
    assert name in workflow
    segment = workflow[workflow.index(name):workflow.index('      - name: "💾 Commit Publication State"')]
    assert "github.event.inputs.dry_run == 'true'" in segment
    assert "github.event.inputs.max_posts == '1'" in segment
    assert "steps.syndication_pipeline.outcome == 'success'" in segment
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in segment
    assert "path: logs/canary-review/" in segment
    assert "retention-days: 1" in segment
    assert "if-no-files-found: error" in segment
