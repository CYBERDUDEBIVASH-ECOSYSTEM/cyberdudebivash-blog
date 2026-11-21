from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from bs4 import BeautifulSoup

from automation import cti_integrity_revenue_v19_1 as v19_1
from automation.cti_integrity_revenue_v19_1_claim_semantics import install_claim_semantics_v19_1
from automation.report_integrity import PublicationIntegrityError

install_claim_semantics_v19_1()


def _source_only_fixture() -> str:
    return """
    <article>
      <h1>CVE-2026-83959 - Substance3D Sampler</h1>
      <div class="cdbd-kpi"><span>SEVERITY</span><strong>UNSPECIFIED</strong></div>
      <div class="cdbd-kpi"><span>TLP</span><strong>NOT ASSIGNED</strong></div>
      <img src="https://blog.cyberdudebivash.in/api/og?title=Test&amp;severity=HIGH&amp;cve=CVE-2026-83959">

      <div><span>CORROBORATION</span><strong>SOURCE ASSESSED</strong></div>
      <div><span>DETECTION</span><strong>GUIDANCE PRESENT</strong></div>
      <div><span>HUNTING</span><strong>GUIDANCE PRESENT</strong></div>
      <div><span>SOC PLAYBOOK</span><strong>PRESENT</strong></div>
      <div><span>EVIDENCE TIER</span><strong>FLASH_READY</strong></div>

      <section class="cdbv8-brief"><div class="cdbv8-brief-grid">
        <article><p>CVE-2026-83959. Full analysis, Sigma/YARA rules, IOCs, Attack Chain.</p></article>
      </div></section>

      <h3>Executive Summary</h3>
      <p>CVE-2026-83959. Full analysis, Sigma/YARA rules, IOCs, Attack Chain.</p>
      <h3>Verified Facts</h3>
      <ul><li>Source publisher: CYBERDUDEBIVASH</li><li>Source published: 2026-09-06T22:45:10+00:00</li></ul>
      <h3>Technical Analysis</h3>
      <p>Heap grooming may target function pointers and attempt arbitrary code execution.</p>
      <h3>MITRE ATT&amp;CK Assessment</h3>
      <p>Not established in cited evidence.</p>
      <h3>Indicators &amp; Observables</h3>
      <p>Not established in cited evidence.</p>
      <h3>Detection Engineering Guidance</h3>
      <p>Identify telemetry and validate evidence before deployment.</p>
      <h3>Threat Hunting Queries</h3>
      <p>Begin with exposure validation; no source-backed pivot is established.</p>
      <h3>SOC Analyst Playbook</h3>
      <ul><li>Validate whether the technology exists internally.</li></ul>

      <section class="cdbv18-commercial" data-astra-revenue-v18="true" data-report-family="cve_advisory">
        <div class="cdbv18-boundary">Paid tiers change delivery, not certainty.</div>
        <a data-cdb-tier="free" data-cdb-v18-cta="api_docs" href="https://blog.cyberdudebivash.in/api.html">API DOCUMENTATION</a>
        <a data-cdb-tier="starter" data-cdb-v18-cta="api_starter" href="https://blog.cyberdudebivash.in/api-dashboard.html">GET API ACCESS</a>
        <a data-cdb-tier="pro" data-cdb-v18-cta="soc_pro" href="https://blog.cyberdudebivash.in/pricing.html">UNLOCK SOC PRO</a>
        <a data-cdb-tier="enterprise" data-cdb-v18-cta="enterprise" href="https://blog.cyberdudebivash.in/pricing.html">ENTERPRISE ACCESS</a>
      </section>

      <a href="mailto:bivash@cyberdudebivash.com">Request Vulnerability Scan →</a>
      <a href="mailto:bivash@cyberdudebivash.com">Request This Assessment →</a>

      <h4>Related Intelligence Reports</h4>
      <ul><li><a href="/related.html">Google Releases Chrome Update to Patch not established as actively exploited in cited evidence V8 Zero-Day</a></li></ul>
    </article>
    """


def _context():
    return SimpleNamespace(
        report_id="CDB-CTI-2026-E235859C8BD7",
        family="cve_advisory",
        family_label="CVE Vulnerability Advisory",
    )


@pytest.mark.parametrize("family", [
    "ransomware_reporting", "ransomware_claim", "threat_actor",
    "breach_notice", "general_intelligence", "ai_security",
])
def test_source_only_non_cve_family_never_receives_vulnerability_disclaimer(family):
    html = (
        "<article><h3>Technical Analysis</h3>"
        "<p>Source-reported campaign behavior requires local validation.</p></article>"
    )
    soup = BeautifulSoup(html, "html.parser")
    context = SimpleNamespace(family=family)
    assert v19_1._label_technical_context(soup, True, context) is True
    label = soup.select_one("[data-cdb-v19-1-evidence-class]")
    assert label is not None
    text = label.get_text(" ", strip=True)
    assert "SOURCE-LINKED THREAT-ACTIVITY CONTEXT" in text
    assert "CVE" not in text
    assert "memory-corruption" not in text
    assert "customer-specific compromise" in text
    assert v19_1._label_technical_context(soup, True, context) is False
    assert len(soup.select("[data-cdb-v19-1-evidence-class]")) == 1


@pytest.mark.parametrize("family", ["cve_advisory", "cisa_kev"])
def test_source_only_cve_families_keep_existing_vulnerability_evidence_notice(family):
    soup = BeautifulSoup("<article><h3>Technical Analysis</h3><p>Review source.</p></article>", "html.parser")
    assert v19_1._label_technical_context(
        soup, True, SimpleNamespace(family=family)
    ) is True
    label = soup.select_one("[data-cdb-v19-1-evidence-class]").get_text(" ", strip=True)
    assert "GENERAL VULNERABILITY-CLASS CONTEXT" in label
    assert "CVE-specific" in label


def test_non_source_only_artifact_never_receives_generic_evidence_notice():
    soup = BeautifulSoup("<article><h3>Technical Analysis</h3><p>Validated.</p></article>", "html.parser")
    assert v19_1._label_technical_context(
        soup, False, SimpleNamespace(family="ransomware_reporting")
    ) is False
    assert not soup.select("[data-cdb-v19-1-evidence-class]")


def test_source_only_live_dossier_regressions_are_repaired_without_inventing_facts():
    rendered = v19_1.enforce_cti_integrity_revenue_v19_1(
        _source_only_fixture(),
        article=SimpleNamespace(title="CVE-2026-83959 - Substance3D Sampler"),
        context=_context(),
    )
    soup = BeautifulSoup(rendered, "html.parser")
    text = soup.get_text(" ", strip=True)

    assert v19_1.MARKER in rendered
    assert "Full analysis, Sigma/YARA rules, IOCs, Attack Chain" not in text
    assert "SOURCE_ONLY_PRELIMINARY" in text
    assert "FLASH_READY" not in text
    assert "EVIDENCE CLASS // GENERAL VULNERABILITY-CLASS CONTEXT" in text
    assert "SINGLE SOURCE" in text
    assert "GUIDANCE_ONLY" in text
    assert "GENERIC_VALIDATION_PLAYBOOK" in text

    severity = next(card for card in soup.select(".cdbd-kpi") if card.find("span").get_text(strip=True) == "SEVERITY")
    assert severity.find("strong").get_text(strip=True) == "UNSPECIFIED"
    tlp = next(card for card in soup.select(".cdbd-kpi") if card.find("span").get_text(strip=True) == "TLP")
    assert tlp.find("strong").get_text(strip=True) == "TLP:CLEAR"
    assert tlp["data-cdb-distribution-assigned-by"] == "CYBERDUDEBIVASH"

    image = soup.find("img")
    assert image["src"] == v19_1.NEUTRAL_OG_URL
    assert "severity=HIGH" not in rendered

    free = soup.select_one('a[data-cdb-tier="free"]')
    assert free["href"] == "https://blog.cyberdudebivash.in/api.html"
    for anchor in soup.select('a[data-cdb-tier="starter"],a[data-cdb-tier="pro"],a[data-cdb-tier="enterprise"]'):
        parsed = urlparse(anchor["href"])
        query = parse_qs(parsed.query)
        assert parsed.scheme == "https"
        assert parsed.netloc == "intel.cyberdudebivash.com"
        assert parsed.path == "/upgrade.html"
        assert "checkout" not in query
        assert query["plan"] == [anchor["data-cdb-tier"]]
        assert anchor["data-cdb-tier"] != "starter"
        assert query["utm_campaign"] == ["astra_cash_conversion_v19"]

    service_links = soup.select('a[data-cdb-v19-1-service-intake="true"]')
    assert len(service_links) == 2
    for anchor in service_links:
        parsed = urlparse(anchor["href"])
        query = parse_qs(parsed.query)
        assert parsed.path == "/contact.html"
        assert parsed.fragment == "inquiry-form-card"
        assert query["service"] == ["vulnerability_assessment"]
        assert query["report_id"] == ["CDB-CTI-2026-E235859C8BD7"]
        assert query["utm_campaign"] == ["astra_cash_conversion_v19_1"]

    related = soup.find("a", href="/related.html").get_text(" ", strip=True)
    assert "not established as actively exploited in cited evidence" not in related.lower()
    assert "V8 Zero-Day" not in related
    assert related == "Google Releases Chrome Update to Patch Zero-Day"


def test_v19_1_is_idempotent():
    once = v19_1.enforce_cti_integrity_revenue_v19_1(_source_only_fixture(), context=_context())
    twice = v19_1.enforce_cti_integrity_revenue_v19_1(once, context=_context())
    assert once == twice


def test_rich_evidence_preserves_flash_ready_and_real_operational_artifacts():
    html = """
    <article>
      <div class="cdbd-kpi"><span>SEVERITY</span><strong>HIGH</strong></div>
      <div class="cdbd-kpi"><span>TLP</span><strong>NOT ASSIGNED</strong></div>
      <div><span>DETECTION</span><strong>GUIDANCE PRESENT</strong></div>
      <div><span>HUNTING</span><strong>GUIDANCE PRESENT</strong></div>
      <div><span>SOC PLAYBOOK</span><strong>PRESENT</strong></div>
      <div><span>EVIDENCE TIER</span><strong>FLASH_READY</strong></div>
      <img src="https://blog.cyberdudebivash.in/api/og?title=Test&amp;severity=MEDIUM">
      <h3>Executive Summary</h3><p>Validated IOC 203.0.113[.]7 with Sigma rule and MITRE ATT&amp;CK mapping T1059.</p>
      <h3>Verified Facts</h3><ul>
        <li>Source publisher: Vendor</li><li>Source published: 2026-09-07</li>
        <li>Observed indicator: 203.0.113[.]7</li><li>Behavior mapped to T1059</li>
      </ul>
      <h3>MITRE ATT&amp;CK Assessment</h3><p>T1059 is source-backed.</p>
      <h3>Indicators &amp; Observables</h3><p>203.0.113[.]7</p>
      <h3>Detection Engineering Guidance</h3><pre>title: Test Rule\nlogsource:\n  category: process_creation\ndetection:\n  condition: selection</pre>
      <h3>Threat Hunting Queries</h3><pre>DeviceProcessEvents | where FileName == "test.exe"</pre>
      <h3>SOC Analyst Playbook</h3><p>Validate and escalate.</p>
    </article>
    """
    rendered = v19_1.enforce_cti_integrity_revenue_v19_1(html, context=_context())
    soup = BeautifulSoup(rendered, "html.parser")
    text = soup.get_text(" ", strip=True)
    assert "FLASH_READY" in text
    assert "SOURCE_ONLY_PRELIMINARY" not in text
    assert "Validated IOC" in text
    assert "EXECUTABLE" in text
    assert "EXECUTABLE_QUERY" in text
    image = soup.find("img")
    query = parse_qs(urlparse(image["src"]).query)
    assert query["severity"] == ["HIGH"]


def test_final_validator_blocks_unrepaired_positive_artifact_claim():
    soup = BeautifulSoup("""
      <div class="cdbd-kpi"><span>TLP</span><strong>TLP:CLEAR</strong></div>
      <h3>Executive Summary</h3><p>Full Sigma rules and IOCs are included.</p>
      <h3>Indicators &amp; Observables</h3><p>Not established in cited evidence.</p>
      <h3>MITRE ATT&amp;CK Assessment</h3><p>Not established in cited evidence.</p>
      <h3>Detection Engineering Guidance</h3><p>Guidance only.</p>
      <h3>Threat Hunting Queries</h3><p>Guidance only.</p>
    """, "html.parser")
    caps = v19_1._capabilities(soup)
    with pytest.raises(PublicationIntegrityError):
        v19_1._validate_final(soup, "UNSPECIFIED", False, caps)


def test_explicit_negative_artifact_disclosure_is_not_treated_as_capability_claim():
    soup = BeautifulSoup("""
      <div class="cdbd-kpi"><span>TLP</span><strong>TLP:CLEAR</strong></div>
      <h3>Executive Summary</h3><p>Source-backed IOCs and MITRE ATT&amp;CK mappings are not established in this record.</p>
      <h3>Indicators &amp; Observables</h3><p>Not established in cited evidence.</p>
      <h3>MITRE ATT&amp;CK Assessment</h3><p>Not established in cited evidence.</p>
      <h3>Detection Engineering Guidance</h3><p>Guidance only.</p>
      <h3>Threat Hunting Queries</h3><p>Guidance only.</p>
    """, "html.parser")
    caps = v19_1._capabilities(soup)
    v19_1._validate_final(soup, "UNSPECIFIED", False, caps)


def test_og_builder_never_converts_unknown_severity_to_high(monkeypatch):
    calls = []

    def inner(*args, **kwargs):
        calls.append((args, kwargs))
        return "https://example.test/api/og?severity=HIGH"

    monkeypatch.setattr(v19_1, "_INNER_OG_BUILDER", inner)
    assert v19_1._patched_og_builder(None, "Title", None, "", None, "Intel") == v19_1.NEUTRAL_OG_URL
    assert calls == []
    assert v19_1._patched_og_builder(None, "Title", "HIGH", "", None, "Intel").startswith("https://example.test/")
    assert len(calls) == 1


def test_telemetry_is_non_secret_and_does_not_change_commercial_truth_sources():
    telemetry = v19_1.telemetry_snapshot()
    assert telemetry["prices_changed"] is False
    assert telemetry["payment_system_changed"] is False
    assert telemetry["reportx_tier_engine_changed"] is False
    assert telemetry["provider_policy_changed"] is False
    assert telemetry["telemetry_contains_pii"] is False
    assert telemetry["telemetry_contains_credentials"] is False
    serialized = str(telemetry).lower()
    assert "email" not in serialized
    assert "api_key" not in serialized
    assert "password" not in serialized



def test_legacy_starter_card_is_repaired_without_mutating_report_severity():
    html = """
    <article>
      <div class="cdbd-kpi"><span>SEVERITY</span><strong>HIGH</strong></div>
      <section class="cdbv18-commercial" data-astra-revenue-v18="true" data-report-family="ransomware_claim">
        <article><small>₹999 / MONTH</small><strong>API STARTER</strong>
          <p>5,000 API calls/day</p>
          <a data-cdb-tier="starter" data-cdb-v18-cta="api_starter" href="https://blog.cyberdudebivash.in/buy.html?plan=starter">Get API Starter</a>
        </article>
      </section>
    </article>
    """
    soup = BeautifulSoup(html, "html.parser")
    assert v19_1._repair_paid_ctas(soup, _context()) is True
    panel = soup.select_one(".cdbv18-commercial")
    assert "₹999" not in panel.get_text(" ", strip=True)
    assert "API STARTER" not in panel.get_text(" ", strip=True)
    anchor = panel.select_one("a[data-cdb-tier]")
    url = urlparse(anchor["href"])
    assert url.netloc == "intel.cyberdudebivash.com"
    assert parse_qs(url.query)["plan"] == ["pro"]
    assert anchor["data-cdb-tier"] == "pro"
    severity = soup.select_one(".cdbd-kpi strong")
    assert severity.get_text(strip=True) == "HIGH"


@pytest.mark.parametrize("bad_price", ["₹999 / MONTH", "INR 1,499 / MONTH", "₹4,999 / MONTH"])
def test_integrity_rejects_unverified_legacy_checkout_price(bad_price):
    soup = BeautifulSoup(
        '<section class="cdbv18-commercial" data-astra-revenue-v18="true">'
        '<article><small>' + bad_price + '</small>'
        '<a data-cdb-tier="pro" href="https://intel.cyberdudebivash.com/upgrade.html?plan=pro'
        '&utm_campaign=astra_cash_conversion_v19">VIEW PLAN</a></article></section>',
        "html.parser",
    )
    with pytest.raises(PublicationIntegrityError, match="hardcoded legacy price"):
        v19_1._validate_final(soup, "HIGH", False, v19_1._capabilities(soup))


def test_integrity_rejects_wrong_product_on_paid_checkout_cta():
    soup = BeautifulSoup(
        '<section class="cdbv18-commercial" data-astra-revenue-v18="true">'
        '<a data-cdb-tier="enterprise" href="https://intel.cyberdudebivash.com/'
        'upgrade.html?plan=pro&utm_campaign=astra_cash_conversion_v19">VIEW PLAN</a></section>',
        "html.parser",
    )
    with pytest.raises(PublicationIntegrityError, match="bypasses canonical platform checkout"):
        v19_1._validate_final(soup, "HIGH", False, v19_1._capabilities(soup))



@pytest.mark.parametrize("marking", [
    "TLP:RED", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:GREEN",
    "TLP:WHITE", "TLP:UNKNOWN", "PRIVATE",
])
def test_restricted_or_unapproved_rendered_tlp_cannot_be_relabelled_public(marking):
    rendered = _source_only_fixture().replace(
        "<strong>NOT ASSIGNED</strong>", f"<strong>{marking}</strong>", 1
    )
    with pytest.raises(PublicationIntegrityError, match="PUBLIC_TLP_RELEASE_BLOCKED"):
        v19_1.enforce_cti_integrity_revenue_v19_1(
            rendered, article=SimpleNamespace(title="Source report"), context=_context(),
        )


@pytest.mark.parametrize("field", ["tlp", "tlp_marking", "sharing_tlp", "distribution_tlp"])
def test_restricted_article_tlp_blocks_even_if_displayed_badge_is_unassigned(field):
    data = {"title": "Source report", field: "TLP:AMBER+STRICT"}
    with pytest.raises(PublicationIntegrityError, match="PUBLIC_TLP_RELEASE_BLOCKED"):
        v19_1.enforce_cti_integrity_revenue_v19_1(
            _source_only_fixture(), article=SimpleNamespace(**data), context=_context(),
        )


def test_restricted_context_tlp_blocks_even_if_rendered_badge_was_clear():
    rendered = _source_only_fixture().replace(
        "<strong>NOT ASSIGNED</strong>", "<strong>TLP:CLEAR</strong>", 1,
    )
    context = SimpleNamespace(family="cve_advisory", tlp="TLP:GREEN")
    with pytest.raises(PublicationIntegrityError, match="PUBLIC_TLP_RELEASE_BLOCKED"):
        v19_1.enforce_cti_integrity_revenue_v19_1(
            rendered, article=SimpleNamespace(title="Source report"), context=context,
        )


@pytest.mark.parametrize("markup", [
    '<meta name="tlp" content="TLP:RED">',
    '<meta property="cdb:tlp" content="TLP:AMBER">',
    '<div data-tlp="TLP:GREEN">source-only research</div>',
])
def test_rendered_metadata_tlp_cannot_bypass_public_release_gate(markup):
    rendered = _source_only_fixture().replace("<article>", "<article>" + markup, 1)
    with pytest.raises(PublicationIntegrityError, match="PUBLIC_TLP_RELEASE_BLOCKED"):
        v19_1.enforce_cti_integrity_revenue_v19_1(
            rendered, article=SimpleNamespace(title="Source report"), context=_context(),
        )


def test_public_clear_marking_and_explicit_unassigned_can_render():
    for mark in ("TLP:CLEAR", "CLEAR", "NOT ASSIGNED"):
        rendered = _source_only_fixture().replace(
            "<strong>NOT ASSIGNED</strong>", f"<strong>{mark}</strong>", 1,
        )
        result = v19_1.enforce_cti_integrity_revenue_v19_1(
            rendered, article=SimpleNamespace(title="Source report", tlp="TLP:CLEAR"),
            context=SimpleNamespace(family="cve_advisory", tlp_marking="TLP:CLEAR"),
        )
        assert "TLP:CLEAR" in result


def test_already_integrity_wrapped_content_does_not_bypass_tlp_restriction():
    # An external patch to a rendered article must not defeat the gate simply
    # because an earlier version carries the presentation marker.
    marked = f"<!-- {v19_1.MARKER} -->" + _source_only_fixture().replace(
        "<strong>NOT ASSIGNED</strong>", "<strong>TLP:RED</strong>", 1,
    )
    with pytest.raises(PublicationIntegrityError, match="PUBLIC_TLP_RELEASE_BLOCKED"):
        v19_1.enforce_cti_integrity_revenue_v19_1(marked)



def test_enterprise_evidence_disclosure_shows_precise_source_only_limitations():
    rendered = v19_1.enforce_cti_integrity_revenue_v19_1(
        _source_only_fixture(),
        article=SimpleNamespace(title="Source linked research"),
        context=_context(),
    )
    soup = BeautifulSoup(rendered, "html.parser")
    panel = soup.select_one('[data-cdb-v19-1-integrity-note="true"]')
    assert panel is not None
    assert panel.get("aria-label") == "Enterprise intelligence evidence disclosure"
    assert panel.name == "aside"
    rows = {
        div.find("dt").get_text(strip=True): div.find("dd").get_text(" ", strip=True)
        for div in panel.select("dl > div")
    }
    assert len(rows) == 7
    assert rows["Evidence basis"] == "Single-source preliminary; seek corroboration"
    assert rows["Indicators"] == "No established source-backed IOC pack"
    assert rows["ATT&CK"] == "No established technique mapping"
    assert rows["Detection content"] == "No validated executable rule supplied"
    assert rows["Customer impact"] == "Not determined by this public report"
    assert rows["Distribution"] == "TLP:CLEAR"
    assert "A pipeline heartbeat does not prove a new report" in panel.get_text(" ", strip=True)
    assert "source linked" not in rows["Customer impact"].lower()
    assert soup.select_one("style#cdb-v19-1-enterprise-evidence-css") is not None
    assert "max-width:640px" in rendered
    assert len(soup.select('[data-cdb-v19-1-integrity-note="true"]')) == 1


def test_enterprise_assurance_presence_never_claims_validated_detection_rule():
    html = _source_only_fixture().replace(
        "<p>Not established in cited evidence.</p>",
        "<p>T1059 referenced; analyst must confirm actual observed behavior.</p>", 1,
    ).replace(
        "<p>Identify telemetry and validate evidence before deployment.</p>",
        "<pre>title: Source Sourced Rule\nlogsource:\n  category: process_creation\ndetection:\n  condition: selection</pre>", 1,
    )
    rendered = v19_1.enforce_cti_integrity_revenue_v19_1(
        html, article=SimpleNamespace(title="Technical record"), context=_context(),
    )
    soup = BeautifulSoup(rendered, "html.parser")
    panel = soup.select_one('[data-cdb-v19-1-integrity-note="true"]')
    rows = {
        item.find("dt").get_text(strip=True): item.find("dd").get_text(" ", strip=True)
        for item in panel.select("dl > div")
    }
    assert rows["Detection content"] == "Rule-like text present; not production-tested"
    assert rows["ATT&CK"] == "Technique reference present; mapping requires analyst validation"
    assert rows["Customer impact"] == "Not determined by this public report"
    assert "Production-tested" not in panel.get_text(" ", strip=True)
