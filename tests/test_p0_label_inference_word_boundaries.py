"""P0 regression: labels are inferred from WHOLE WORDS, not substrings.

Evidence (all previously published CTI titles, 6,816 evaluated): the old substring matcher produced labels
such as APT for "Adapt..." and for laptop reviews, SOC Operations for "SocGholish", Cloud Security for
"iCloud" and "cloudquantum", and AI Security for "enrollment" (it contains "llm"). The whole-word matcher
removed 141 label instances and added none. These tests pin the false positives out and the true
positives (plurals, past tense, hyphenated compounds, numbered threat groups) in.
"""
import pytest

from automation.content_discovery import _LABEL_KEYWORDS, _infer_labels

BASE = ["CYBERDUDEBIVASH", "Threat Intelligence"]


def extra(title, summary=""):
    return [label for label in _infer_labels(title, summary) if label not in BASE]


def _old_substring_labels(title, summary):
    """The previous implementation, kept only to prove the new one never ADDS a label."""
    text = (title + " " + summary).lower()
    out = list(BASE)
    for keyword, label in _LABEL_KEYWORDS.items():
        if keyword in text and label not in out:
            out.append(label)
    return out


FALSE_POSITIVES = [
    ("How to adapt your detection pipeline", "", "APT"),
    ("MSI's Katana 15 is a solid midrange gaming laptop", "", "APT"),
    ("Forget traffic lights, reCAPTCHA may ask for hand gestures", "", "APT"),
    ("Nearly 15,000 infected websites cleaned in SocGholish crackdown", "", "SOC Operations"),
    ("Social media accounts hijacked in new scam", "", "SOC Operations"),
    ("Google vs iCloud", "", "Cloud Security"),
    ("236,000 DCloud Uni-App Sites Used in Crypto Scams", "", "Cloud Security"),
    ("Entra passkey enrollment vishing targets Microsoft 365 users", "", "AI Security"),
    ("Patriot Act reform", "", "IoT Security"),
    ("Chaotic Eclipse Releases Kaspersky Zero-Day HardBreacher", "", "Data Breach"),
    ("[NotCVE-2026-0017] game-music-emu NULL Pointer Dereference", "", "Vulnerabilities"),
    ("Watch out for renewal scams pretending to be Malwarebytes", "", "Malware Research"),
    ("My antiphishing Suricata ruleset is now in suricata-update", "", "Phishing"),
    ("Release notes", "adapters and captured sockets", "APT"),
]


@pytest.mark.parametrize("title,summary,label", FALSE_POSITIVES)
def test_substring_false_positives_no_longer_label(title, summary, label):
    assert label not in extra(title, summary)
    assert label in _old_substring_labels(title, summary), "the case must be a real regression, not a vacuous one"


TRUE_POSITIVES = [
    ("APT28 targets European governments", "APT"),
    ("APT41 resurfaces with new tooling", "APT"),
    ("New APTs observed in the wild", "APT"),
    ("CVE-2026-12345 critical flaw", "Vulnerabilities"),
    ("Five CVEs patched this month", "Vulnerabilities"),
    ("Ransomware-as-a-service gang claims another victim", "Ransomware"),
    ("New malware family steals credentials", "Malware Research"),
    ("Phishing campaign abuses OAuth", "Phishing"),
    ("Company breached by unknown actor", "Data Breach"),
    ("Two data breaches disclosed", "Data Breach"),
    ("A breach notification was sent", "Data Breach"),
    ("SOC analysts overwhelmed by alert volume", "SOC Operations"),
    ("Building a modern SOC", "SOC Operations"),
    ("Cloud misconfiguration exposes buckets", "Cloud Security"),
    ("Multi-cloud identity risks", "Cloud Security"),
    ("IoT cameras exploited", "IoT Security"),
    ("Securing LLMs in production", "AI Security"),
    ("LLM-based agents can be hijacked", "AI Security"),
    ("Prompt injection against coding assistants", "AI Security"),
    ("New zero-day exploited", "Zero-Day"),
    ("A zero day in a VPN appliance", "Zero-Day"),
    ("Supply chain attack hits npm", "Supply Chain"),
    ("Patch Tuesday fixes 80 flaws", "Patch Tuesday"),
    ("MITRE ATT&CK mapping for the campaign", "Detection Engineering"),
    ("New Sigma rules released", "Detection Engineering"),
    ("YARA rule for the loader", "Detection Engineering"),
    ("OWASP Top 10 for LLM applications", "AI Security"),
    ("Incident response lessons learned", "Incident Response"),
    ("Three incidents this quarter", "Incident Response"),
    ("DevSecOps pipeline hardening", "DevSecOps"),
    ("CISA KEV adds two flaws", "CISA KEV"),
    ("Known exploited vulnerabilities catalog grows", "CISA KEV"),
    ("Nation-state actors target telecoms", "APT"),
    ("Prompt injection and AI security", "AI Security"),
]


@pytest.mark.parametrize("text,label", TRUE_POSITIVES)
def test_real_threat_wording_still_gets_its_label(text, label):
    assert label in extra(text), text
    assert label in extra("Headline", text), "also matched in the summary"


def test_the_new_matcher_never_adds_a_label_the_old_one_did_not():
    corpus = [t for t, *_ in FALSE_POSITIVES] + [t for t, _ in TRUE_POSITIVES]
    for title in corpus:
        assert set(_infer_labels(title, "")) <= set(_old_substring_labels(title, "")), title


def test_labels_keep_their_documented_order_base_first_and_unique():
    # Literal expectation (not derived from the mapping) so a reordered or duplicated label cannot hide.
    labels = _infer_labels("CVE-2026-1 ransomware zero-day in the cloud", "SOC incident")
    assert labels == ["CYBERDUDEBIVASH", "Threat Intelligence", "Vulnerabilities", "Zero-Day", "Ransomware",
                      "SOC Operations", "Cloud Security", "Incident Response"]
    # Several keywords for one label (ai security / llm / prompt injection / owasp) yield ONE label.
    many = _infer_labels("AI security: LLM prompt injection per OWASP", "")
    assert many.count("AI Security") == 1
    assert len(many) == len(set(many))


def test_empty_and_unlabelled_text_return_only_the_base_labels():
    assert _infer_labels("", "") == BASE
    assert _infer_labels("some random article", "content here") == BASE


def test_numbered_threat_groups_are_not_broken_by_the_word_boundary_rule():
    assert "APT" in extra("UNC and APT29 overlap")
    assert "APT" in extra("APT 28 and APT-41 clusters")  # spaced and hyphenated forms keep matching (hyphen/space are boundaries)
