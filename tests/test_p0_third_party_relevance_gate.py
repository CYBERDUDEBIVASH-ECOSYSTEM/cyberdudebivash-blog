"""P0 regression: third-party articles that are not threat events must not be published as CTI.

Incident (2026-11-24, CTI Blogger, audit F1): the Rapid Intelligence lane published vendor release notes
(Elastic Security 9.6), consumer Windows-feature news, Black Friday shopping advice and risk-management
commentary under the enterprise "SOC ANALYST BRIEF" banner. Eligibility was "listed publisher + 80 words";
nothing asked whether the item was a threat event. `publication_scheduler.is_non_threat_editorial` is the
single filter both selectors use, so the gate lives there.
"""
from datetime import datetime, timezone

import pytest

from automation import premium_factory_throughput as factory
from automation import publication_scheduler as scheduler
from automation.content_discovery import DiscoveredArticle, _infer_labels
from automation.publication_scheduler import (
    classify_publication_family,
    is_non_threat_editorial,
    select_publication_batch,
)
from automation.threat_relevance import SUMMARY_MIN_DISTINCT_TERMS, assess_third_party, threat_terms

ELASTIC_TITLE = "Press play on Elastic Security 9.6, banger after banger"
ELASTIC_SUMMARY = (
    "AlertZero works your alert queue in the background and nothing consequential it proposes runs until you "
    "approve it. 9.6 also brings entity resolution, MITRE ATLAS mappings, 143 AI detection rules, and Linux "
    "ransomware protection."
)


def article(title, summary="", *, source="global_rss", publisher="Example Publisher", url=None, n=0, **kw):
    return DiscoveredArticle(
        url=url or f"https://news.example.test/item-{n}-{abs(hash(title)) % 99999}",
        title=title,
        summary=summary,
        published_at=datetime.now(timezone.utc).isoformat(),
        content_hash=f"relevance{n}{abs(hash(title)) % 99999}",
        labels=_infer_labels(title, summary),
        source=source,
        source_publisher=publisher,
        **kw,
    )


# ---------------------------------------------------------------- real headlines (public titles)
JUNK = [  # published or queued on the CTI Blogger; none of them is a threat event
    (ELASTIC_TITLE, ELASTIC_SUMMARY, "product_release"),
    ("Black Friday, red flags: too-good-to-be-true deals hiding real threats", "", "non_threat_title_pattern"),
    ("Some of the best Amazon Prime Day SSD and storage deals are still live", "", "non_threat_title_pattern"),
    ("This durable Lexar SSD is perfect for content creators and it's 26% off during Prime Day", "", "non_threat_title_pattern"),
    ("I tested Lenovo's new modular ThinkPad, and it renewed my faith in repairable laptops", "", "non_threat_title_pattern"),
    ("Risk Ledger Raises $32 Million in Series B Funding", "", "non_threat_title_pattern"),
    ("Cyera agrees to acquire Oasis Security for $1B to safeguard proliferating AI agents", "", "non_threat_title_pattern"),
    ("ISC Stormcast For Friday, July 10th, 2026 https://isc.sans.edu/podcastdetail/10002, (Fri, Jul 10th)", "", "non_threat_title_pattern"),
    ("Security Affairs newsletter Round 595 by Pierluigi Paganini – INTERNATIONAL EDITION", "", "non_threat_title_pattern"),
    ("AccuKnox Wins Best AI Startup Award for Enterprise Agentic AI Security at BSides Bangalore", "", "non_threat_title_pattern"),
    ("Introducing AWS account access manager: IAM role flexibility with centralized workforce access", "", "non_threat_title_pattern"),
    ("Yubico Launches YubiKey 5.8 With Hardware-Backed Authorization for AI Agent Workflows", "", "product_release"),
    ("Wireshark 4.6.7 Released, (Sat, Jul 11th)", "", "product_release"),
    ("Anthropic rolls out Sonnet 5 with near-Opus 4.8 performance at a lower price", "", "product_release"),
    ("How stressful is your role?", "", "bare_question"),
    ("Email security recommendations for 2026?", "", "bare_question"),
    ("Snort for Enterprise IPS/IDS????", "", "bare_question"),
    ("A quiet week in infosec <.<", "", "no_threat_signal"),
    ("I just woke up to someone remote controlling my desktop", "", "no_threat_signal"),
    ("ARTEX Moves at Machine Speed: What Risk Owners Need to Change", "Risk owners face a new operating model.", "no_threat_signal"),
    ("New Windows security check could let apps block access", "A new platform feature lets apps verify device health.", "no_threat_signal"),
]


@pytest.mark.parametrize("title,summary,reason", JUNK)
def test_non_threat_third_party_items_are_rejected_with_a_stable_reason(title, summary, reason):
    ok, why = assess_third_party(title, summary)
    assert (ok, why) == (False, reason), title
    assert is_non_threat_editorial(article(title, summary))


LEGIT = [  # real threat headlines, including cryptic and compound-word titles the first vocabulary missed
    "CISA warns of exploited N-able bug as company restores email platform",
    "Operation ShadowCloud: cloud service–based backdoors targeting government networks",
    "Operation FlashHole: Lazarus breaks security, defies control",
    "Four REVSTEALER-Linked Modules Disable Windows Update and Defender to Run a Crypto Miner",
    "The Shared Clipboard Inside the Sandbox: Cross-Account Data Leakage in ChatGPT",
    "Silent Ransom Group Allegedly Extorted $207 Million Without Encrypting Files",
    "Researchers uncover Volt Typhoon’s covert, ephemeral network",
    "FortiBleed Exposes Global Credential-Spraying Operation",
    "Critical U-Boot Bugs Undermine Secure Boot on Millions of Devices",
    "Samsung KNOX Kernel UAF Exposes Millions of Galaxy Devices",
    "6.9 million driver’s license numbers stolen from AssuranceAmerica",
    "Fake npm Packages Impersonate PostCSS Tool to Steal Chrome Passwords",
    "Salesforce Disables Klue Integration After OAuth Token Theft Hits Customer Data",
    "Volant Manticore: Flying Under the Radar",
    "Malware spread through Optimizely hits 178 organizations, including BBC",
    "Cybersecurity incident at BAE Systems disrupts US bankruptcy court system",
    "Killing me gently: Inside Gentlemen’s EDR killer framework",
    "0% GPU utilization: How SANSAR hides Linux cryptomining",
    "Anatomy of a Silent Domain Takeover",
    "Iran, Russia, China Target Water Systems for Sabotage",
    "BTR Reforged: Weaponizing Defender’s Remediation Driver as a Kernel Operation Primitive",
    "Akira criminal infrastructure bulletin",
    "Four RevStealer variants analysed",  # compound words: the threat noun is a suffix, not a separate word
    "Operation Endgame",  # a capitalised "Operation <Name>" is a threat or law-enforcement operation on its own
    "Google and Microsoft Pull ModHeader With 1.6 Million Installs After Dormant Collector Found",  # decimal + unit is not a version
]


@pytest.mark.parametrize("title", LEGIT)
def test_real_threat_headlines_are_not_rejected_even_when_the_summary_is_empty(title):
    if title.startswith("Google and Microsoft Pull ModHeader"):
        # No title vocabulary: it must at least NOT be classed a product release; the summary decides.
        assert assess_third_party(title, "")[1] == "no_threat_signal"
        assert assess_third_party(title, "A malicious extension was found stealing browsing data in a campaign.")[0]
        return
    ok, why = assess_third_party(title, "")
    assert ok and why == "threat_term_in_title", (title, why)
    assert not is_non_threat_editorial(article(title))


def test_a_threat_term_in_the_title_wins_over_commerce_wording():
    assert assess_third_party("Black Friday scam campaign steals payment cards from shoppers", "")[0]
    assert assess_third_party("Vendor raises $20M after ransomware attack disrupted operations", "")[0]
    assert assess_third_party("Is this ransomware? Analysis of a new loader", "")[0]


def test_summary_rule_needs_two_distinct_terms_not_one_incidental_word():
    assert SUMMARY_MIN_DISTINCT_TERMS == 2
    cryptic = "Catan and Mouse"
    assert assess_third_party(cryptic, "A threat actor ran a campaign against exposed servers.") == (True, "threat_terms_in_summary")
    assert assess_third_party(cryptic, "Backups matter because ransomware is common.")[0] is False
    assert assess_third_party(cryptic, "ransomware ransomware ransomware Ransomware")[0] is False, "repeats count once"
    assert assess_third_party(cryptic, "<p>The <b>campaign</b> deployed&nbsp;malware.</p>")[0], "tags and entities are stripped"
    # Words that exist only inside tag attributes (URLs, class names) are not evidence.
    assert assess_third_party(cryptic, '<a href="https://x.test/attack-and-exploit" class="malware ransomware">read more</a>')[0] is False


def test_whole_word_matching_and_ambiguous_words_are_not_threat_terms():
    for text in ("How to adapt your pipeline", "Stack Overflow developer survey", "Bug bounty program expands rewards",
                 "The rat race of SOC hiring", "Activision Blizzard layoffs", "Panda Security adds a feature"):
        assert not threat_terms(text), text
    assert threat_terms("APT28 and APT 41 clusters") and threat_terms("CVE-2026-12345") and threat_terms("heap overflow")


def test_version_rule_recognises_releases_but_not_quantities():
    assert assess_third_party("Elastic Security 9.6 ships new dashboards", "")[1] == "product_release"
    assert assess_third_party("OpenSSH 10.4 arrives with security fixes and a post-quantum signature option", "")[0]
    assert assess_third_party("Hackers hit 1.6 million routers, 95.95% unpatched", "")[0]


# ---------------------------------------------------------------- scope: only third-party global_rss
def test_typed_and_first_party_sources_are_never_judged_by_vocabulary():
    junk_title = "Quarterly roundup with nothing in it"
    for source in ("nvd", "cisa_kev", "cisa_advisory", "ransomware_intel", "breach_intel", "threat_actor_intel", "rss", "live_intel"):
        assert not is_non_threat_editorial(article(junk_title, source=source)), source
    assert is_non_threat_editorial(article(junk_title, source="global_rss"))


def test_the_existing_job_roundup_rule_still_applies_to_every_source():
    assert is_non_threat_editorial(article("Cybersecurity jobs available right now: SOC analyst", source="nvd"))
    assert is_non_threat_editorial(article("Cybersecurity Jobs available right now", source="global_rss"))


def test_the_elastic_release_note_is_classed_non_intelligence_end_to_end():
    a = article(ELASTIC_TITLE, ELASTIC_SUMMARY, publisher="Elastic Security Labs")
    assert classify_publication_family(a) == "non_intelligence"
    assert factory.classify_factory_family(a) == "non_intelligence"


# ---------------------------------------------------------------- selection: filtered, counted, never padded
def _batch(selector, fresh, retry=()):
    return selector(list(retry), list(fresh), 4)


def test_both_selectors_drop_junk_count_it_and_never_pad_with_it():
    junk = [article(t, s, n=i) for i, (t, s, _) in enumerate(JUNK[:8])]
    real = [article("Ransomware gang claims attack on a regional hospital", "Operators posted victim data.", n=100),
            article("CVE-2026-12345 exploited in the wild against VPN appliances", "Patch available.", n=101)]
    for selector in (select_publication_batch, factory.select_factory_publication_batch):
        picked = _batch(selector, junk + real)
        titles = {a.title for a in picked.articles}
        assert titles <= {a.title for a in real}, (selector, titles)
        assert picked.metrics["non_intelligence_filtered"] == len(junk)
        only_junk = _batch(selector, junk)
        assert only_junk.articles == [] and only_junk.metrics["non_intelligence_filtered"] == len(junk)


def test_retry_queue_items_are_filtered_too():
    retry = [article(ELASTIC_TITLE, ELASTIC_SUMMARY, n=1)]
    fresh = [article("Backdoor found in popular npm package", "Malicious versions steal tokens.", n=2)]
    for selector in (select_publication_batch, factory.select_factory_publication_batch):
        picked = _batch(selector, fresh, retry)
        assert [a.title for a in picked.articles] == [fresh[0].title]
        assert picked.metrics["non_intelligence_filtered"] == 1


def test_a_defect_in_the_relevance_check_falls_back_to_the_previous_behaviour(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("simulated defect")
    monkeypatch.setattr(scheduler, "assess_third_party", boom)
    assert is_non_threat_editorial(article(ELASTIC_TITLE, ELASTIC_SUMMARY)) is False  # not filtered, pipeline keeps running
    assert is_non_threat_editorial(article("Cybersecurity jobs available right now")) is True  # the older rule is unaffected
