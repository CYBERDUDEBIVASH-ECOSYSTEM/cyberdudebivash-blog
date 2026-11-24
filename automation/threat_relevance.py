"""Deterministic relevance check for THIRD-PARTY (global RSS) candidates.

Why this exists (audit F1, 2026-11-24): the Rapid Intelligence lane admitted any article from a listed
publisher with at least 80 words. Nothing asked whether the article was a threat event, so vendor
release notes, consumer shopping advice, funding news and help-seeking forum posts were published
under the enterprise "SOC ANALYST BRIEF" banner. This module is that missing question, answered
without a model: a small, auditable vocabulary and a few title patterns.

Design rules
  * FAIL CLOSED but narrow: it only runs on third-party ``global_rss`` articles. Typed sources (NVD,
    CISA KEV/advisories, ransomware/breach/threat-actor intel) and first-party canonical reports have
    their own structure and are never judged here.
  * Positive evidence of non-threat content (deals, funding, awards, webinars, release notes, a
    product version, a bare question) rejects an article ONLY when its title carries no threat
    vocabulary of its own.
  * Otherwise an article needs threat vocabulary: any term in the title, or at least two DISTINCT
    terms in the summary. One incidental word (a product feature list that mentions "ransomware")
    is not evidence.
  * Whole words only (``(?<![a-z0-9])...(?![a-z0-9])``): "adapt" is not "apt".
  * Pure functions, no I/O, no network, no secrets; the reason is returned for logging and tests.
"""
from __future__ import annotations

import html as _html
import re
from typing import Tuple

# Words that, in a title or summary, signal a security EVENT or technique (not a product or topic).
_THREAT_TERMS = (
    r"cve-\d{4}-\d{4,}", r"zero[- ]?days?", r"0[- ]?days?", r"ransom(?:ware)?", r"extort\w*", r"malware", r"malicious",
    r"backdoors?", r"trojans?", r"botnets?", r"spyware", r"\w*stealers?", r"rootkits?", r"wipers?",
    r"\w*loaders?", r"keyloggers?", r"remote access trojans?", r"phishing", r"spear-?phish\w*", r"vishing",
    r"smishing", r"business email compromise", r"bec", r"credential (?:theft|stuffing|harvest\w*)", r"account takeovers?",
    r"takeovers?", r"breach(?:e[sd])?", r"data (?:leaks?|theft|exposure)", r"leak\w*", r"stol(?:en|e)", r"steal(?:s|ing)?",
    r"theft", r"hack(?:ed|er|ers|ing|s)?", r"cyber-?attacks?", r"attack(?:s|ers?|ed|ing)?", r"threat actors?",
    r"apt\d{0,3}s?", r"nation[- ]state", r"espionage", r"sabotage", r"intrusions?", r"incidents?", r"compromis(?:e|ed|es|ing)",
    r"supply[- ]chain", r"d?ddos", r"vulnerabilit(?:y|ies)", r"vulnerable", r"exploit(?:s|ed|ing|ation|able)?", r"flaws?",
    r"bugs?(?! bount)", r"rce", r"remote code execution", r"privilege escalation", r"sandbox (?:escape|bypass)", r"bypass(?:es|ed)?",
    r"auth(?:entication)? bypass", r"sql injection", r"xss", r"ssrf", r"use-after-free", r"uaf", r"(?:buffer|heap|integer) overflow",
    r"cvss", r"c2", r"command[- ]and[- ]control", r"lateral movement", r"initial access", r"exfiltrat\w*",
    r"hijack\w*", r"spoof\w*", r"weaponi[sz]\w*", r"abus(?:e|ed|es|ing)", r"misuse\w*", r"evad(?:e|es|ed|ing|sion)", r"tamper\w*", r"advisor(?:y|ies)", r"apple-sa-\d+", r"ttps?", r"iocs?", r"mitre att&ck",
    r"cisa", r"kev", r"campaigns?", r"crimeware", r"cybercrim\w*", r"criminals?", r"crime\w*", r"gangs?", r"fraud\w*", r"scammers?", r"fake", r"drainers?",
    r"unauthori[sz]ed access", r"insider threat", r"jailbreak\w*", r"prompt injection", r"patch(?:es|ed)?", r"unpatched",
    r"security (?:fix(?:es)?|updates?|patch(?:es)?|flaws?)", r"forensics?", r"takedowns?", r"disrupt(?:s|ed|ion)?", r"\w*miners?", r"cryptomin\w*", r"cryptojack\w*", r"credential[- ]spray\w*", r"edr killers?",
    r"seiz(?:ed|ure)s?", r"indict\w*", r"arrest\w*", r"sanction(?:s|ed)?", r"sinkhol\w*", r"typhoon", r"manticore",
    r"emerging threats?", r"(?:midnight|forest) blizzard", r"chollima", r"scattered spider", r"lazarus", r"kimsuky", r"turla", r"sandworm", r"fin\d{1,2}", r"unc\d{3,4}", r"ta\d{3}", r"storm-\d{4}", r"threat (?:hunting|campaign|landscape|report)",
)
_THREAT_RE = re.compile(r"(?<![a-z0-9])(?:" + "|".join(_THREAT_TERMS) + r")(?![a-z0-9])", re.IGNORECASE)

# Positive evidence the item is commerce, marketing, business news or a recurring digest.
_NON_THREAT_TITLE = (
    r"black friday", r"cyber monday", r"prime day", r"deals?", r"discounts?", r"coupons?", r"gift guide", r"giveaway",
    r"on sale", r"\d+% off", r"best (?:[a-z0-9-]+ ){0,3}(?:vpns?|antivirus|laptops?|phones?|routers?|password managers?|"
    r"headphones?|tablets?|monitors?|keyboards?|webcams?|gadgets?)", r"hands-on", r"unboxing", r"i tried", r"i tested",
    r"i replaced", r"i found \d+", r"release notes?", r"what['’]?s new", r"now available", r"introducing", r"announc(?:es|ing|ed|ement)",
    r"webinar", r"podcast", r"stormcast", r"livestream", r"newsletter(?: round \d+)?", r"weekly (?:digest|roundup|recap)",
    r"case study", r"customer stor(?:y|ies)", r"named (?:a )?leader", r"recogni[sz]ed", r"appoints?", r"raises? \$[\d.,]+",
    r"series [a-e]\b", r"funding", r"acquires?", r"agrees to acquire", r"acquisition", r"earnings", r"keynote",
    r"how to (?:choose|pick|buy|set up|use|get started|create)", r"beginner['’]?s?", r"tutorial", r"sponsored",
    r"free trial", r"award", r"wins? best", r"participants needed", r"first time learning",
)
_NON_THREAT_TITLE_RE = re.compile(r"(?<![a-z0-9])(?:" + "|".join(_NON_THREAT_TITLE) + r")(?![a-z0-9])", re.IGNORECASE)

# "<Product Name> 9.6" / "v2.0.1": a version number in a title with no threat vocabulary is a product release.
_VERSION_RE = re.compile(
    r"\b[A-Z][A-Za-z0-9]+(?: [A-Z][A-Za-z0-9]+){0,3} v?\d{1,3}\.\d{1,2}(?:\.\d{1,3})?\b"
    r"(?!\s*(?:%|(?i:percent|million|billion|thousand)|[KMGT]B\b|x\b))"
)

_OPERATION_RE = re.compile(r"\bOperation [A-Z][A-Za-z0-9]+")
_TAG_RE = re.compile(r"<[^>]+>")
SUMMARY_MIN_DISTINCT_TERMS = 2
_SUMMARY_LIMIT = 4000


def threat_terms(text: object) -> set:
    """Distinct lower-cased threat-vocabulary matches in ``text`` (HTML tags and entities ignored)."""
    cleaned = _html.unescape(_TAG_RE.sub(" ", str(text or "")))
    return {match.group(0).lower() for match in _THREAT_RE.finditer(cleaned)}


def assess_third_party(title: object, summary: object) -> Tuple[bool, str]:
    """Return ``(is_threat_event, reason)`` for a third-party article.

    ``reason`` is a stable short code: ``threat_term_in_title``, ``threat_terms_in_summary``,
    ``non_threat_title_pattern``, ``product_release``, ``bare_question`` or ``no_threat_signal``.
    """
    title_text = str(title or "").strip()
    if threat_terms(title_text) or _OPERATION_RE.search(title_text):
        return True, "threat_term_in_title"
    if _NON_THREAT_TITLE_RE.search(title_text):
        return False, "non_threat_title_pattern"
    if _VERSION_RE.search(title_text):
        return False, "product_release"
    if title_text.endswith("?"):
        return False, "bare_question"
    if len(threat_terms(str(summary or "")[:_SUMMARY_LIMIT])) >= SUMMARY_MIN_DISTINCT_TERMS:
        return True, "threat_terms_in_summary"
    return False, "no_threat_signal"
