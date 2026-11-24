"""Per-run accounting for the first-party public-delivery probe.

PROBLEM (CTI Blogger runs 9306 and 9307, 2026-11-24): the scheduler ranks first-party SOC dossiers first, and the
persisted retry queue re-selects the ones blocked last hour. While the live SOC Worker predates those dossiers every
one fails the delivery probe with HTTP 404. Each blocked item still consumed one of the 6 publication ATTEMPTS, a
budget whose stated purpose (_publication_attempt_limit) is to bound LLM/API work, yet the probe runs BEFORE any
hydration or LLM work and costs one HTTP GET. All 6 attempts went to blocked items, so no deliverable third-party
candidate was ever tried: published posts per run fell 4, 1, 0.

This module changes only how that cheap probe is accounted:

* RELIEF: an item that fails the probe does not count against the attempt budget (at most RELIEF_SLOTS of them),
  so the budget still bounds expensive work exactly as before and the total number of candidates examined stays
  bounded (attempt limit + RELIEF_SLOTS).
* CIRCUIT: after CIRCUIT_THRESHOLD CONSECUTIVE "origin not serving" answers in one run (HTTP 404 = not deployed, HTTP 5xx,
  or unreachable) the origin is treated as not serving dossiers: the remaining first-party candidates are skipped
  WITHOUT another request and are not offered as backfill, so the run reaches deliverable third-party reports. Any
  dossier that resolves resets the counter. Reasons about one item's content (wrong content type, canonical or title
  mismatch, bad size or URL) are judged per item and never open it.

Stateless by design: a fresh instance per run, nothing persisted. Once the SOC Worker serves its dossiers the first
probes pass and none of this ever triggers.
"""
from __future__ import annotations

import re

from .source_delivery_guard import is_first_party_dossier

NOT_DEPLOYED_REASON = "first_party_source_http_404"
UNREACHABLE_REASON = "first_party_source_unreachable"
_SERVER_ERROR = re.compile(r"first_party_source_http_5\d\d")
CIRCUIT_OPEN_REASON = "first_party_origin_not_serving_circuit_open"
RELIEF_SLOTS = 6
CIRCUIT_THRESHOLD = 3


def origin_not_serving(reason: str | None) -> bool:
    """True when a probe verdict says the SOC ORIGIN is not serving dossiers (404, 5xx, unreachable)."""
    return bool(reason) and (
        reason == NOT_DEPLOYED_REASON or reason == UNREACHABLE_REASON or _SERVER_ERROR.fullmatch(reason) is not None
    )


class SourceDeliveryBudget:
    def __init__(self, relief_slots: int = RELIEF_SLOTS, circuit_threshold: int = CIRCUIT_THRESHOLD) -> None:
        self.relief_slots = max(0, int(relief_slots))
        self.circuit_threshold = max(1, int(circuit_threshold))
        self.blocked = 0
        self.consecutive_not_deployed = 0
        self.circuit_open = False
        self.probes_skipped = 0

    def skips_probe(self, article) -> bool:
        """True when this first-party article must be blocked without asking the origin again."""
        return self.circuit_open and is_first_party_dossier(article)

    def record(self, article, reason: str | None) -> bool:
        """Record the probe verdict for one article. Returns True only when this call opened the circuit.

        ``reason`` is what the delivery check returned: None (verified or not a first-party dossier) or a block reason.
        """
        if reason == CIRCUIT_OPEN_REASON:
            self.blocked += 1
            self.probes_skipped += 1
            return False
        if reason is None:
            if is_first_party_dossier(article):
                self.consecutive_not_deployed = 0  # a dossier resolved: the origin is serving
            return False
        self.blocked += 1
        if not origin_not_serving(reason):
            return False
        self.consecutive_not_deployed += 1
        if not self.circuit_open and self.consecutive_not_deployed >= self.circuit_threshold:
            self.circuit_open = True
            return True
        return False

    def relieved_slots(self) -> int:
        return min(self.blocked, self.relief_slots)

    def attempt_budget_exhausted(self, queued: int, attempt_limit: int) -> bool:
        """The original rule (queued >= limit), with items that failed the cheap probe not counted (capped)."""
        return queued - self.relieved_slots() >= attempt_limit
