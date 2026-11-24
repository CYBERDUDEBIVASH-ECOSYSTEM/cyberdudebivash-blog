"""SourceDeliveryBudget: per-run accounting for the cheap first-party delivery probe (see the module docstring)."""
from types import SimpleNamespace

import pytest

from automation.source_delivery_budget import (
    CIRCUIT_OPEN_REASON,
    CIRCUIT_THRESHOLD,
    NOT_DEPLOYED_REASON,
    RELIEF_SLOTS,
    UNREACHABLE_REASON,
    SourceDeliveryBudget,
    origin_not_serving,
)
from automation.source_delivery_guard import is_first_party_dossier, verify_public_first_party_source

FP = SimpleNamespace(url="https://blog.cyberdudebivash.in/posts/cve-2026-100001.html", title="x")
FP2 = SimpleNamespace(url="https://blog.cyberdudebivash.in/posts/cve-2026-100002.html", title="y")
TP = SimpleNamespace(url="https://news.example.test/story-1", title="z")


def test_constants_match_what_the_guard_actually_returns_for_a_404():
    # If these drifted apart the circuit could never open. The guard builds f"first_party_source_http_{status}".
    class Resp:
        status_code = 404
        headers = {}
        content = b""

    assert verify_public_first_party_source(FP, http_get=lambda *a, **k: Resp()) == NOT_DEPLOYED_REASON
    assert (RELIEF_SLOTS, CIRCUIT_THRESHOLD) == (6, 3)


class TestSharedScopePredicate:
    @pytest.mark.parametrize("url,expected", [
        ("https://blog.cyberdudebivash.in/posts/cve-2026-1.html", True),
        ("https://blog.cyberdudebivash.in/posts/anything.html", True),
        ("https://blog.cyberdudebivash.in/posts/", False),
        ("https://blog.cyberdudebivash.in/posts/data.json", False),      # historical non-HTML endpoints stay out of scope
        ("https://blog.cyberdudebivash.in/other/page.html", False),
        ("https://soc.cyberdudebivash.in/posts/x.html", False),          # other hosts are never probed
        ("https://news.example.test/posts/x.html", False),
        ("", False),
        (None, False),
    ])
    def test_scope(self, url, expected):
        assert is_first_party_dossier(SimpleNamespace(url=url)) is expected

    def test_missing_url_attribute_is_out_of_scope(self):
        assert is_first_party_dossier(SimpleNamespace()) is False

    def test_the_probe_ignores_out_of_scope_articles_without_any_request(self):
        def boom(*a, **k):
            raise AssertionError("no request may be made for an out-of-scope article")

        assert verify_public_first_party_source(TP, http_get=boom) is None
        assert verify_public_first_party_source(SimpleNamespace(url="https://blog.cyberdudebivash.in/posts/d.json"), http_get=boom) is None


class TestCircuit:
    def test_opens_on_exactly_the_third_consecutive_not_deployed_answer(self):
        b = SourceDeliveryBudget()
        assert b.record(FP, NOT_DEPLOYED_REASON) is False
        assert b.record(FP, NOT_DEPLOYED_REASON) is False
        assert b.circuit_open is False
        assert b.record(FP, NOT_DEPLOYED_REASON) is True   # opened by THIS call
        assert b.circuit_open is True
        assert b.record(FP, NOT_DEPLOYED_REASON) is False  # already open: reported only once

    def test_a_dossier_that_resolves_resets_the_count(self):
        b = SourceDeliveryBudget()
        b.record(FP, NOT_DEPLOYED_REASON)
        b.record(FP, NOT_DEPLOYED_REASON)
        b.record(FP2, None)                                 # a first-party dossier resolved: origin is serving
        assert b.consecutive_not_deployed == 0
        b.record(FP, NOT_DEPLOYED_REASON)
        b.record(FP, NOT_DEPLOYED_REASON)
        assert b.circuit_open is False

    def test_a_third_party_pass_does_not_count_as_proof_the_origin_serves(self):
        b = SourceDeliveryBudget()
        b.record(FP, NOT_DEPLOYED_REASON)
        b.record(FP, NOT_DEPLOYED_REASON)
        b.record(TP, None)                                  # irrelevant to the SOC origin
        b.record(FP, NOT_DEPLOYED_REASON)
        assert b.circuit_open is True

    @pytest.mark.parametrize("reason", [
        "first_party_source_wrong_content_type", "first_party_source_canonical_mismatch",
        "first_party_source_title_mismatch", "invalid_first_party_source_url", "first_party_source_probe_error",
        "first_party_source_invalid_body_size", "first_party_source_content_invalid",
        "first_party_source_http_403", "first_party_source_http_429", "first_party_source_http_301",
    ])
    def test_reasons_about_one_items_content_are_judged_per_item_and_never_open_the_circuit(self, reason):
        b = SourceDeliveryBudget()
        for _ in range(20):
            b.record(FP, reason)
        assert b.circuit_open is False
        assert b.blocked == 20  # they still count as blocked (and get relief)

    @pytest.mark.parametrize("reason", [
        NOT_DEPLOYED_REASON, UNREACHABLE_REASON, "first_party_source_http_500", "first_party_source_http_502",
        "first_party_source_http_503", "first_party_source_http_504", "first_party_source_http_599",
    ])
    def test_origin_not_serving_reasons_open_the_circuit_after_three_in_a_row(self, reason):
        b = SourceDeliveryBudget()
        assert [b.record(FP, reason) for _ in range(3)] == [False, False, True]
        assert origin_not_serving(reason) is True

    def test_a_streak_can_mix_404_5xx_and_unreachable(self):
        b = SourceDeliveryBudget()
        b.record(FP, NOT_DEPLOYED_REASON)
        b.record(FP, "first_party_source_http_503")
        assert b.record(FP, UNREACHABLE_REASON) is True

    @pytest.mark.parametrize("reason", [None, "", "first_party_source_http_404x", "first_party_source_http_6xx",
                                        "first_party_source_http_50", "first_party_source_http_5000", "x_first_party_source_http_500"])
    def test_origin_not_serving_is_exact(self, reason):
        assert origin_not_serving(reason) is False

    def test_a_content_level_block_in_between_does_not_reset_or_advance_the_count(self):
        b = SourceDeliveryBudget()
        b.record(FP, NOT_DEPLOYED_REASON)
        b.record(FP, "first_party_source_title_mismatch")
        b.record(FP, NOT_DEPLOYED_REASON)
        assert b.consecutive_not_deployed == 2 and b.circuit_open is False
        b.record(FP, NOT_DEPLOYED_REASON)
        assert b.circuit_open is True

    def test_skips_only_first_party_dossiers_and_only_once_open(self):
        b = SourceDeliveryBudget()
        assert b.skips_probe(FP) is False
        for _ in range(3):
            b.record(FP, NOT_DEPLOYED_REASON)
        assert b.skips_probe(FP) is True
        assert b.skips_probe(FP2) is True
        assert b.skips_probe(TP) is False                   # third-party items are never skipped

    def test_skipped_items_count_as_blocked_and_as_skipped_but_never_advance_the_circuit(self):
        b = SourceDeliveryBudget()
        for _ in range(3):
            b.record(FP, NOT_DEPLOYED_REASON)
        before = (b.blocked, b.consecutive_not_deployed)
        assert b.record(FP2, CIRCUIT_OPEN_REASON) is False
        assert (b.blocked, b.consecutive_not_deployed, b.probes_skipped) == (before[0] + 1, before[1], 1)

    def test_custom_thresholds_are_honoured_and_clamped(self):
        b = SourceDeliveryBudget(circuit_threshold=1)
        assert b.record(FP, NOT_DEPLOYED_REASON) is True
        assert SourceDeliveryBudget(circuit_threshold=0).circuit_threshold == 1
        assert SourceDeliveryBudget(relief_slots=-4).relief_slots == 0


class TestAttemptBudget:
    LIMIT = 6

    def test_without_blocks_it_is_the_original_rule_queued_ge_limit(self):
        b = SourceDeliveryBudget()
        assert [b.attempt_budget_exhausted(n, self.LIMIT) for n in (5, 6, 7)] == [False, True, True]

    def test_each_blocked_item_gives_one_slot_back_up_to_the_relief_cap(self):
        b = SourceDeliveryBudget()
        for blocked in range(1, 10):
            b.record(FP, "first_party_source_title_mismatch")
            relieved = min(blocked, 6)
            assert b.relieved_slots() == relieved
            # exactly at the boundary: queued - relieved == limit - 1 is allowed, == limit is exhausted
            assert b.attempt_budget_exhausted(self.LIMIT + relieved - 1, self.LIMIT) is False
            assert b.attempt_budget_exhausted(self.LIMIT + relieved, self.LIMIT) is True

    def test_the_total_number_of_candidates_ever_examined_is_bounded(self):
        b = SourceDeliveryBudget()
        for _ in range(100):
            b.record(FP, "first_party_source_title_mismatch")
        assert b.attempt_budget_exhausted(self.LIMIT + RELIEF_SLOTS, self.LIMIT) is True  # hard ceiling: 12

    def test_a_zero_limit_stays_exhausted(self):
        assert SourceDeliveryBudget().attempt_budget_exhausted(0, 0) is True
