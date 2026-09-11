import pytest

from sentinel.arena import ArenaLedger, ArenaPhase


def ready_for_market() -> ArenaLedger:
    ledger = ArenaLedger(self_service_ids={"sentinel.verify"})
    ledger.begin_critique()
    ledger.record_trial("a", "Output omitted provenance")
    ledger.record_trial("b", "Price is high for a single call")
    ledger.record_trial("c", "Schema is underspecified")
    ledger.submit_ranking(["a", "c", "b"])
    ledger.begin_market()
    return ledger


def test_cannot_rank_before_three_trials():
    ledger = ArenaLedger()
    ledger.begin_critique()
    ledger.record_trial("a", "Specific disagreement")
    with pytest.raises(ValueError, match="at least 3"):
        ledger.submit_ranking(["a"])


def test_disagreement_is_required():
    ledger = ArenaLedger()
    ledger.begin_critique()
    with pytest.raises(ValueError, match="specific disagreement"):
        ledger.record_trial("a", "   ")


def test_self_purchase_rejected():
    ledger = ready_for_market()
    with pytest.raises(ValueError, match="self-purchases"):
        ledger.record_purchase("sentinel.verify", 20)


def test_budget_overrun_rejected():
    ledger = ready_for_market()
    ledger.record_purchase("x", 60)
    with pytest.raises(ValueError, match="100-credit"):
        ledger.record_purchase("y", 50)


def test_finish_requires_spend_and_diversity():
    ledger = ready_for_market()
    ledger.record_purchase("x", 40)
    ledger.record_purchase("y", 40)
    with pytest.raises(ValueError, match="purchased_from_at_least_three_services"):
        ledger.finish()


def test_complete_arena_path():
    ledger = ready_for_market()
    ledger.record_purchase("x", 30)
    ledger.record_purchase("y", 30)
    ledger.record_purchase("z", 20)
    ledger.finish()

    assert ledger.phase is ArenaPhase.COMPLETE
    assert ledger.total_spend == 80
