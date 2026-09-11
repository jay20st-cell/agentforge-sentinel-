"""Arena obligation ledger.

This module does not invent SharedNet transport. It tracks the event rules locally so the
representative agent cannot accidentally finish a round while mandatory obligations are
still unmet.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ArenaPhase(str, Enum):
    PREP = "PREP"
    CRITIQUE = "CRITIQUE"
    MARKET = "MARKET"
    COMPLETE = "COMPLETE"


@dataclass(frozen=True)
class ProductTrial:
    product_id: str
    disagreement: str


@dataclass(frozen=True)
class Purchase:
    service_id: str
    credits: int


@dataclass
class ArenaLedger:
    """Tracks minimum competition obligations and fails closed on bad accounting."""

    phase: ArenaPhase = ArenaPhase.PREP
    trials: dict[str, ProductTrial] = field(default_factory=dict)
    ranking: tuple[str, ...] = ()
    purchases: list[Purchase] = field(default_factory=list)
    self_service_ids: set[str] = field(default_factory=set)

    MIN_TRIALS = 3
    MIN_SPEND = 80
    MIN_PURCHASED_SERVICES = 3

    def begin_critique(self) -> None:
        if self.phase is not ArenaPhase.PREP:
            raise ValueError(f"cannot begin critique from {self.phase}")
        self.phase = ArenaPhase.CRITIQUE

    def record_trial(self, product_id: str, disagreement: str) -> None:
        self._require_phase(ArenaPhase.CRITIQUE)
        product_id = product_id.strip()
        disagreement = disagreement.strip()
        if not product_id:
            raise ValueError("product_id must not be blank")
        if not disagreement:
            raise ValueError("every trial needs a specific disagreement")
        self.trials[product_id] = ProductTrial(product_id=product_id, disagreement=disagreement)

    def submit_ranking(self, product_ids: list[str] | tuple[str, ...]) -> None:
        self._require_phase(ArenaPhase.CRITIQUE)
        normalized = tuple(item.strip() for item in product_ids if item.strip())
        if len(set(normalized)) != len(normalized):
            raise ValueError("ranking must not contain duplicate products")
        if len(self.trials) < self.MIN_TRIALS:
            raise ValueError(f"must try at least {self.MIN_TRIALS} products before ranking")
        if not normalized:
            raise ValueError("ranking must not be empty")
        unknown = set(normalized) - set(self.trials)
        if unknown:
            raise ValueError(f"ranking contains untried products: {sorted(unknown)}")
        self.ranking = normalized

    def begin_market(self) -> None:
        self._require_phase(ArenaPhase.CRITIQUE)
        if len(self.trials) < self.MIN_TRIALS or not self.ranking:
            raise ValueError("critique obligations are not complete")
        self.phase = ArenaPhase.MARKET

    def record_purchase(self, service_id: str, credits: int) -> None:
        self._require_phase(ArenaPhase.MARKET)
        service_id = service_id.strip()
        if not service_id:
            raise ValueError("service_id must not be blank")
        if service_id in self.self_service_ids:
            raise ValueError("self-purchases do not satisfy Arena obligations")
        if not isinstance(credits, int) or credits <= 0:
            raise ValueError("credits must be a positive integer")
        if self.total_spend + credits > 100:
            raise ValueError("purchase would exceed the 100-credit Arena budget")
        self.purchases.append(Purchase(service_id=service_id, credits=credits))

    @property
    def total_spend(self) -> int:
        return sum(item.credits for item in self.purchases)

    @property
    def purchased_service_count(self) -> int:
        return len({item.service_id for item in self.purchases})

    def obligations(self) -> dict[str, bool | int]:
        return {
            "tried_at_least_three": len(self.trials) >= self.MIN_TRIALS,
            "specific_disagreement_per_trial": all(bool(item.disagreement.strip()) for item in self.trials.values()),
            "ranking_submitted": bool(self.ranking),
            "spent_at_least_80": self.total_spend >= self.MIN_SPEND,
            "purchased_from_at_least_three_services": self.purchased_service_count >= self.MIN_PURCHASED_SERVICES,
            "total_spend": self.total_spend,
            "unique_trials": len(self.trials),
            "unique_purchased_services": self.purchased_service_count,
        }

    def finish(self) -> None:
        self._require_phase(ArenaPhase.MARKET)
        status = self.obligations()
        required = (
            "tried_at_least_three",
            "specific_disagreement_per_trial",
            "ranking_submitted",
            "spent_at_least_80",
            "purchased_from_at_least_three_services",
        )
        missing = [name for name in required if not status[name]]
        if missing:
            raise ValueError(f"Arena obligations incomplete: {', '.join(missing)}")
        self.phase = ArenaPhase.COMPLETE

    def _require_phase(self, phase: ArenaPhase) -> None:
        if self.phase is not phase:
            raise ValueError(f"operation requires {phase}; current phase is {self.phase}")
