"""Tests for the variance-based budget uncertainty (cost/simulation.py)."""
from cost.simulation import estimate_uncertainty
from cost.schema import (
    CostLineItem, CostTriple, RemediationCategory, CapexOpex, CostConfidence,
)


def _item(low, base, high, conf=CostConfidence.MEDIUM):
    return CostLineItem(
        title="x", category=RemediationCategory.TOOLING, capex_opex=CapexOpex.OPEX,
        cost=CostTriple(low=low, base=base, high=high), confidence=conf,
    )


def test_empty_is_zero():
    u = estimate_uncertainty([])
    assert u.accuracy_pct == 0.0 and u.p50 == 0.0


def test_interval_is_ordered():
    u = estimate_uncertainty([_item(80, 100, 140), _item(40, 50, 70)])
    assert u.p10 < u.p50 < u.p90
    assert 0 < u.accuracy_pct < 100
    assert u.p50 == 150.0   # sum of the two base cases


def test_diversification_tightens_the_band():
    # aggregating 10 independent items yields a TIGHTER % band than one alone
    one = estimate_uncertainty([_item(50, 100, 200)])
    ten = estimate_uncertainty([_item(50, 100, 200)] * 10)
    assert ten.band_pct < one.band_pct


def test_low_confidence_widens_the_band():
    hi = estimate_uncertainty([_item(80, 100, 140, CostConfidence.HIGH)])
    lo = estimate_uncertainty([_item(80, 100, 140, CostConfidence.LOW)])
    assert lo.band_pct > hi.band_pct


def test_assumed_headcount_widens_the_band():
    known = estimate_uncertainty([_item(80, 100, 140)], headcount_assumed=False)
    assumed = estimate_uncertainty([_item(80, 100, 140)], headcount_assumed=True)
    assert assumed.band_pct >= known.band_pct
