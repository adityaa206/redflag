"""
cost/rollup.py — Aggregate CostLineItems into a CostRollup.

Entry point for the cost engine: takes a list of deduplicated line items and
produces the full CostRollup with:
  - total / capex / opex CostTriples
  - per-scenario CostScenario objects
  - per-category breakdown
  - flagged items list for the human review gate

Usage:
    from cost.rollup import build_rollup

    rollup = build_rollup(items, target="example.com")
"""
from __future__ import annotations

from cost.schema import CostLineItem, CostRollup, CostTriple, CapexOpex, ReviewFlag
from cost.scenario_engine import build_scenarios


def build_rollup(items: list[CostLineItem], target: str = "",
                 headcount_assumed: bool = False) -> CostRollup:
    """
    Build a CostRollup from a list of CostLineItems.

    Args:
        items:  deduplicated list of CostLineItems
        target: scan target string for labelling
        headcount_assumed: True if the integration budget used a default headcount
            (widens the accuracy band).

    Returns:
        CostRollup with all aggregated totals, bucket split, accuracy and flags.
    """
    if not items:
        return CostRollup(
            target=target,
            line_items=[],
            total=CostTriple.zero(),
            capex_total=CostTriple.zero(),
            opex_total=CostTriple.zero(),
            scenarios=[],
            by_category={},
            flagged_items=[],
        )

    # Aggregate totals
    total_low  = 0.0
    total_base = 0.0
    total_high = 0.0
    capex_low  = 0.0
    capex_base = 0.0
    capex_high = 0.0
    opex_low   = 0.0
    opex_base  = 0.0
    opex_high  = 0.0

    # Per-category accumulation: {category_value: {low, base, high}}
    cat_totals: dict[str, dict[str, float]] = {}

    # Bucket accumulation: remediation vs integration
    bucket_totals: dict[str, dict[str, float]] = {
        "remediation": {"low": 0.0, "base": 0.0, "high": 0.0},
        "integration": {"low": 0.0, "base": 0.0, "high": 0.0},
    }

    for item in items:
        c = item.cost

        total_low  += c.low
        total_base += c.base
        total_high += c.high

        bucket = getattr(item, "bucket", "remediation") or "remediation"
        bt = bucket_totals.setdefault(bucket, {"low": 0.0, "base": 0.0, "high": 0.0})
        bt["low"]  += c.low
        bt["base"] += c.base
        bt["high"] += c.high

        ce = str(getattr(item.capex_opex, "value", item.capex_opex))
        if ce == CapexOpex.CAPEX.value:
            capex_low  += c.low
            capex_base += c.base
            capex_high += c.high
        elif ce == CapexOpex.OPEX.value:
            opex_low   += c.low
            opex_base  += c.base
            opex_high  += c.high
        else:  # MIXED
            capex_low  += c.low  * 0.5
            capex_base += c.base * 0.5
            capex_high += c.high * 0.5
            opex_low   += c.low  * 0.5
            opex_base  += c.base * 0.5
            opex_high  += c.high * 0.5

        # Per-category
        cat = str(getattr(item.category, "value", item.category))
        if cat not in cat_totals:
            cat_totals[cat] = {"low": 0.0, "base": 0.0, "high": 0.0}
        cat_totals[cat]["low"]  += c.low
        cat_totals[cat]["base"] += c.base
        cat_totals[cat]["high"] += c.high

    # Build scenarios
    scenarios = build_scenarios(items)

    # Estimate accuracy (± band + confidence %) across the whole budget
    from cost.day1_costing import compute_accuracy
    band_pct, accuracy_pct = compute_accuracy(items, headcount_assumed)

    def _triple(d: dict) -> CostTriple:
        return CostTriple(low=round(d["low"], 2), base=round(d["base"], 2), high=round(d["high"], 2))

    # Collect flagged items (any item with review_flags)
    flagged_ids = [item.id for item in items if item.needs_review]

    return CostRollup(
        target=target,
        line_items=list(items),
        total=CostTriple(
            low=round(total_low,  2),
            base=round(total_base, 2),
            high=round(total_high, 2),
        ),
        capex_total=CostTriple(
            low=round(capex_low,  2),
            base=round(capex_base, 2),
            high=round(capex_high, 2),
        ),
        opex_total=CostTriple(
            low=round(opex_low,  2),
            base=round(opex_base, 2),
            high=round(opex_high, 2),
        ),
        scenarios=scenarios,
        by_category={k: {"low": round(v["low"], 2), "base": round(v["base"], 2), "high": round(v["high"], 2)}
                     for k, v in cat_totals.items()},
        remediation_total=_triple(bucket_totals["remediation"]),
        integration_total=_triple(bucket_totals["integration"]),
        accuracy_band_pct=band_pct,
        accuracy_pct=accuracy_pct,
        flagged_items=flagged_ids,
    )


def run_cost_pipeline(
    findings: list,
    gap_report=None,
    target: str = "",
    include_maturity_gaps: bool = True,
    blueprint=None,
    include_integration: bool = True,
    headcount=None,
) -> CostRollup:
    """
    Full cost pipeline: estimate → deduplicate → scenario → rollup.

    Args:
        findings:              triaged Finding objects
        gap_report:            GapReport from standards_compare (optional)
        target:                scan target string
        include_maturity_gaps: whether to include maturity gap costs
        blueprint:             Day1Blueprint (optional) — prices the recommended
                               connectivity model as the integration budget
        include_integration:   whether to include the Day-1 integration budget
        headcount:             acquired-company user count (drives per-user costs);
                               None falls back to the catalog default

    Returns:
        CostRollup ready for display and export.
    """
    from cost.estimator   import estimate_from_findings, estimate_from_gaps
    from cost.deduplicator import deduplicate

    # Estimate remediation (findings + maturity gaps) — deduplicated
    items = estimate_from_findings(findings)
    if include_maturity_gaps and gap_report:
        items += estimate_from_gaps(gap_report)
    items = deduplicate(items)

    # Estimate the Day-1 integration budget (NOT deduplicated against remediation —
    # it's a separate bucket) and note whether headcount was assumed.
    headcount_assumed = False
    if include_integration and blueprint is not None:
        from cost.day1_costing import estimate_from_day1
        day1_items = estimate_from_day1(blueprint, headcount=headcount)
        items += day1_items
        headcount_assumed = not (headcount and int(headcount) > 0)

    return build_rollup(items, target=target, headcount_assumed=headcount_assumed)
