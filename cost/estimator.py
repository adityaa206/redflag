"""
cost/estimator.py — Build a list of raw CostLineItems from findings and
maturity gaps before deduplication.

Usage:
    from cost.estimator import estimate_from_findings, estimate_from_gaps

    raw_items = estimate_from_findings(findings)
    gap_items = estimate_from_gaps(gap_report)
    all_items = raw_items + gap_items
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from cost.catalog import lookup_finding, lookup_maturity_gap
from cost.schema import CostLineItem, ReviewFlag

if TYPE_CHECKING:
    from analysis.schema import Finding
    from analysis.standards_compare import GapReport


def estimate_from_findings(findings: list) -> list[CostLineItem]:
    """
    Generate a CostLineItem for each finding.

    Findings that are UNSCORED are skipped (no triage result yet).
    """
    items: list[CostLineItem] = []

    for finding in findings:
        tier = str(getattr(finding.deal_tier, "value", finding.deal_tier))
        if tier == "unscored":
            continue

        item = lookup_finding(finding)

        # Always flag deal-killer items for human review
        if tier == "deal_killer" and ReviewFlag.DEAL_KILLER_ITEM not in item.review_flags:
            item.review_flags.append(ReviewFlag.DEAL_KILLER_ITEM)

        items.append(item)

    return items


def estimate_from_gaps(gap_report) -> list[CostLineItem]:
    """
    Generate a CostLineItem for each maturity gap.

    Improvement gaps (below recommended but above acceptable_min) are included
    but not flagged as deal-killers.
    """
    items: list[CostLineItem] = []

    for gap in gap_report.gaps:
        item = lookup_maturity_gap(gap)
        items.append(item)

    return items
