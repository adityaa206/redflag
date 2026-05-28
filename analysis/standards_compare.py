"""
analysis/standards_compare.py — Compare a MaturityAssessment against the
corporate standard and generate a structured gap report.

Returns a list of GapItem objects that can be consumed by the narrative engine
and the cost estimator (each gap maps to a maturity_entry in the remediation
catalog).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from analysis.maturity import MaturityAssessment, DomainScore, MaturityGapSeverity
from config.loader import get_domain_standard


@dataclass
class GapItem:
    """A single maturity gap with context for cost estimation and narrative."""
    domain:             str
    label:              str
    current_score:      float
    acceptable_min:     int
    recommended:        int
    gap_severity:       MaturityGapSeverity
    gap_to_acceptable:  float
    gap_to_recommended: float
    rationale:          str
    catalog_key:        str   # key for maturity_entries in remediation_catalog.yaml
    is_deal_blocker:    bool


@dataclass
class GapReport:
    """Full gap report for a MaturityAssessment."""
    gaps:              list[GapItem] = field(default_factory=list)
    deal_blocker_gaps: list[GapItem] = field(default_factory=list)
    below_min_gaps:    list[GapItem] = field(default_factory=list)
    # Domains at or above acceptable_min but below recommended
    improvement_gaps:  list[GapItem] = field(default_factory=list)

    @property
    def has_deal_blockers(self) -> bool:
        return len(self.deal_blocker_gaps) > 0

    @property
    def has_any_gaps(self) -> bool:
        return len(self.gaps) > 0

    @property
    def total_gap_count(self) -> int:
        return len(self.gaps)


def compare_to_standard(assessment: MaturityAssessment) -> GapReport:
    """
    Compare a MaturityAssessment against the corporate standard.

    Returns a GapReport with categorised gaps for each domain that falls
    below the recommended level.
    """
    gaps: list[GapItem]       = []
    deal_blockers: list[GapItem] = []
    below_min: list[GapItem]  = []
    improvements: list[GapItem] = []

    for ds in assessment.domain_scores:
        # Only include domains with any gaps
        if ds.gap_severity == MaturityGapSeverity.AT_TARGET:
            continue

        catalog_key = f"{ds.domain}_gap"

        item = GapItem(
            domain=ds.domain,
            label=ds.label,
            current_score=ds.score,
            acceptable_min=ds.acceptable_min,
            recommended=ds.recommended,
            gap_severity=ds.gap_severity,
            gap_to_acceptable=ds.gap_to_acceptable,
            gap_to_recommended=ds.gap_to_recommended,
            rationale=ds.rationale,
            catalog_key=catalog_key,
            is_deal_blocker=ds.is_deal_blocker,
        )

        if ds.gap_severity == MaturityGapSeverity.DEAL_BLOCKER:
            deal_blockers.append(item)
            gaps.append(item)
        elif ds.gap_severity == MaturityGapSeverity.BELOW_MIN:
            below_min.append(item)
            gaps.append(item)
        elif ds.gap_severity == MaturityGapSeverity.ACCEPTABLE:
            improvements.append(item)
            gaps.append(item)

    return GapReport(
        gaps=gaps,
        deal_blocker_gaps=deal_blockers,
        below_min_gaps=below_min,
        improvement_gaps=improvements,
    )


def format_gap_summary(gap_report: GapReport) -> str:
    """Return a compact text summary of the gap report (for UI display)."""
    lines = []

    if gap_report.deal_blocker_gaps:
        domains = ", ".join(g.label for g in gap_report.deal_blocker_gaps)
        lines.append(f"DEAL-BLOCKER gaps: {domains}")

    if gap_report.below_min_gaps:
        domains = ", ".join(g.label for g in gap_report.below_min_gaps)
        lines.append(f"Below acceptable minimum: {domains}")

    if gap_report.improvement_gaps:
        domains = ", ".join(g.label for g in gap_report.improvement_gaps)
        lines.append(f"Improvement recommended: {domains}")

    if not lines:
        return "All assessed domains meet or exceed the recommended maturity level."

    return "\n".join(lines)
