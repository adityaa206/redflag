"""
narrative/report_builder.py — Assembles the full narrative report dict from
all data sources.

Returns a structured dict (not a string) so the caller (Streamlit UI, PDF
generator, XLSX exporter) can render each section independently.

Usage:
    from narrative.report_builder import build_report

    report = build_report(findings, assessment=assessment, rollup=rollup, target="example.com")
    print(report["executive_summary"])
"""
from __future__ import annotations

from typing import Optional

from narrative.engine import (
    build_executive_summary,
    build_maturity_narrative,
    build_cost_narrative,
    build_finding_narrative,
    build_remediation_priority,
)


def build_report(
    findings:   list,
    target:     str  = "",
    assessment=None,
    rollup=None,
) -> dict:
    """
    Build the full narrative report as a structured dict.

    Keys:
      executive_summary  : str  — top-level deal assessment paragraph
      maturity_summary   : str  — maturity assessment paragraph (or "" if N/A)
      cost_summary       : str  — cost estimate paragraph (or "" if N/A)
      findings           : list[dict] — per-finding narrative
        Each dict has: title, tier, narrative, remediation_priority
      metadata           : dict — target, finding counts, generation timestamp
    """
    import datetime

    exec_summary = build_executive_summary(
        findings, target=target, assessment=assessment, rollup=rollup
    )

    mat_summary  = build_maturity_narrative(assessment) if assessment else ""
    cost_summary = build_cost_narrative(rollup)         if rollup     else ""

    finding_narratives = []
    for f in findings:
        tier = str(getattr(f.deal_tier, "value", f.deal_tier))
        finding_narratives.append({
            "id":                 f.id,
            "title":              f.title,
            "tier":               tier,
            "cvss":               f.cvss_score,
            "host":               f.host or "",
            "service":            f.service or "",
            "narrative":          build_finding_narrative(f),
            "remediation_priority": build_remediation_priority(f),
        })

    tier_counts = {}
    for f in findings:
        t = str(getattr(f.deal_tier, "value", f.deal_tier))
        tier_counts[t] = tier_counts.get(t, 0) + 1

    return {
        "executive_summary":  exec_summary,
        "maturity_summary":   mat_summary,
        "cost_summary":       cost_summary,
        "findings":           finding_narratives,
        "metadata": {
            "target":          target,
            "total_findings":  len(findings),
            "deal_killers":    tier_counts.get("deal_killer", 0),
            "critical":        tier_counts.get("critical", 0),
            "moderate":        tier_counts.get("moderate", 0),
            "manageable":      tier_counts.get("manageable", 0),
            "has_maturity":    assessment is not None,
            "has_cost":        rollup is not None,
            "generated_at":    datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
    }
