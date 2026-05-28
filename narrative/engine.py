"""
narrative/engine.py — Builds context dicts from RedFlag data objects and
delegates to narrative/blocks.py for block selection and rendering.

Usage:
    from narrative.engine import build_executive_summary, build_finding_narrative

All functions are pure (no side effects, no external calls).
"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from narrative.blocks import select_block, select_all_blocks

if TYPE_CHECKING:
    from analysis.schema import Finding
    from analysis.maturity import MaturityAssessment
    from cost.schema import CostRollup, ScenarioType


# ── Context builders ──────────────────────────────────────────────────────────

def _findings_context(findings: list) -> dict:
    """Build a context dict from a list of Finding objects."""
    if not findings:
        return {
            "total_count": 0,
            "deal_killer_count": 0,
            "critical_count": 0,
            "moderate_count": 0,
            "has_deal_killers": False,
            "has_critical": False,
            "has_moderate": False,
            "top_deal_killer_title": "",
            "target": "",
        }

    tier_counts = {}
    for f in findings:
        t = str(getattr(f.deal_tier, "value", f.deal_tier))
        tier_counts[t] = tier_counts.get(t, 0) + 1

    dk_findings = [
        f for f in findings
        if str(getattr(f.deal_tier, "value", f.deal_tier)) == "deal_killer"
    ]
    top_dk_title = dk_findings[0].title if dk_findings else ""

    n_dk   = tier_counts.get("deal_killer", 0)
    n_crit = tier_counts.get("critical", 0)
    n_mod  = tier_counts.get("moderate", 0)

    return {
        "total_count":         len(findings),
        "deal_killer_count":   n_dk,
        "critical_count":      n_crit,
        "moderate_count":      n_mod,
        "has_deal_killers":    n_dk > 0,
        "has_critical":        n_crit > 0,
        "has_moderate":        n_mod > 0,
        "top_deal_killer_title": top_dk_title,
    }


def _maturity_context(assessment) -> dict:
    """Build context dict from a MaturityAssessment."""
    if not assessment:
        return {
            "has_maturity_deal_blockers": False,
            "has_maturity_gaps": False,
            "maturity_blocker_count": 0,
            "maturity_blocker_domains": "",
            "maturity_gap_count": 0,
            "maturity_gap_domains": "",
        }

    blocker_labels = [
        ds.label for ds in assessment.domain_scores
        if ds.is_deal_blocker
    ]
    gap_labels = [
        ds.label for ds in assessment.domain_scores
        if ds.is_below_acceptable and not ds.is_deal_blocker
    ]

    return {
        "has_maturity_deal_blockers": len(blocker_labels) > 0,
        "has_maturity_gaps":          len(gap_labels) > 0,
        "maturity_blocker_count":     len(blocker_labels),
        "maturity_blocker_domains":   ", ".join(blocker_labels),
        "maturity_gap_count":         len(gap_labels),
        "maturity_gap_domains":       ", ".join(gap_labels),
        "overall_maturity_score":     getattr(assessment, "overall_score", 0.0),
    }


def _cost_context(rollup) -> dict:
    """Build context dict from a CostRollup."""
    if not rollup:
        return {
            "cost_low":              0,
            "cost_base":             0,
            "cost_high":             0,
            "base_cost_above_50k":   False,
            "base_cost_above_250k":  False,
            "base_cost_above_1m":    False,
            "capex_pct":             0,
            "opex_pct":              0,
            "dominant_cost_type":    "operational",
            "top_cost_category":     "patching",
        }

    base = rollup.total.base if rollup.total else 0
    low  = rollup.total.low  if rollup.total else 0
    high = rollup.total.high if rollup.total else 0

    capex_base = rollup.capex_total.base if rollup.capex_total else 0
    opex_base  = rollup.opex_total.base  if rollup.opex_total  else 0

    capex_pct = round(capex_base / base * 100) if base else 0
    opex_pct  = 100 - capex_pct

    dominant = "capital" if capex_pct >= 50 else "operational"

    # Top category by base cost
    by_cat = rollup.by_category or {}
    top_cat = max(by_cat.items(), key=lambda kv: kv[1].get("base", 0), default=("patching", {}))[0]

    def fmt(v: float) -> str:
        if v >= 1_000_000:
            return f"{v/1_000_000:.1f}M"
        if v >= 1_000:
            return f"{v/1_000:.0f}K"
        return str(int(v))

    return {
        "cost_low":              fmt(low),
        "cost_base":             fmt(base),
        "cost_high":             fmt(high),
        "base_cost_above_50k":   base > 50_000,
        "base_cost_above_250k":  base > 250_000,
        "base_cost_above_1m":    base > 1_000_000,
        "capex_pct":             capex_pct,
        "opex_pct":              opex_pct,
        "dominant_cost_type":    dominant,
        "top_cost_category":     top_cat.replace("_", " "),
    }


def _finding_context(finding) -> dict:
    """Build context dict from a single Finding."""
    exploit = str(getattr(finding.exploit_status, "value", finding.exploit_status))
    exposure = str(getattr(finding.exposure, "value", finding.exposure))
    sensitivity = str(getattr(finding.data_sensitivity, "value", finding.data_sensitivity))
    tier = str(getattr(finding.deal_tier, "value", finding.deal_tier))

    return {
        "exploit_status":    exploit,
        "exposure":          exposure,
        "data_sensitivity":  sensitivity,
        "deal_tier":         tier,
        "cvss_score":        finding.cvss_score,
        "cvss_above_8":      finding.cvss_score >= 8.0,
        "title":             finding.title,
        "cve_id":            finding.cve_id or "",
        "host":              finding.host or "",
        "service":           finding.service or "",
    }


# ── Public API ────────────────────────────────────────────────────────────────

def build_executive_summary(
    findings: list,
    target: str = "",
    assessment=None,
    rollup=None,
) -> str:
    """
    Build the executive summary narrative paragraph.

    Args:
        findings:   list of triaged Finding objects
        target:     scan target string
        assessment: MaturityAssessment (optional)
        rollup:     CostRollup (optional)

    Returns:
        Rendered narrative string.
    """
    ctx = {**_findings_context(findings), "target": target}
    text = select_block("executive_summary", ctx)
    return text or f"Assessment of {target} complete. {len(findings)} findings identified."


def build_maturity_narrative(assessment) -> str:
    """Build maturity section narrative paragraph."""
    if not assessment:
        return "No maturity assessment has been completed."
    ctx  = _maturity_context(assessment)
    text = select_block("maturity_summary", ctx)
    return text or "Maturity assessment complete."


def build_cost_narrative(rollup) -> str:
    """Build cost section narrative paragraph."""
    if not rollup:
        return "No cost estimate has been generated."
    ctx  = _cost_context(rollup)
    text = select_block("cost_summary", ctx)
    return text or "Cost estimation complete."


def build_finding_narrative(finding) -> str:
    """
    Build contextual narrative for a single finding.
    Returns the first matching finding_detail block.
    """
    ctx  = _finding_context(finding)
    text = select_block("finding_detail", ctx)
    return text or ""


def build_remediation_priority(finding) -> str:
    """Return the remediation priority guidance for a finding."""
    ctx  = _finding_context(finding)
    text = select_block("remediation_priority", ctx)
    return text or ""


def build_full_context(
    findings: list,
    target: str = "",
    assessment=None,
    rollup=None,
) -> dict:
    """
    Build a single merged context dict from all data sources.
    Useful for passing to custom block selectors.
    """
    return {
        **_findings_context(findings),
        **_maturity_context(assessment),
        **_cost_context(rollup),
        "target": target,
    }
