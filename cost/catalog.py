"""
cost/catalog.py — Remediation catalog lookup.

Maps a Finding (or maturity gap) to a CostLineItem using the priority order:
  1. cve_id exact match  (remediation_catalog.cve_overrides)
  2. service match       (remediation_catalog.service_entries)
  3. deal tier match     (remediation_catalog.tier_entries)
  4. default fallback    (remediation_catalog.default)

For maturity gaps, use lookup_maturity_gap().
"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from config.loader import get_remediation_catalog, get_labour_rate, get_effort_hours, get_tool_cost
from cost.schema import (
    CostLineItem,
    CostTriple,
    RemediationCategory,
    CapexOpex,
    CostConfidence,
    ReviewFlag,
)

if TYPE_CHECKING:
    from analysis.schema import Finding


# ── Category enum mapping ─────────────────────────────────────────────────────
_CAT_MAP = {cat.value: cat for cat in RemediationCategory}
_CE_MAP  = {ce.value: ce   for ce  in CapexOpex}
_CONF_MAP = {c.value: c    for c   in CostConfidence}
_FLAG_MAP = {f.value: f    for f   in ReviewFlag}


def _parse_category(val: str) -> RemediationCategory:
    return _CAT_MAP.get(val, RemediationCategory.CONFIGURATION)


def _parse_capex_opex(val: str) -> CapexOpex:
    return _CE_MAP.get(val, CapexOpex.OPEX)


def _parse_confidence(val: str) -> CostConfidence:
    return _CONF_MAP.get(val, CostConfidence.MEDIUM)


def _parse_flag(val: str) -> Optional[ReviewFlag]:
    return _FLAG_MAP.get(val)


def _build_cost_triple(entry: dict) -> CostTriple:
    """
    Build a CostTriple from a catalog entry.

    Supports two forms:
    1. labour_role + labour_hours_key  — look up both from pricing_benchmarks
    2. labour_hours: {low, base, high} — inline hours, use labour_role for rate

    Optionally adds add_tool_key annual cost.
    """
    role     = entry.get("labour_role", "security_engineer")
    hours_key = entry.get("labour_hours_key")
    inline_hours = entry.get("labour_hours")

    # Get labour rate (per hour)
    rate_low  = get_labour_rate(role, "low")
    rate_base = get_labour_rate(role, "base")
    rate_high = get_labour_rate(role, "high")

    # Get effort hours
    if hours_key:
        h_low  = get_effort_hours(hours_key, "low")
        h_base = get_effort_hours(hours_key, "base")
        h_high = get_effort_hours(hours_key, "high")
    elif inline_hours and isinstance(inline_hours, dict):
        h_low  = float(inline_hours.get("low",  4))
        h_base = float(inline_hours.get("base", 16))
        h_high = float(inline_hours.get("high", 40))
    else:
        h_low, h_base, h_high = 4.0, 16.0, 40.0

    cost_low  = rate_low  * h_low
    cost_base = rate_base * h_base
    cost_high = rate_high * h_high

    # Add tool/licence cost if specified
    tool_key = entry.get("add_tool_key")
    if tool_key:
        cost_low  += get_tool_cost(tool_key, "low")
        cost_base += get_tool_cost(tool_key, "base")
        cost_high += get_tool_cost(tool_key, "high")

    return CostTriple(
        low=round(cost_low,  2),
        base=round(cost_base, 2),
        high=round(cost_high, 2),
    )


def _entry_to_line_item(
    entry:       dict,
    finding_ids: list[str],
    catalog_key: str,
    title_override: Optional[str] = None,
) -> CostLineItem:
    """Convert a catalog entry dict into a CostLineItem."""
    cost   = _build_cost_triple(entry)
    flags  = []
    raw_flag = entry.get("review_flag")
    if raw_flag:
        parsed = _parse_flag(raw_flag)
        if parsed:
            flags.append(parsed)

    # High-variance check: if high/low spread > 3×
    if cost.spread_ratio() > 3.0:
        flags.append(ReviewFlag.HIGH_VARIANCE)

    return CostLineItem(
        title=title_override or entry.get("title", "Security remediation"),
        description=entry.get("description", ""),
        category=_parse_category(entry.get("category", "configuration")),
        capex_opex=_parse_capex_opex(entry.get("capex_opex", "opex")),
        finding_ids=list(finding_ids),
        cost=cost,
        confidence=_parse_confidence(entry.get("confidence", "medium")),
        catalog_key=catalog_key,
        notes=entry.get("notes"),
        review_flags=flags,
    )


# ── Public API ────────────────────────────────────────────────────────────────

def lookup_finding(finding) -> CostLineItem:
    """
    Look up and return a CostLineItem for a single Finding.

    Lookup priority:
      1. cve_id  (exact match in cve_overrides)
      2. service (match in service_entries)
      3. deal tier (match in tier_entries)
      4. default
    """
    catalog = get_remediation_catalog()
    fid = finding.id

    # 1. CVE override
    if finding.cve_id:
        cve_overrides = catalog.get("cve_overrides", {})
        if finding.cve_id in cve_overrides:
            entry = cve_overrides[finding.cve_id]
            return _entry_to_line_item(entry, [fid], finding.cve_id)

    # 2. Service match
    service = (finding.service or "").lower().strip()
    service_entries = catalog.get("service_entries", {})
    if service in service_entries:
        entry = service_entries[service]
        return _entry_to_line_item(entry, [fid], f"service:{service}")

    # Partial service match (e.g. "http" matches "http/ftp")
    for svc_key, entry in service_entries.items():
        if svc_key in service:
            return _entry_to_line_item(entry, [fid], f"service:{svc_key}")

    # 3. Tier fallback
    tier = str(getattr(finding.deal_tier, "value", finding.deal_tier))
    tier_entries = catalog.get("tier_entries", {})
    if tier in tier_entries:
        entry = tier_entries[tier]
        item  = _entry_to_line_item(entry, [fid], f"tier:{tier}")
        # Deal-killer items always get a review flag
        if tier == "deal_killer" and ReviewFlag.DEAL_KILLER_ITEM not in item.review_flags:
            item.review_flags.append(ReviewFlag.DEAL_KILLER_ITEM)
        return item

    # 4. Default fallback
    default = catalog.get("default", {})
    item = _entry_to_line_item(default, [fid], "default")
    if ReviewFlag.MANUAL_REQUIRED not in item.review_flags:
        item.review_flags.append(ReviewFlag.MANUAL_REQUIRED)
    if ReviewFlag.ZERO_ESTIMATE not in item.review_flags:
        item.review_flags.append(ReviewFlag.ZERO_ESTIMATE)
    return item


def lookup_maturity_gap(gap) -> CostLineItem:
    """
    Look up and return a CostLineItem for a maturity gap.

    Args:
        gap: GapItem from analysis.standards_compare
    """
    catalog = get_remediation_catalog()
    maturity_entries = catalog.get("maturity_entries", {})

    entry = maturity_entries.get(gap.catalog_key)
    if not entry:
        # Fallback to default
        entry = catalog.get("default", {})

    return _entry_to_line_item(
        entry,
        finding_ids=[],
        catalog_key=gap.catalog_key,
        title_override=entry.get("title"),
    )
