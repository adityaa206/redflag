"""
cost/day1_costing.py — price the Day-1 INTEGRATION plan.

Turns the connectivity model that analysis/day1.py recommends into costed
CostLineItems (bucket="integration"), separate from the vulnerability-remediation
costs the rest of the engine produces. Also costs *every* rung of the ladder so
the UI can show the price of integrating faster, and computes an accuracy readout
(±% + confidence %) from each item's sourced confidence.

All numbers come from config/day1_cost_catalog.yaml (sourced, 2026). Pure and
deterministic — no Reflex, no network.
"""
from __future__ import annotations

from config.loader import get_day1_cost_catalog
from cost.schema import (
    CostLineItem, CostTriple, RemediationCategory, CapexOpex, CostConfidence, ReviewFlag,
)

_CATEGORY = {c.value: c for c in RemediationCategory}
_CAPEX = {c.value: c for c in CapexOpex}
_CONF = {c.value: c for c in CostConfidence}

_LADDER = ["isolate", "broker", "federate", "integrate"]


def _assumptions(catalog: dict) -> dict:
    return catalog.get("assumptions", {}) or {}


def _scale_triple(item: dict, headcount: int, months: int,
                  tsa_months: int, priv_ratio: float) -> tuple[float, float, float]:
    """Apply an item's `scale` to headcount/duration → (low, base, high) USD."""
    low = float(item.get("low", 0))
    base = float(item.get("base", 0))
    high = float(item.get("high", 0))
    scale = str(item.get("scale", "fixed"))

    if scale == "fixed":
        mult = 1.0
    elif scale == "per_user":
        mult = headcount
    elif scale == "per_user_year":
        mult = headcount
    elif scale == "per_user_month":
        mult = headcount * months
    elif scale == "per_priv_user_year":
        mult = max(1, round(headcount * priv_ratio))
    elif scale == "tsa_runrate":
        mult = headcount * tsa_months
    else:
        mult = 1.0
    return low * mult, base * mult, high * mult


def _item_to_line(item: dict, headcount: int, months: int,
                  tsa_months: int, priv_ratio: float, model_key: str) -> CostLineItem:
    low, base, high = _scale_triple(item, headcount, months, tsa_months, priv_ratio)
    cost = CostTriple(low=round(low, 2), base=round(base, 2), high=round(high, 2))
    flags: list[ReviewFlag] = []
    if cost.spread_ratio() > 3.0:
        flags.append(ReviewFlag.HIGH_VARIANCE)
    return CostLineItem(
        title=item.get("title", item.get("key", "Integration item")),
        description=item.get("source", ""),
        category=_CATEGORY.get(str(item.get("category", "process")), RemediationCategory.PROCESS),
        capex_opex=_CAPEX.get(str(item.get("capex_opex", "capex")), CapexOpex.CAPEX),
        bucket="integration",
        cost=cost,
        confidence=_CONF.get(str(item.get("confidence", "medium")), CostConfidence.MEDIUM),
        review_flags=flags,
        catalog_key=f"day1.{model_key}.{item.get('key', '')}",
        notes=item.get("source"),
    )


def _resolve_headcount(headcount, catalog: dict) -> tuple[int, bool]:
    """Return (headcount, assumed?) — assumed=True when we fell back to default."""
    a = _assumptions(catalog)
    if headcount and int(headcount) > 0:
        return int(headcount), False
    return int(a.get("default_headcount", 250)), True


def estimate_from_day1(blueprint, headcount=None, catalog: dict | None = None) -> list[CostLineItem]:
    """Cost the RECOMMENDED connectivity model → integration CostLineItems."""
    if blueprint is None:
        return []
    catalog = catalog or get_day1_cost_catalog()
    a = _assumptions(catalog)
    n, _assumed = _resolve_headcount(headcount, catalog)
    months = int(a.get("opex_months", 12))
    tsa_months = int(a.get("tsa_months", 12))
    priv_ratio = float(a.get("privileged_user_ratio", 0.05))

    model_key = str(getattr(blueprint, "recommended_model", "isolate"))
    model = (catalog.get("models", {}) or {}).get(model_key, {})
    return [
        _item_to_line(it, n, months, tsa_months, priv_ratio, model_key)
        for it in model.get("items", [])
    ]


def cost_all_models(headcount=None, catalog: dict | None = None) -> dict[str, CostTriple]:
    """Cost every connectivity tier → {model_key: CostTriple}. The 'ladder'."""
    catalog = catalog or get_day1_cost_catalog()
    a = _assumptions(catalog)
    n, _assumed = _resolve_headcount(headcount, catalog)
    months = int(a.get("opex_months", 12))
    tsa_months = int(a.get("tsa_months", 12))
    priv_ratio = float(a.get("privileged_user_ratio", 0.05))

    out: dict[str, CostTriple] = {}
    models = catalog.get("models", {}) or {}
    for key in _LADDER:
        total = CostTriple.zero()
        for it in models.get(key, {}).get("items", []):
            low, base, high = _scale_triple(it, n, months, tsa_months, priv_ratio)
            total = total + CostTriple(low=round(low, 2), base=round(base, 2), high=round(high, 2))
        out[key] = total
    return out


def compute_accuracy(items: list, headcount_assumed: bool = False,
                     catalog: dict | None = None) -> tuple[float, float]:
    """Cost-weighted accuracy from item confidences → (±band_pct, accuracy_pct)."""
    catalog = catalog or get_day1_cost_catalog()
    bands = catalog.get("accuracy_bands", {"high": 15, "medium": 30, "low": 50})
    penalty = float(catalog.get("assumed_headcount_penalty", 8))
    if not items:
        return 0.0, 0.0
    tot = sum(float(i.cost.base) for i in items) or 1.0
    weighted = 0.0
    for i in items:
        conf = str(getattr(i.confidence, "value", i.confidence))
        weighted += float(i.cost.base) * float(bands.get(conf, 30))
    band = weighted / tot
    if headcount_assumed:
        band += penalty
    band = round(min(60.0, max(5.0, band)), 1)
    return band, round(100.0 - band, 1)
