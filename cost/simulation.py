"""
cost/simulation.py — statistically honest budget uncertainty.

Replaces "average the ± bands" (which treats all errors as fully correlated and
overstates aggregate uncertainty) with proper variance aggregation:

  1. Each line item is a triangular distribution (low, base, high) whose spread
     is widened by its sourced confidence (low-confidence items get wider).
  2. Items are aggregated with PARTIAL correlation — independent estimate errors
     partly cancel (diversification, which tightens the band), but a common-mode
     market factor keeps it from getting unrealistically tight.
  3. Yields an 80% confidence interval (P10–P90) and an accuracy % that is both
     tighter and more defensible than summing worst cases.

Deterministic, pure stdlib (closed-form — no Monte Carlo sampling noise).
"""
from __future__ import annotations

import math
from dataclasses import dataclass

# confidence → how much to widen the (low, high) range around base
_CONF_WIDEN = {"high": 1.0, "medium": 1.25, "low": 1.6}
_Z80 = 1.2816          # z-score for an 80% (P10–P90) two-sided interval
_CORRELATION = 0.35    # common-mode correlation across items (0=indep, 1=full)
_ASSUMED_WIDEN = 1.15  # extra spread when the headcount is a default guess
_BAND_MIN, _BAND_MAX = 8.0, 55.0


@dataclass
class Uncertainty:
    expected: float      # base-case total (the P50 anchor)
    std: float           # effective aggregate standard deviation
    p10: float
    p50: float
    p90: float
    band_pct: float      # ± around p50, percent
    accuracy_pct: float  # 100 - band_pct


def _conf(x) -> str:
    return str(getattr(x, "value", x))


def estimate_uncertainty(items, headcount_assumed: bool = False) -> Uncertainty:
    """Variance-based 80% confidence interval + accuracy % over cost line items."""
    if not items:
        return Uncertainty(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

    base_total = 0.0
    sum_var = 0.0   # Σ σ_i²  (independent aggregation)
    sum_std = 0.0   # Σ σ_i   (fully-correlated aggregation)

    for it in items:
        a = float(it.cost.low)
        m = float(it.cost.base)
        b = float(it.cost.high)
        f = _CONF_WIDEN.get(_conf(it.confidence), 1.25)
        a2 = max(0.0, m - (m - a) * f)   # confidence-widened low
        b2 = m + (b - m) * f             # confidence-widened high

        base_total += m
        # variance of a triangular(a2, m, b2) distribution
        var = (a2 * a2 + m * m + b2 * b2 - a2 * m - a2 * b2 - m * b2) / 18.0
        var = max(0.0, var)
        sum_var += var
        sum_std += math.sqrt(var)

    if base_total <= 0:
        return Uncertainty(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

    indep_std = math.sqrt(sum_var)
    eff_std = _CORRELATION * sum_std + (1.0 - _CORRELATION) * indep_std

    half = _Z80 * eff_std
    if headcount_assumed:
        half *= _ASSUMED_WIDEN

    band_pct = min(_BAND_MAX, max(_BAND_MIN, half / base_total * 100.0))
    half = band_pct / 100.0 * base_total   # re-derive after clamping the band

    p50 = base_total
    return Uncertainty(
        expected=round(base_total, 2),
        std=round(eff_std, 2),
        p10=round(max(0.0, p50 - half), 2),
        p50=round(p50, 2),
        p90=round(p50 + half, 2),
        band_pct=round(band_pct, 1),
        accuracy_pct=round(100.0 - band_pct, 1),
    )
