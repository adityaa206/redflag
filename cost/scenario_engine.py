"""
cost/scenario_engine.py — Generate low / base / high cost scenarios.

Each scenario uses the corresponding cost_triple value from every line item.
Returns a list[CostScenario] representing the three sensitivity analysis cases.
"""
from __future__ import annotations

from cost.schema import CostLineItem, CostScenario, ScenarioType, CapexOpex


def build_scenarios(items: list[CostLineItem]) -> list[CostScenario]:
    """
    Build low, base, and high scenarios from a list of line items.

    For each scenario type:
      - total_usd  = sum of all item.cost[scenario]
      - capex_usd  = sum of CAPEX items' cost[scenario]
      - opex_usd   = sum of OPEX items' cost[scenario]
      - MIXED items split 50/50 between capex and opex

    Returns a list of 3 CostScenario objects (low, base, high).
    """
    scenarios = []

    for scenario_type in (ScenarioType.LOW, ScenarioType.BASE, ScenarioType.HIGH):
        total  = 0.0
        capex  = 0.0
        opex   = 0.0

        for item in items:
            cost_val = item.cost.total(scenario_type)
            total   += cost_val

            ce = str(getattr(item.capex_opex, "value", item.capex_opex))
            if ce == CapexOpex.CAPEX.value:
                capex += cost_val
            elif ce == CapexOpex.OPEX.value:
                opex  += cost_val
            else:  # MIXED — split 50/50
                capex += cost_val * 0.5
                opex  += cost_val * 0.5

        scenarios.append(
            CostScenario(
                scenario_type=scenario_type,
                total_usd=round(total,  2),
                capex_usd=round(capex,  2),
                opex_usd=round(opex,   2),
                line_count=len(items),
            )
        )

    return scenarios
