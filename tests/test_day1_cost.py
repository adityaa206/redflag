"""Tests for the Day-1 integration budget (cost/day1_costing.py + rollup wiring)."""
from types import SimpleNamespace

from analysis.schema import Finding, ScannerSource, ExposureLevel, ExploitStatus, DataSensitivity
from analysis.triage import triage_all
from cost.day1_costing import estimate_from_day1, cost_all_models, compute_accuracy
from cost.rollup import run_cost_pipeline
from config.loader import get_day1_cost_catalog, reload_all


def _bp(model: str):
    return SimpleNamespace(recommended_model=model)


def _scored_finding():
    f = Finding(
        title="OpenSSH exposed", host="10.0.0.5", port=22, service="ssh",
        cvss_score=7.5, exposure=ExposureLevel.INTERNET_FACING,
        exploit_status=ExploitStatus.PUBLIC_EXPLOIT, data_sensitivity=DataSensitivity.SENSITIVE,
        scanner_source=ScannerSource.NMAP,
    )
    return triage_all([f])


def test_catalog_has_all_four_models():
    reload_all()
    cat = get_day1_cost_catalog()
    for m in ["isolate", "broker", "federate", "integrate"]:
        assert m in cat["models"]
        assert cat["models"][m]["items"], f"{m} has no items"


def test_estimate_prices_recommended_model_as_integration():
    items = estimate_from_day1(_bp("broker"), headcount=500)
    assert items
    assert all(i.bucket == "integration" for i in items)
    # per-user VDI scales with headcount (500 users × $45 × 12mo = $270k base)
    vdi = next(i for i in items if "VDI" in i.title or "DaaS" in i.title)
    assert vdi.cost.base == 500 * 45 * 12


def test_headcount_scales_the_budget():
    small = estimate_from_day1(_bp("federate"), headcount=100)
    big = estimate_from_day1(_bp("federate"), headcount=1000)
    tot_small = sum(i.cost.base for i in small)
    tot_big = sum(i.cost.base for i in big)
    assert tot_big > tot_small


def test_ladder_costs_all_tiers_positive():
    ladder = cost_all_models(headcount=250)
    assert set(ladder) == {"isolate", "broker", "federate", "integrate"}
    for key, triple in ladder.items():
        assert triple.base > 0, f"{key} costed zero"
    # integrate (migration + re-arch + PMO) outweighs federate
    assert ladder["integrate"].base > ladder["federate"].base


def test_pipeline_folds_integration_and_reports_accuracy():
    roll = run_cost_pipeline(_scored_finding(), blueprint=_bp("broker"), headcount=300)
    assert roll.integration_total.base > 0
    assert roll.remediation_total.base > 0
    # combined total covers both buckets
    assert round(roll.total.base, 2) == round(
        roll.remediation_total.base + roll.integration_total.base, 2)
    assert 0 < roll.accuracy_pct < 100
    assert roll.accuracy_band_pct > 0


def test_accuracy_drops_when_headcount_assumed():
    known = run_cost_pipeline([], blueprint=_bp("integrate"), headcount=500)
    assumed = run_cost_pipeline([], blueprint=_bp("integrate"), headcount=None)
    assert assumed.accuracy_pct <= known.accuracy_pct


def test_integration_excluded_when_no_blueprint():
    roll = run_cost_pipeline(_scored_finding())  # no blueprint
    assert roll.integration_total.base == 0


def test_vendor_quote_override_pins_item():
    items = estimate_from_day1(_bp("broker"), headcount=500,
                               overrides={"vdi_daas": 99000})
    vdi = next(i for i in items if "VDI" in i.title or "DaaS" in i.title)
    assert vdi.cost.base == 99000
    assert vdi.cost.low == 99000 and vdi.cost.high == 99000   # firm quote, no spread
    assert str(getattr(vdi.confidence, "value", vdi.confidence)) == "high"


def test_quote_improves_accuracy():
    bp = _bp("broker")
    base = run_cost_pipeline([], blueprint=bp, headcount=500)
    # quote the two biggest benchmark drivers as firm numbers
    quoted = run_cost_pipeline([], blueprint=bp, headcount=500,
                               overrides={"vdi_daas": 200000, "siem_day1": 40000,
                                          "broker_services": 40000})
    assert quoted.accuracy_pct >= base.accuracy_pct


def test_ladder_reflects_overrides():
    plain = cost_all_models(headcount=250)
    quoted = cost_all_models(headcount=250, overrides={"vdi_daas": 10})
    assert quoted["broker"].base < plain["broker"].base
