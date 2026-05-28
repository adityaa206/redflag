"""
tests/test_estimator.py — Unit tests for the cost estimation engine.
"""
import pytest

from analysis.schema import (
    Finding, DealTier, ExposureLevel, DataSensitivity,
    ExploitStatus, ScannerSource, EvidenceStrength,
)
from cost.schema import (
    CostTriple, CostLineItem, RemediationCategory, CapexOpex,
    CostConfidence, ReviewFlag, ScenarioType,
)
from cost.catalog import lookup_finding, lookup_maturity_gap
from cost.estimator import estimate_from_findings
from cost.deduplicator import deduplicate
from cost.rollup import build_rollup, run_cost_pipeline


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(
    title="Test finding",
    cve_id=None,
    service="http",
    deal_tier=DealTier.MODERATE,
    exploit=ExploitStatus.UNKNOWN,
    exposure=ExposureLevel.INTERNAL,
) -> Finding:
    f = Finding(
        title=title,
        cve_id=cve_id,
        service=service,
        cvss_score=5.0,
        description="test",
        remediation="fix it",
        exposure=exposure,
        exploit_status=exploit,
        scanner_source=ScannerSource.NMAP,
        evidence_strength=EvidenceStrength.CONFIRMED,
    )
    f.deal_tier   = deal_tier
    f.risk_score  = 60.0
    return f


# ── CostTriple tests ──────────────────────────────────────────────────────────

def test_cost_triple_add():
    a = CostTriple(low=100, base=200, high=300)
    b = CostTriple(low=50,  base=100, high=200)
    c = a + b
    assert c.low  == 150
    assert c.base == 300
    assert c.high == 500


def test_cost_triple_total():
    t = CostTriple(low=100, base=500, high=1000)
    assert t.total(ScenarioType.LOW)  == 100
    assert t.total(ScenarioType.BASE) == 500
    assert t.total(ScenarioType.HIGH) == 1000


def test_cost_triple_spread_ratio():
    t = CostTriple(low=100, base=300, high=500)
    assert t.spread_ratio() == pytest.approx(5.0)


def test_cost_triple_zero():
    z = CostTriple.zero()
    assert z.low == 0 and z.base == 0 and z.high == 0


# ── lookup_finding tests ──────────────────────────────────────────────────────

def test_lookup_finding_returns_line_item():
    f = _make_finding(service="ssh")
    item = lookup_finding(f)
    assert isinstance(item, CostLineItem)


def test_lookup_finding_cve_override():
    """CVE-2017-0144 (EternalBlue) has a specific catalog entry."""
    f = _make_finding(cve_id="CVE-2017-0144")
    item = lookup_finding(f)
    assert "MS17-010" in item.title or "EternalBlue" in item.title.lower() or item.catalog_key == "CVE-2017-0144"


def test_lookup_finding_service_match():
    """telnet service should map to a specific entry."""
    f = _make_finding(service="telnet")
    item = lookup_finding(f)
    assert "telnet" in item.title.lower() or "ssh" in item.title.lower()


def test_lookup_finding_deal_killer_gets_flag():
    f = _make_finding(deal_tier=DealTier.DEAL_KILLER, service="unknown_service_xyz")
    item = lookup_finding(f)
    assert ReviewFlag.DEAL_KILLER_ITEM in item.review_flags


def test_lookup_finding_cost_positive():
    f = _make_finding(service="rdp")
    item = lookup_finding(f)
    assert item.cost.base > 0
    assert item.cost.low <= item.cost.base <= item.cost.high


# ── estimate_from_findings tests ──────────────────────────────────────────────

def test_estimate_from_findings_empty():
    items = estimate_from_findings([])
    assert items == []


def test_estimate_from_findings_skips_unscored():
    f = _make_finding()
    f.deal_tier = DealTier.UNSCORED
    items = estimate_from_findings([f])
    assert items == []


def test_estimate_from_findings_returns_one_per_finding():
    findings = [_make_finding(f"f{i}") for i in range(5)]
    items = estimate_from_findings(findings)
    assert len(items) == 5


# ── deduplicate tests ─────────────────────────────────────────────────────────

def test_deduplicate_merges_same_catalog_key():
    """Five SSH findings → one merged item."""
    findings = [_make_finding(f"ssh_{i}", service="ssh") for i in range(5)]
    raw_items = estimate_from_findings(findings)
    deduped   = deduplicate(raw_items)
    # Should have fewer items than the original 5
    assert len(deduped) < len(raw_items)


def test_deduplicate_passthrough_on_single():
    findings = [_make_finding("only one", service="ftp")]
    raw = estimate_from_findings(findings)
    deduped = deduplicate(raw)
    assert len(deduped) == len(raw)


def test_deduplicate_merged_flag():
    findings = [_make_finding(f"rdp_{i}", service="rdp") for i in range(3)]
    raw    = estimate_from_findings(findings)
    deduped = deduplicate(raw)
    merged = [i for i in deduped if i.is_merged]
    if merged:
        assert ReviewFlag.DUPLICATE in merged[0].review_flags


def test_deduplicate_preserves_finding_ids():
    """Merged item should reference all original finding IDs."""
    findings = [_make_finding(f"telnet_{i}", service="telnet") for i in range(3)]
    fids = {f.id for f in findings}
    raw    = estimate_from_findings(findings)
    deduped = deduplicate(raw)
    all_fids = set()
    for item in deduped:
        all_fids.update(item.finding_ids)
    assert fids == all_fids


# ── build_rollup tests ────────────────────────────────────────────────────────

def test_build_rollup_empty():
    rollup = build_rollup([])
    assert rollup.total.base == 0
    assert rollup.line_items == []


def test_build_rollup_totals_sum():
    findings = [_make_finding(f"f{i}", service="http") for i in range(3)]
    raw    = estimate_from_findings(findings)
    rollup = build_rollup(raw)
    expected_base = sum(i.cost.base for i in raw)
    assert rollup.total.base == pytest.approx(expected_base, rel=1e-3)


def test_build_rollup_has_three_scenarios():
    findings = [_make_finding()]
    raw    = estimate_from_findings(findings)
    rollup = build_rollup(raw)
    scenario_types = {str(s.scenario_type) for s in rollup.scenarios}
    assert scenario_types == {"low", "base", "high"}


def test_build_rollup_capex_opex_split():
    findings = [_make_finding()]
    raw    = estimate_from_findings(findings)
    rollup = build_rollup(raw)
    # capex + opex base should approximately equal total base (within floating point)
    assert abs((rollup.capex_total.base + rollup.opex_total.base) - rollup.total.base) < 1.0


def test_build_rollup_flagged_items():
    """Deal-killer finding should produce a flagged line item."""
    f = _make_finding(deal_tier=DealTier.DEAL_KILLER, service="smb")
    f.risk_score = 100.0
    items  = estimate_from_findings([f])
    rollup = build_rollup(items)
    assert rollup.has_flagged_items


def test_rollup_export_blocked_when_unflagged():
    f = _make_finding(deal_tier=DealTier.DEAL_KILLER)
    items  = estimate_from_findings([f])
    rollup = build_rollup(items)
    if rollup.has_flagged_items:
        assert rollup.export_blocked is True
        rollup.review_acknowledged = True
        assert rollup.export_blocked is False


# ── run_cost_pipeline tests ───────────────────────────────────────────────────

def test_run_cost_pipeline_no_gaps():
    findings = [_make_finding(f"f{i}") for i in range(3)]
    rollup   = run_cost_pipeline(findings, gap_report=None, target="test.com")
    assert rollup.target == "test.com"
    assert rollup.total.base >= 0
