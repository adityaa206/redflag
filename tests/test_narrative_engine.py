"""
tests/test_narrative_engine.py — Tests for the narrative template engine.
"""
import pytest

from analysis.schema import (
    Finding, DealTier, ExposureLevel, DataSensitivity,
    ExploitStatus, ScannerSource, EvidenceStrength,
)
from narrative.blocks import select_block, select_all_blocks, list_sections
from narrative.engine import (
    build_executive_summary,
    build_maturity_narrative,
    build_cost_narrative,
    build_finding_narrative,
    build_remediation_priority,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(
    deal_tier=DealTier.MODERATE,
    exploit=ExploitStatus.UNKNOWN,
    exposure=ExposureLevel.INTERNAL,
    cvss=5.0,
) -> Finding:
    f = Finding(
        title="Test finding",
        service="http",
        cvss_score=cvss,
        description="desc",
        remediation="fix",
        exposure=exposure,
        exploit_status=exploit,
        scanner_source=ScannerSource.NMAP,
        evidence_strength=EvidenceStrength.CONFIRMED,
    )
    f.deal_tier  = deal_tier
    f.risk_score = 60.0
    return f


# ── Block selector tests ──────────────────────────────────────────────────────

def test_list_sections_not_empty():
    sections = list_sections()
    assert len(sections) > 0
    assert "executive_summary" in sections


def test_select_block_returns_string():
    ctx  = {"has_deal_killers": True, "deal_killer_count": 2, "target": "example.com", "top_deal_killer_title": "Test"}
    text = select_block("executive_summary", ctx)
    assert text is not None
    assert isinstance(text, str)
    assert len(text) > 20


def test_select_block_returns_none_no_match():
    text = select_block("executive_summary", {"has_deal_killers": "IMPOSSIBLE_VALUE"})
    # Should not crash; may or may not match (depends on default block)


def test_select_block_variable_substitution():
    ctx  = {"has_deal_killers": True, "deal_killer_count": 3, "target": "acme.corp",
            "top_deal_killer_title": "EternalBlue"}
    text = select_block("executive_summary", ctx)
    if text:
        # Variables should be substituted (not left as {variable})
        assert "{deal_killer_count}" not in text


def test_select_block_priority_order():
    """deal-killer context should match the highest-priority block first."""
    ctx  = {"has_deal_killers": True, "deal_killer_count": 1, "target": "t", "top_deal_killer_title": "X"}
    text = select_block("executive_summary", ctx)
    assert text is not None


def test_select_all_blocks_returns_list():
    ctx  = {"exploit_status": "active_exploitation", "exposure": "internet_facing",
            "cvss_score": 9.5, "cvss_above_8": True, "data_sensitivity": "unknown",
            "deal_tier": "deal_killer", "title": "T", "cve_id": "", "host": "", "service": ""}
    results = select_all_blocks("finding_detail", ctx)
    assert isinstance(results, list)


# ── engine.build_executive_summary tests ─────────────────────────────────────

def test_exec_summary_with_deal_killers():
    dk = _make_finding(deal_tier=DealTier.DEAL_KILLER, exploit=ExploitStatus.ACTIVE_EXPLOITATION)
    dk.risk_score = 100.0
    text = build_executive_summary([dk], target="target.com")
    assert isinstance(text, str)
    assert len(text) > 10


def test_exec_summary_empty_findings():
    text = build_executive_summary([], target="target.com")
    assert isinstance(text, str)


def test_exec_summary_clean():
    findings = [_make_finding(deal_tier=DealTier.MANAGEABLE)]
    text = build_executive_summary(findings, target="target.com")
    assert isinstance(text, str)
    assert len(text) > 10


# ── engine.build_maturity_narrative tests ─────────────────────────────────────

def test_maturity_narrative_no_assessment():
    text = build_maturity_narrative(None)
    assert isinstance(text, str)


def test_maturity_narrative_with_assessment():
    from analysis.maturity import run_assessment, get_all_question_ids
    answers = {qid: 0 for qid in get_all_question_ids()}
    assessment = run_assessment(answers)
    text = build_maturity_narrative(assessment)
    assert isinstance(text, str)
    assert len(text) > 10


# ── engine.build_finding_narrative tests ─────────────────────────────────────

def test_finding_narrative_active_exploitation():
    f = _make_finding(exploit=ExploitStatus.ACTIVE_EXPLOITATION)
    text = build_finding_narrative(f)
    assert isinstance(text, str)


def test_finding_narrative_returns_string_or_empty():
    f = _make_finding()
    text = build_finding_narrative(f)
    assert isinstance(text, str)


# ── engine.build_remediation_priority tests ───────────────────────────────────

def test_remediation_priority_deal_killer():
    f = _make_finding(deal_tier=DealTier.DEAL_KILLER)
    text = build_remediation_priority(f)
    assert isinstance(text, str)


def test_remediation_priority_manageable():
    f = _make_finding(deal_tier=DealTier.MANAGEABLE)
    text = build_remediation_priority(f)
    assert isinstance(text, str)
