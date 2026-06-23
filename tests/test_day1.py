"""
tests/test_day1.py — Unit tests for the Day-1 Safe Harbor Blueprint engine.
"""
import pytest

from analysis.schema import (
    Finding, ExposureLevel, DataSensitivity, ExploitStatus,
    ScannerSource, EvidenceStrength,
)
from analysis.triage import triage_all
from analysis.maturity import run_assessment, get_all_question_ids
from analysis.standards_compare import compare_to_standard
from analysis.day1 import (
    Day1Phase, ConnectivityModel, PillarStatus,
    is_remote_access, assign_phase, build_roadmap, build_pillars,
    build_gates, recommend_connectivity, build_day1_blueprint,
)


# ── Finding factories ─────────────────────────────────────────────────────────

def _f(**kw):
    base = dict(
        title="finding", host="10.0.0.1", port=80, service="http",
        cvss_score=5.0, exposure=ExposureLevel.INTERNAL,
        data_sensitivity=DataSensitivity.LOW, exploit_status=ExploitStatus.NO_EXPLOIT,
        scanner_source=ScannerSource.NMAP, evidence_strength=EvidenceStrength.UNKNOWN,
    )
    base.update(kw)
    return Finding(**base)


def _max_maturity():
    a = run_assessment({qid: 5 for qid in get_all_question_ids()}, target="t")
    return a, compare_to_standard(a)


def _zero_maturity():
    a = run_assessment({qid: 0 for qid in get_all_question_ids()}, target="t")
    return a, compare_to_standard(a)


# ── is_remote_access ──────────────────────────────────────────────────────────

def test_remote_access_by_service():
    assert is_remote_access(_f(service="rdp", port=3389))
    assert is_remote_access(_f(service="ssh", port=22))
    assert is_remote_access(_f(service="microsoft-ds", port=445))


def test_remote_access_by_port_only():
    assert is_remote_access(_f(service="unknown", port=3389))


def test_non_remote_access():
    assert not is_remote_access(_f(service="http", port=80))


# ── assign_phase ──────────────────────────────────────────────────────────────

def test_active_exploitation_is_p0():
    f = _f(exploit_status=ExploitStatus.ACTIVE_EXPLOITATION, exposure=ExposureLevel.INTERNAL)
    assert assign_phase(f) == Day1Phase.P0_PRE_CONNECT.value


def test_internet_remote_access_is_p0():
    f = _f(service="ms-wbt-server", port=3389, exposure=ExposureLevel.INTERNET_FACING)
    assert assign_phase(f) == Day1Phase.P0_PRE_CONNECT.value


def test_internet_public_exploit_is_p0():
    f = _f(exposure=ExposureLevel.INTERNET_FACING, exploit_status=ExploitStatus.PUBLIC_EXPLOIT, service="http")
    assert assign_phase(f) == Day1Phase.P0_PRE_CONNECT.value


def test_plain_internet_facing_is_p1():
    f = _f(exposure=ExposureLevel.INTERNET_FACING, service="http", exploit_status=ExploitStatus.NO_EXPLOIT)
    assert assign_phase(f) == Day1Phase.P1_CONTAIN.value


def test_partner_remote_access_is_p1():
    f = _f(exposure=ExposureLevel.PARTNER, service="ssh", port=22)
    assert assign_phase(f) == Day1Phase.P1_CONTAIN.value


def test_partner_plain_is_p2():
    f = _f(exposure=ExposureLevel.PARTNER, service="http", port=80)
    assert assign_phase(f) == Day1Phase.P2_STABILISE.value


def test_internal_low_is_p3():
    f = _f(exposure=ExposureLevel.INTERNAL, service="http", port=80)
    assert assign_phase(f) == Day1Phase.P3_INTEGRATE_READY.value


# ── build_roadmap ─────────────────────────────────────────────────────────────

def test_roadmap_p0_sorted_by_risk_desc():
    findings = triage_all([
        _f(title="low-internet", host="a", port=8080, service="http",
           exposure=ExposureLevel.INTERNET_FACING, cvss_score=4.0),
        _f(title="kev", host="b", port=445, service="microsoft-ds",
           exposure=ExposureLevel.INTERNET_FACING, cvss_score=9.8,
           exploit_status=ExploitStatus.ACTIVE_EXPLOITATION,
           data_sensitivity=DataSensitivity.CROWN_JEWEL),
    ])
    roadmap = build_roadmap(findings)
    p0 = roadmap[Day1Phase.P0_PRE_CONNECT.value]
    assert p0, "expected P0 items"
    scores = [it.risk_score for it in p0]
    assert scores == sorted(scores, reverse=True)


def test_roadmap_includes_maturity_gaps():
    findings = triage_all([_f(exposure=ExposureLevel.INTERNAL)])
    _, gap_report = _zero_maturity()
    roadmap = build_roadmap(findings, gap_report)
    maturity_items = [
        it for items in roadmap.values() for it in items if it.source == "maturity"
    ]
    assert maturity_items, "expected maturity gaps folded into roadmap"
    # All-zero maturity -> deal-blocker gaps land in P0
    assert any(it.phase == Day1Phase.P0_PRE_CONNECT.value for it in maturity_items)


# ── recommend_connectivity ────────────────────────────────────────────────────

def test_recommend_isolate_on_active_exploitation():
    findings = triage_all([
        _f(exposure=ExposureLevel.INTERNET_FACING, service="http",
           exploit_status=ExploitStatus.ACTIVE_EXPLOITATION),
    ])
    a, _ = _max_maturity()
    model, label, _ = recommend_connectivity(findings, assessment=a)
    assert model == ConnectivityModel.ISOLATE.value


def test_recommend_integrate_when_clean_and_mature():
    findings = triage_all([_f(exposure=ExposureLevel.INTERNAL, service="http")])
    a, _ = _max_maturity()
    model, _, _ = recommend_connectivity(findings, assessment=a)
    assert model == ConnectivityModel.INTEGRATE.value


def test_recommend_broker_when_clean_but_no_maturity():
    # Clean findings but no maturity assessment -> cannot prove identity/network,
    # so federate/integrate gates fail; broker is the highest unlocked tier.
    findings = triage_all([_f(exposure=ExposureLevel.INTERNAL, service="http")])
    model, _, _ = recommend_connectivity(findings, assessment=None)
    assert model == ConnectivityModel.BROKER.value


def test_recommend_isolate_when_no_findings():
    model, _, _ = recommend_connectivity([], assessment=None)
    assert model == ConnectivityModel.ISOLATE.value


def test_internet_rdp_blocks_federate_even_with_max_maturity():
    findings = triage_all([
        _f(service="ms-wbt-server", port=3389, exposure=ExposureLevel.INTERNET_FACING,
           exploit_status=ExploitStatus.NO_EXPLOIT),
    ])
    a, _ = _max_maturity()
    model, _, _ = recommend_connectivity(findings, assessment=a)
    # internet-facing RDP is P0 + fails the federate gate -> at most broker
    assert model in (ConnectivityModel.BROKER.value, ConnectivityModel.ISOLATE.value)


# ── build_gates ───────────────────────────────────────────────────────────────

def test_isolate_gate_always_passes():
    gates = {g.model: g for g in build_gates([], assessment=None)}
    assert gates["isolate"].passed


def test_federate_gate_fails_without_maturity():
    findings = triage_all([_f(exposure=ExposureLevel.INTERNAL)])
    gates = {g.model: g for g in build_gates(findings, assessment=None)}
    assert not gates["federate"].passed
    assert gates["federate"].blocking


def test_integrate_gate_passes_when_clean_and_mature():
    findings = triage_all([_f(exposure=ExposureLevel.INTERNAL, service="http")])
    a, _ = _max_maturity()
    gates = {g.model: g for g in build_gates(findings, assessment=a)}
    assert gates["integrate"].passed


# ── build_pillars ─────────────────────────────────────────────────────────────

def test_pillars_unknown_without_maturity():
    findings = triage_all([_f(exposure=ExposureLevel.INTERNAL, service="http")])
    pillars = {p.key: p for p in build_pillars(findings, assessment=None)}
    assert pillars["identity_sources"].status == PillarStatus.UNKNOWN
    assert pillars["network_boundaries"].status in (PillarStatus.GREEN, PillarStatus.UNKNOWN)


def test_remote_access_pillar_red_on_internet_rdp():
    findings = triage_all([
        _f(service="ms-wbt-server", port=3389, exposure=ExposureLevel.INTERNET_FACING),
    ])
    pillars = {p.key: p for p in build_pillars(findings)}
    assert pillars["remote_access_pathways"].status == PillarStatus.RED


def test_identity_pillar_green_with_max_maturity():
    findings = triage_all([_f(exposure=ExposureLevel.INTERNAL)])
    a, _ = _max_maturity()
    pillars = {p.key: p for p in build_pillars(findings, assessment=a)}
    assert pillars["identity_sources"].status == PillarStatus.GREEN


# ── build_day1_blueprint (graceful degradation + integration) ─────────────────

def test_blueprint_degrades_without_maturity():
    findings = triage_all([_f(exposure=ExposureLevel.INTERNET_FACING, service="http")])
    bp = build_day1_blueprint(findings, target="t.example.com")
    assert bp.has_maturity is False
    assert bp.recommended_model  # set
    assert len(bp.pillars) == 3
    assert len(bp.gates) == 4
    assert bp.total_actions == len(findings)


def test_blueprint_empty_findings():
    bp = build_day1_blueprint([], target="t")
    assert bp.recommended_model == ConnectivityModel.ISOLATE.value
    assert bp.total_actions == 0


def test_blueprint_full_pipeline():
    findings = triage_all([
        _f(title="kev", host="b", port=445, service="microsoft-ds",
           exposure=ExposureLevel.INTERNET_FACING, cvss_score=9.8,
           exploit_status=ExploitStatus.ACTIVE_EXPLOITATION,
           data_sensitivity=DataSensitivity.CROWN_JEWEL),
    ])
    a, gap = _zero_maturity()
    bp = build_day1_blueprint(findings, assessment=a, gap_report=gap, target="t")
    assert bp.has_maturity is True
    assert bp.recommended_model == ConnectivityModel.ISOLATE.value
    assert bp.p0_count >= 1
    # recommended flag set on exactly one catalog entry
    assert sum(1 for m in bp.model_catalog if m["recommended"]) == 1
