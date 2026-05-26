import pytest
from analysis.schema import (
    Finding,
    ExposureLevel,
    DataSensitivity,
    ExploitStatus,
    EvidenceStrength,
    DealTier,
    ScannerSource,
)
from analysis.triage import (
    calculate_base_score,
    calculate_score,
    check_override_rules,
    score_to_tier,
    triage,
    triage_all,
    EVIDENCE_MULTIPLIERS,
    EXPOSURE_SCORES,
    SENSITIVITY_SCORES,
    EXPLOIT_SCORES,
    WEIGHT_CVSS,
    WEIGHT_EXPOSURE,
    WEIGHT_SENSITIVITY,
    WEIGHT_EXPLOIT,
)
from scanners.openvas_parse import merge_openvas_with_nmap
from scanners.vulners_parse import merge_vulners_with_nmap


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_finding(**kwargs) -> Finding:
    defaults = dict(
        title="Test Finding",
        host="192.168.1.1",
        port=80,
        service="http",
        cvss_score=5.0,
        description="Test description",
        remediation="Test remediation",
        exposure=ExposureLevel.INTERNAL,
        data_sensitivity=DataSensitivity.UNKNOWN,
        exploit_status=ExploitStatus.UNKNOWN,
        scanner_source=ScannerSource.NMAP,
        evidence_strength=EvidenceStrength.CONFIRMED,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ── Base score formula ─────────────────────────────────────────────────────────

def test_base_score_formula():
    f = make_finding(
        cvss_score=8.0,
        exposure=ExposureLevel.INTERNET_FACING,
        data_sensitivity=DataSensitivity.UNKNOWN,
        exploit_status=ExploitStatus.PUBLIC_EXPLOIT,
        evidence_strength=EvidenceStrength.CONFIRMED,
    )
    expected = (
        (80.0 * WEIGHT_CVSS) +
        (EXPOSURE_SCORES[ExposureLevel.INTERNET_FACING] * WEIGHT_EXPOSURE) +
        (SENSITIVITY_SCORES[DataSensitivity.UNKNOWN] * WEIGHT_SENSITIVITY) +
        (EXPLOIT_SCORES[ExploitStatus.PUBLIC_EXPLOIT] * WEIGHT_EXPLOIT)
    )
    assert abs(calculate_base_score(f) - expected) < 0.01


def test_base_score_uses_correct_weights():
    # All factors at minimum → score should be low
    f_low = make_finding(
        cvss_score=0.0,
        exposure=ExposureLevel.INTERNAL,
        data_sensitivity=DataSensitivity.LOW,
        exploit_status=ExploitStatus.NO_EXPLOIT,
    )
    # All factors at maximum → score should be high
    f_high = make_finding(
        cvss_score=10.0,
        exposure=ExposureLevel.INTERNET_FACING,
        data_sensitivity=DataSensitivity.CROWN_JEWEL,
        exploit_status=ExploitStatus.ACTIVE_EXPLOITATION,
    )
    assert calculate_base_score(f_low) < calculate_base_score(f_high)
    assert calculate_base_score(f_high) == pytest.approx(100.0, abs=0.01)


def test_cvss_normalisation():
    f10 = make_finding(cvss_score=10.0, exposure=ExposureLevel.UNKNOWN,
                       data_sensitivity=DataSensitivity.UNKNOWN, exploit_status=ExploitStatus.UNKNOWN)
    f5  = make_finding(cvss_score=5.0,  exposure=ExposureLevel.UNKNOWN,
                       data_sensitivity=DataSensitivity.UNKNOWN, exploit_status=ExploitStatus.UNKNOWN)
    diff = calculate_base_score(f10) - calculate_base_score(f5)
    assert abs(diff - 50.0 * WEIGHT_CVSS) < 0.01


# ── Evidence multipliers ───────────────────────────────────────────────────────

def test_evidence_multipliers_order():
    base = make_finding(cvss_score=8.0, exposure=ExposureLevel.INTERNET_FACING,
                        data_sensitivity=DataSensitivity.SENSITIVE, exploit_status=ExploitStatus.PUBLIC_EXPLOIT)

    scores = {}
    for strength in EvidenceStrength:
        f = base.model_copy()
        f.evidence_strength = strength
        scores[strength] = calculate_score(f)

    assert scores[EvidenceStrength.CONFIRMED] >= scores[EvidenceStrength.CORRELATED]
    assert scores[EvidenceStrength.CORRELATED] >= scores[EvidenceStrength.UNKNOWN]
    assert scores[EvidenceStrength.UNKNOWN]    >= scores[EvidenceStrength.INFERRED]
    assert scores[EvidenceStrength.INFERRED]   >= scores[EvidenceStrength.EXTERNAL]


def test_confirmed_multiplier_is_one():
    f = make_finding(evidence_strength=EvidenceStrength.CONFIRMED)
    base = calculate_base_score(f)
    final = calculate_score(f)
    assert abs(base - final) < 0.01


# ── Score-to-tier thresholds ───────────────────────────────────────────────────

def test_score_to_tier_boundaries():
    assert score_to_tier(75.0) == DealTier.CRITICAL
    assert score_to_tier(74.9) == DealTier.MODERATE
    assert score_to_tier(50.0) == DealTier.MODERATE
    assert score_to_tier(49.9) == DealTier.MANAGEABLE
    assert score_to_tier(0.0)  == DealTier.MANAGEABLE


# ── Deal-killer override rules ─────────────────────────────────────────────────

def test_deal_killer_active_exploitation():
    f = make_finding(exploit_status=ExploitStatus.ACTIVE_EXPLOITATION)
    is_dk, reason = check_override_rules(f)
    assert is_dk is True
    assert reason


def test_deal_killer_crown_jewel_critical_internet():
    f = make_finding(
        data_sensitivity=DataSensitivity.CROWN_JEWEL,
        cvss_score=9.0,
        exposure=ExposureLevel.INTERNET_FACING,
        exploit_status=ExploitStatus.UNKNOWN,
    )
    is_dk, _ = check_override_rules(f)
    assert is_dk is True


def test_deal_killer_crown_jewel_below_cvss_threshold():
    f = make_finding(
        data_sensitivity=DataSensitivity.CROWN_JEWEL,
        cvss_score=8.9,
        exposure=ExposureLevel.INTERNET_FACING,
    )
    is_dk, _ = check_override_rules(f)
    assert is_dk is False


def test_deal_killer_regulated_critical_internet():
    f = make_finding(
        data_sensitivity=DataSensitivity.REGULATED,
        cvss_score=9.5,
        exposure=ExposureLevel.INTERNET_FACING,
        exploit_status=ExploitStatus.UNKNOWN,
    )
    is_dk, _ = check_override_rules(f)
    assert is_dk is True


def test_deal_killer_regulated_below_threshold():
    f = make_finding(
        data_sensitivity=DataSensitivity.REGULATED,
        cvss_score=9.4,
        exposure=ExposureLevel.INTERNET_FACING,
    )
    is_dk, _ = check_override_rules(f)
    assert is_dk is False


def test_deal_killer_sets_score_to_100():
    f = make_finding(exploit_status=ExploitStatus.ACTIVE_EXPLOITATION)
    result = triage(f)
    assert result.risk_score == 100.0
    assert result.deal_tier == DealTier.DEAL_KILLER


def test_no_deal_killer_for_internal_crown_jewel():
    f = make_finding(
        data_sensitivity=DataSensitivity.CROWN_JEWEL,
        cvss_score=9.5,
        exposure=ExposureLevel.INTERNAL,
    )
    is_dk, _ = check_override_rules(f)
    assert is_dk is False


# ── triage_all ordering ────────────────────────────────────────────────────────

def test_triage_all_sorted_descending():
    findings = [
        make_finding(cvss_score=3.0, title="Low"),
        make_finding(cvss_score=9.0, title="High"),
        make_finding(cvss_score=6.0, title="Med"),
    ]
    result = triage_all(findings)
    scores = [f.risk_score for f in result]
    assert scores == sorted(scores, reverse=True)


def test_deal_killer_sorts_first():
    findings = [
        make_finding(cvss_score=9.0, title="High but not killer"),
        make_finding(exploit_status=ExploitStatus.ACTIVE_EXPLOITATION, cvss_score=3.0, title="Killer"),
    ]
    result = triage_all(findings)
    assert result[0].deal_tier == DealTier.DEAL_KILLER


# ── OpenVAS merge ──────────────────────────────────────────────────────────────

def test_merge_openvas_upgrades_evidence_on_match():
    nmap = [make_finding(host="10.0.0.1", port=443, cvss_score=3.5,
                         evidence_strength=EvidenceStrength.UNKNOWN)]
    openvas = [make_finding(host="10.0.0.1", port=443, cvss_score=8.0,
                            scanner_source=ScannerSource.OPENVAS,
                            evidence_strength=EvidenceStrength.CONFIRMED)]
    result = merge_openvas_with_nmap(nmap, openvas)
    nmap_f = result[0]
    assert nmap_f.evidence_strength == EvidenceStrength.CONFIRMED
    assert nmap_f.cvss_score == 8.0
    assert len(result) == 1  # no standalone added when host+port match


def test_merge_openvas_standalone_on_no_match():
    nmap    = [make_finding(host="10.0.0.1", port=80)]
    openvas = [make_finding(host="10.0.0.1", port=8443,
                            scanner_source=ScannerSource.OPENVAS)]
    result = merge_openvas_with_nmap(nmap, openvas)
    assert len(result) == 2


def test_merge_openvas_copies_cve_id():
    nmap    = [make_finding(host="10.0.0.1", port=22, cve_id=None)]
    openvas = [make_finding(host="10.0.0.1", port=22, cve_id="CVE-2023-1234",
                            scanner_source=ScannerSource.OPENVAS)]
    result = merge_openvas_with_nmap(nmap, openvas)
    assert result[0].cve_id == "CVE-2023-1234"


def test_merge_openvas_takes_higher_exploit():
    nmap    = [make_finding(host="10.0.0.1", port=22,
                            exploit_status=ExploitStatus.UNKNOWN)]
    openvas = [make_finding(host="10.0.0.1", port=22,
                            exploit_status=ExploitStatus.PUBLIC_EXPLOIT,
                            scanner_source=ScannerSource.OPENVAS)]
    result = merge_openvas_with_nmap(nmap, openvas)
    assert result[0].exploit_status == ExploitStatus.PUBLIC_EXPLOIT


def test_merge_openvas_never_downgrades_exploit():
    nmap    = [make_finding(host="10.0.0.1", port=22,
                            exploit_status=ExploitStatus.ACTIVE_EXPLOITATION)]
    openvas = [make_finding(host="10.0.0.1", port=22,
                            exploit_status=ExploitStatus.NO_EXPLOIT,
                            scanner_source=ScannerSource.OPENVAS)]
    result = merge_openvas_with_nmap(nmap, openvas)
    assert result[0].exploit_status == ExploitStatus.ACTIVE_EXPLOITATION


# ── Vulners merge ──────────────────────────────────────────────────────────────

def test_merge_vulners_upgrades_to_correlated():
    nmap     = [make_finding(host="10.0.0.1", port=80, cvss_score=3.5,
                             evidence_strength=EvidenceStrength.UNKNOWN)]
    vulners  = [make_finding(host="10.0.0.1", port=80, cvss_score=7.8,
                             cve_id="CVE-2023-9999",
                             scanner_source=ScannerSource.VULNERS,
                             evidence_strength=EvidenceStrength.INFERRED)]
    result = merge_vulners_with_nmap(nmap, vulners)
    assert result[0].evidence_strength == EvidenceStrength.CORRELATED
    assert result[0].cvss_score == 7.8


def test_merge_vulners_secondary_high_cvss_added_as_standalone():
    nmap = [make_finding(host="10.0.0.1", port=80)]
    vulners = [
        make_finding(host="10.0.0.1", port=80, cvss_score=9.0, cve_id="CVE-2023-0001",
                     scanner_source=ScannerSource.VULNERS),
        make_finding(host="10.0.0.1", port=80, cvss_score=7.5, cve_id="CVE-2023-0002",
                     scanner_source=ScannerSource.VULNERS),
    ]
    result = merge_vulners_with_nmap(nmap, vulners)
    assert len(result) == 2  # nmap finding + one high-cvss secondary standalone


def test_merge_vulners_secondary_low_cvss_dropped():
    nmap = [make_finding(host="10.0.0.1", port=80)]
    vulners = [
        make_finding(host="10.0.0.1", port=80, cvss_score=8.0, cve_id="CVE-2023-0001",
                     scanner_source=ScannerSource.VULNERS),
        make_finding(host="10.0.0.1", port=80, cvss_score=5.0, cve_id="CVE-2023-0002",
                     scanner_source=ScannerSource.VULNERS),
    ]
    result = merge_vulners_with_nmap(nmap, vulners)
    assert len(result) == 1  # only nmap finding; low-cvss secondary dropped


def test_merge_vulners_no_match_is_standalone():
    nmap    = [make_finding(host="10.0.0.1", port=80)]
    vulners = [make_finding(host="10.0.0.1", port=443,
                            scanner_source=ScannerSource.VULNERS)]
    result = merge_vulners_with_nmap(nmap, vulners)
    assert len(result) == 2
