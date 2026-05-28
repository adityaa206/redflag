"""
tests/test_integration.py — End-to-end integration tests for the full
maturity + cost + narrative pipeline.

Uses a fixture JSON file (tests/fixtures/sample_assessment.json) to drive
a representative scan result through the complete pipeline.
"""
import json
import os
import pytest

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
SAMPLE_FIXTURE = os.path.join(FIXTURES_DIR, "sample_assessment.json")


@pytest.fixture
def sample_data():
    """Load the sample assessment fixture."""
    with open(SAMPLE_FIXTURE, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture
def sample_findings(sample_data):
    """Reconstruct Finding objects from the fixture."""
    from analysis.schema import (
        Finding, DealTier, ExposureLevel, DataSensitivity,
        ExploitStatus, ScannerSource, EvidenceStrength,
    )
    findings = []
    for raw in sample_data["findings"]:
        f = Finding(
            title=raw["title"],
            cve_id=raw.get("cve_id"),
            host=raw.get("host", "192.168.1.1"),
            port=raw.get("port"),
            service=raw.get("service", "http"),
            cvss_score=raw.get("cvss_score", 5.0),
            description=raw.get("description", ""),
            remediation=raw.get("remediation", ""),
            exposure=ExposureLevel(raw.get("exposure", "internal")),
            data_sensitivity=DataSensitivity(raw.get("data_sensitivity", "unknown")),
            exploit_status=ExploitStatus(raw.get("exploit_status", "unknown")),
            scanner_source=ScannerSource(raw.get("scanner_source", "nmap")),
            evidence_strength=EvidenceStrength(raw.get("evidence_strength", "confirmed")),
        )
        f.risk_score = raw.get("risk_score", 50.0)
        f.deal_tier  = DealTier(raw.get("deal_tier", "moderate"))
        findings.append(f)
    return findings


@pytest.fixture
def sample_answers(sample_data):
    return sample_data.get("maturity_answers", {})


# ── Pipeline integration tests ────────────────────────────────────────────────

def test_fixture_file_exists():
    assert os.path.exists(SAMPLE_FIXTURE), f"Fixture file missing: {SAMPLE_FIXTURE}"


def test_fixture_has_required_keys(sample_data):
    assert "findings" in sample_data
    assert "maturity_answers" in sample_data
    assert "target" in sample_data


def test_full_maturity_pipeline(sample_answers):
    from analysis.maturity import run_assessment
    from analysis.standards_compare import compare_to_standard

    assessment = run_assessment(sample_answers, target="integration-test.local")
    assert assessment is not None
    assert len(assessment.domain_scores) > 0

    gap_report = compare_to_standard(assessment)
    assert gap_report is not None


def test_full_cost_pipeline(sample_findings, sample_answers):
    from analysis.maturity import run_assessment
    from analysis.standards_compare import compare_to_standard
    from cost.rollup import run_cost_pipeline

    assessment = run_assessment(sample_answers)
    gap_report = compare_to_standard(assessment)

    rollup = run_cost_pipeline(
        findings=sample_findings,
        gap_report=gap_report,
        target="integration-test.local",
        include_maturity_gaps=True,
    )

    assert rollup is not None
    assert len(rollup.line_items) > 0
    assert rollup.total.base >= 0
    assert len(rollup.scenarios) == 3


def test_full_narrative_pipeline(sample_findings, sample_answers):
    from analysis.maturity import run_assessment
    from analysis.standards_compare import compare_to_standard
    from cost.rollup import run_cost_pipeline
    from narrative.report_builder import build_report

    assessment = run_assessment(sample_answers)
    gap_report = compare_to_standard(assessment)
    rollup     = run_cost_pipeline(sample_findings, gap_report=gap_report, target="integration-test.local")

    report = build_report(
        findings=sample_findings,
        target="integration-test.local",
        assessment=assessment,
        rollup=rollup,
    )

    assert "executive_summary" in report
    assert isinstance(report["executive_summary"], str)
    assert len(report["executive_summary"]) > 10
    assert "findings" in report
    assert report["metadata"]["total_findings"] == len(sample_findings)


def test_cost_csv_export(sample_findings):
    from cost.rollup import run_cost_pipeline
    from cost.exporters import export_rollup_csv

    rollup = run_cost_pipeline(sample_findings, target="export-test.local")
    rollup.review_acknowledged = True  # bypass review gate

    csv_bytes = export_rollup_csv(rollup)
    assert isinstance(csv_bytes, bytes)
    assert len(csv_bytes) > 100

    # Verify it's parseable CSV
    import csv, io
    text = csv_bytes.decode("utf-8")
    reader = list(csv.reader(io.StringIO(text)))
    assert len(reader) > 1  # at least header + one row


def test_existing_triage_still_passes(sample_findings):
    """Ensure the original 24-test triage logic is unaffected."""
    from analysis.triage import triage_all
    triaged = triage_all(sample_findings)
    assert len(triaged) == len(sample_findings)
    # All should have risk_score set
    for f in triaged:
        assert f.risk_score >= 0
