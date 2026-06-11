"""
Headless smoke tests for app.py using Streamlit's AppTest framework.

These render the real Streamlit app with mock findings injected into
session_state and assert that no exceptions or errors surface on any tab or
through the main interactions (What-If simulator, tier filters, maturity
assessment, cost engine). They are the regression guard that caught the
What-If / deprecation issues.
"""
import pytest

from streamlit.testing.v1 import AppTest

from analysis.schema import (
    Finding, ExposureLevel, DataSensitivity, ExploitStatus,
    ScannerSource, EvidenceStrength,
)
from analysis.triage import triage_all

APP = "app.py"


def _mock_findings():
    raw = [
        Finding(
            cve_id="CVE-2017-0144", title="SMB Remote Code Execution (EternalBlue)",
            host="10.0.0.5", port=445, service="microsoft-ds", cvss_score=9.8,
            description="MS17-010 SMBv1 RCE.", remediation="Patch MS17-010; disable SMBv1.",
            exposure=ExposureLevel.INTERNET_FACING, data_sensitivity=DataSensitivity.CROWN_JEWEL,
            exploit_status=ExploitStatus.ACTIVE_EXPLOITATION, scanner_source=ScannerSource.OPENVAS,
            evidence_strength=EvidenceStrength.CONFIRMED,
        ),
        Finding(
            cve_id="CVE-2021-44228", title="Log4Shell JNDI RCE",
            host="10.0.0.6", port=8080, service="http", cvss_score=10.0,
            description="Log4j2 JNDI lookup RCE.", remediation="Upgrade Log4j to 2.17+.",
            exposure=ExposureLevel.INTERNET_FACING, data_sensitivity=DataSensitivity.SENSITIVE,
            exploit_status=ExploitStatus.PUBLIC_EXPLOIT, scanner_source=ScannerSource.NMAP,
            evidence_strength=EvidenceStrength.CORRELATED,
        ),
        Finding(
            title="Open SSH service", host="10.0.0.7", port=22, service="ssh",
            cvss_score=5.0, description="SSH exposed.", remediation="Restrict by IP.",
            exposure=ExposureLevel.PARTNER, data_sensitivity=DataSensitivity.LOW,
            exploit_status=ExploitStatus.NO_EXPLOIT, scanner_source=ScannerSource.NMAP,
            evidence_strength=EvidenceStrength.UNKNOWN,
        ),
        Finding(
            title="HTTP service banner", host="10.0.0.8", port=80, service="http",
            cvss_score=2.5, description="Informational.", remediation="None.",
            exposure=ExposureLevel.INTERNAL, data_sensitivity=DataSensitivity.LOW,
            exploit_status=ExploitStatus.NO_EXPLOIT, scanner_source=ScannerSource.NMAP,
            evidence_strength=EvidenceStrength.INFERRED,
        ),
    ]
    return triage_all(raw)


def _base_state(at):
    at.session_state["findings"]      = _mock_findings()
    at.session_state["shodan_result"] = {
        "success": True, "ports": [80, 443, 445],
        "vulns": ["CVE-2017-0144", "CVE-2021-44228"],
        "organization": "Acme Corp", "isp": "Acme ISP",
        "country": "US", "city": "New York",
    }
    at.session_state["resolved_ip"]  = "10.0.0.5"
    at.session_state["clean_target"] = "target.example.com"


def _assert_clean(at):
    assert not at.exception, [str(getattr(e, "value", e)) for e in at.exception]
    assert not at.error, [str(getattr(e, "value", e)) for e in at.error]


def _run_base():
    at = AppTest.from_file(APP, default_timeout=90)
    _base_state(at)
    at.run()
    return at


def test_initial_render_all_tabs_clean():
    """All six tabs render with no exceptions or errors."""
    at = _run_base()
    _assert_clean(at)


def test_whatif_simulator_select():
    """Selecting findings in the What-If simulator does not raise (the reported bug)."""
    at = _run_base()
    findings = at.session_state["findings"]
    at.multiselect(key="whatif_remediated").set_value([findings[0].id, findings[1].id]).run()
    _assert_clean(at)


def test_whatif_stale_selection_after_rescan():
    """Stale What-If selection (UUIDs from a previous scan) is dropped gracefully."""
    at = AppTest.from_file(APP, default_timeout=90)
    _base_state(at)
    at.session_state["whatif_remediated"] = ["stale-uuid-a", "stale-uuid-b"]
    at.run()
    _assert_clean(at)


def test_tier_preset_navigation():
    """Metric-card tier preset pre-filters the Findings tab without the
    default+session_state conflict warning."""
    at = AppTest.from_file(APP, default_timeout=90)
    _base_state(at)
    at.session_state["tier_preset"] = "deal_killer"
    at.run()
    _assert_clean(at)


def test_expand_finding_cards():
    at = _run_base()
    cbs = [c for c in at.checkbox if "Expand" in c.label]
    assert cbs, "Expand finding cards checkbox not found"
    cbs[0].set_value(True).run()
    _assert_clean(at)


def test_maturity_assessment_submit():
    at = _run_base()
    btns = [b for b in at.button if "Maturity" in b.label]
    assert btns, "Maturity submit button not found"
    btns[0].click().run()
    _assert_clean(at)
    assert "maturity_assessment" in at.session_state


def test_cost_estimate_generate():
    at = _run_base()
    btns = [b for b in at.button if "Cost Estimate" in b.label]
    assert btns, "Cost estimate button not found"
    btns[0].click().run()
    _assert_clean(at)
    assert "cost_rollup" in at.session_state


def test_empty_findings_edge_case():
    at = AppTest.from_file(APP, default_timeout=60)
    at.session_state["findings"]      = []
    at.session_state["shodan_result"] = {"success": False, "error": "no data"}
    at.session_state["resolved_ip"]   = "0.0.0.0"
    at.session_state["clean_target"]  = "empty.example.com"
    at.run()
    _assert_clean(at)
