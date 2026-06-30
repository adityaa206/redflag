"""Tests for the Nuclei parser + merge (offline — JSONL injected, no binary)."""
from analysis.schema import (
    Finding, ScannerSource, ExposureLevel, ExploitStatus, EvidenceStrength,
)
from scanners.nuclei_scan import parse_nuclei_jsonl, merge_nuclei_with_nmap


_JSONL = "\n".join([
    '{"template-id":"CVE-2021-44228","info":{"name":"Log4j RCE","severity":"critical",'
    '"classification":{"cve-id":["CVE-2021-44228"],"cvss-score":10.0}},'
    '"host":"https://example.com:443","matched-at":"https://example.com:443/","type":"http"}',
    '{"template-id":"jenkins-panel","info":{"name":"Exposed Jenkins","severity":"medium"},'
    '"host":"example.com:8080","type":"http"}',
    '{"template-id":"tech-detect","info":{"name":"nginx detect","severity":"info"},'
    '"host":"example.com:80","type":"http"}',
])


def _es(f) -> str:
    return str(getattr(f.exploit_status, "value", f.exploit_status))


def test_parse_skips_info_without_cve():
    findings = parse_nuclei_jsonl(_JSONL)
    # critical CVE + medium panel; the info/tech-detect row is dropped
    assert len(findings) == 2
    titles = {f.title for f in findings}
    assert "Log4j RCE" in titles
    assert "nginx detect" not in titles


def test_parse_extracts_host_port_cve_cvss():
    findings = parse_nuclei_jsonl(_JSONL)
    log4j = next(f for f in findings if f.title == "Log4j RCE")
    assert log4j.host == "example.com"
    assert log4j.port == 443
    assert log4j.cve_id == "CVE-2021-44228"
    assert log4j.cvss_score == 10.0
    assert str(getattr(log4j.scanner_source, "value", log4j.scanner_source)) == "nuclei"
    assert str(getattr(log4j.evidence_strength, "value", log4j.evidence_strength)) == "confirmed"


def test_severity_baseline_cvss_when_no_score():
    findings = parse_nuclei_jsonl(_JSONL)
    jenkins = next(f for f in findings if f.host == "example.com" and f.port == 8080)
    assert jenkins.cvss_score == 5.5   # medium baseline


def test_merge_upgrades_matching_nmap_finding():
    nmap = Finding(
        title="https", host="example.com", port=443, service="https",
        cvss_score=3.5, exposure=ExposureLevel.INTERNET_FACING,
        exploit_status=ExploitStatus.UNKNOWN, scanner_source=ScannerSource.NMAP,
        evidence_strength=EvidenceStrength.UNKNOWN,
    )
    nuclei = parse_nuclei_jsonl(_JSONL)
    merged = merge_nuclei_with_nmap([nmap], nuclei)
    upgraded = next(f for f in merged if f.host == "example.com" and f.port == 443)
    assert str(getattr(upgraded.evidence_strength, "value", upgraded.evidence_strength)) == "confirmed"
    assert upgraded.cvss_score == 10.0
    assert upgraded.cve_id == "CVE-2021-44228"
    # the unmatched jenkins finding survives standalone
    assert any(f.port == 8080 for f in merged)


def test_empty_input_is_empty():
    assert parse_nuclei_jsonl("") == []
    assert parse_nuclei_jsonl("not json\n{bad}") == []
