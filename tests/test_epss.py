"""Tests for EPSS enrichment (offline — scores injected, no network)."""
from analysis.schema import Finding, ExploitStatus, ScannerSource
from scanners.epss_scan import enrich_findings_with_epss


def _f(cve, exploit=ExploitStatus.UNKNOWN):
    return Finding(title="t", cve_id=cve, exploit_status=exploit,
                   scanner_source=ScannerSource.NMAP)


def _es(f) -> str:
    return str(getattr(f.exploit_status, "value", f.exploit_status))


def test_epss_attaches_scores():
    f = _f("CVE-2021-44228")
    enrich_findings_with_epss([f], scores={"CVE-2021-44228": {"epss": 0.97, "percentile": 0.99}})
    assert f.epss_score == 0.97
    assert f.epss_percentile == 0.99


def test_epss_high_score_promotes_exploit_status():
    f = _f("CVE-2021-44228", ExploitStatus.UNKNOWN)
    enrich_findings_with_epss([f], scores={"CVE-2021-44228": {"epss": 0.90, "percentile": 0.99}})
    assert _es(f) == "public_exploit"


def test_epss_low_score_does_not_promote():
    f = _f("CVE-2020-0001", ExploitStatus.UNKNOWN)
    enrich_findings_with_epss([f], scores={"CVE-2020-0001": {"epss": 0.01, "percentile": 0.10}})
    assert _es(f) == "unknown"


def test_epss_never_downgrades_active_exploitation():
    f = _f("CVE-2021-44228", ExploitStatus.ACTIVE_EXPLOITATION)
    enrich_findings_with_epss([f], scores={"CVE-2021-44228": {"epss": 0.90, "percentile": 0.99}})
    assert _es(f) == "active_exploitation"


def test_epss_no_cve_is_noop():
    f = _f(None)
    enrich_findings_with_epss([f], scores={"CVE-2021-44228": {"epss": 0.9, "percentile": 0.9}})
    assert f.epss_score is None


def test_epss_empty_scores_is_noop():
    f = _f("CVE-2021-44228", ExploitStatus.UNKNOWN)
    enrich_findings_with_epss([f], scores={})
    assert f.epss_score is None
    assert _es(f) == "unknown"
