"""Tests for the networkx attack-graph analytics."""
from analysis.schema import Finding, ExposureLevel, DataSensitivity, ScannerSource
from analysis.attack_graph import analyze_graph


def F(host, port=None, exposure=ExposureLevel.INTERNAL, sens=DataSensitivity.UNKNOWN):
    return Finding(title="t", host=host, port=port, exposure=exposure,
                   data_sensitivity=sens, scanner_source=ScannerSource.NMAP)


def _scenario():
    return [
        F("1.1.1.1", 443, ExposureLevel.INTERNET_FACING, DataSensitivity.CROWN_JEWEL),
        F("1.1.1.1", 22, ExposureLevel.INTERNET_FACING),
        F("10.0.0.5", 3306, ExposureLevel.INTERNAL, DataSensitivity.REGULATED),
    ]


def test_graph_blast_radius_and_entry():
    r = analyze_graph(_scenario(), "acme")
    assert r.has_graph
    assert r.internet_hosts == 1
    # host + 2 services + internal host + its service = 5 reachable assets
    assert r.blast_radius == 5


def test_top_chokepoint_is_the_single_entry_host():
    r = analyze_graph(_scenario())
    assert r.chokepoints
    top = r.chokepoints[0]
    assert top.label == "1.1.1.1"
    # removing the only internet entry isolates the other 4 assets
    assert top.isolates == 4


def test_crown_jewel_path_found_first():
    r = analyze_graph(_scenario())
    assert r.crown_paths
    cj = next(p for p in r.crown_paths if p.sensitivity == "crown_jewel")
    assert cj.target_label == "1.1.1.1:443"
    assert cj.hops[0] == "INTERNET"
    assert cj.length == 2


def test_no_internet_means_no_blast():
    r = analyze_graph([F("10.0.0.1", 80, ExposureLevel.INTERNAL)])
    assert r.internet_hosts == 0
    assert r.blast_radius == 0


def test_empty_findings():
    r = analyze_graph([])
    assert r.has_graph is False
    assert r.blast_radius == 0
