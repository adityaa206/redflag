import xml.etree.ElementTree as ET

from analysis.schema import (
    Finding,
    ScannerSource,
    ExposureLevel,
    ExploitStatus,
    EvidenceStrength,
)
from scanners.kev_lookup import is_kev

_EXPLOIT_RANK = {
    ExploitStatus.ACTIVE_EXPLOITATION: 3,
    ExploitStatus.PUBLIC_EXPLOIT: 2,
    ExploitStatus.UNKNOWN: 1,
    ExploitStatus.NO_EXPLOIT: 0,
}

_MIN_CVSS = 5.0          # ignore trivial CVEs from NSE output
_STANDALONE_MIN_CVSS = 7.0  # threshold for additional CVEs on an already-merged port


def _higher_exploit(a: ExploitStatus, b: ExploitStatus) -> ExploitStatus:
    return a if _EXPLOIT_RANK.get(a, 0) >= _EXPLOIT_RANK.get(b, 0) else b


def _extract_cve_entries(script_el) -> list[dict]:
    """
    Pull CVE entries out of a <script id="vulners"> element.

    Handles two common layouts:
      1. Nested under CPE key:  <table key="cpe:..."><table key="CVE-...">
      2. Flat:                  <table key="CVE-...">
    """
    entries = []

    def _read_table(tbl):
        entry = {}
        for elem in tbl.findall("elem"):
            entry[elem.get("key")] = (elem.text or "").strip()
        return entry

    for top in script_el.findall("table"):
        key = top.get("key", "")
        if key.startswith("CVE-"):
            # Flat layout
            e = _read_table(top)
            e.setdefault("id", key)
            entries.append(e)
        else:
            # Nested under CPE or other grouping key
            for inner in top.findall("table"):
                inner_key = inner.get("key", "")
                if inner_key.startswith("CVE-"):
                    e = _read_table(inner)
                    e.setdefault("id", inner_key)
                    entries.append(e)

    return entries


def parse_vulners_from_nmap_xml(xml_file: str) -> list[Finding]:
    """
    Extract <script id="vulners"> data from a saved Nmap XML file.

    Returns one Finding per CVE per port (CVSS >= _MIN_CVSS only).
    Findings are sorted by CVSS descending so merge logic picks the strongest first.
    """
    findings = []

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError:
        return []

    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        host_ip = addr_el.get("addr")

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is not None and state_el.get("state") != "open":
                continue

            port_id = int(port_el.get("portid", 0)) or None
            service_el = port_el.find("service")
            service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"

            script_el = port_el.find(".//script[@id='vulners']")
            if script_el is None:
                continue

            cve_entries = _extract_cve_entries(script_el)

            for entry in cve_entries:
                cve_id = entry.get("id", "")
                if not cve_id.startswith("CVE-"):
                    continue

                try:
                    cvss = float(entry.get("cvss", 0))
                except ValueError:
                    cvss = 0.0

                if cvss < _MIN_CVSS:
                    continue

                is_exploit_flag = entry.get("is_exploit", "false").lower() == "true"

                if is_kev(cve_id):
                    exploit = ExploitStatus.ACTIVE_EXPLOITATION
                elif is_exploit_flag:
                    exploit = ExploitStatus.PUBLIC_EXPLOIT
                else:
                    exploit = ExploitStatus.UNKNOWN

                findings.append(Finding(
                    title=f"Vulners: {cve_id} on {service_name} port {port_id}",
                    cve_id=cve_id,
                    host=host_ip,
                    port=port_id,
                    service=service_name,
                    cvss_score=cvss,
                    description=(
                        f"Vulners identified {cve_id} (CVSS {cvss}) associated with "
                        f"{service_name} on {host_ip}:{port_id}. "
                        "This is based on the detected service version banner."
                    ),
                    remediation=(
                        "Patch the affected service to a version that resolves this CVE. "
                        "Review vendor advisories and restrict network access where possible."
                    ),
                    exposure=ExposureLevel.UNKNOWN,
                    exploit_status=exploit,
                    scanner_source=ScannerSource.VULNERS,
                    evidence_strength=EvidenceStrength.INFERRED,
                    raw_data={
                        "source": "vulners_nse",
                        "cve_id": cve_id,
                        "cvss": cvss,
                        "is_exploit": is_exploit_flag,
                    },
                ))

    # Sort descending by CVSS so merge picks the strongest CVE first per port
    findings.sort(key=lambda f: f.cvss_score, reverse=True)
    return findings


def merge_vulners_with_nmap(
    nmap_findings: list[Finding],
    vulners_findings: list[Finding],
) -> list[Finding]:
    """
    Cross-reference Vulners NSE findings against Nmap findings by (host, port).

    First Vulners CVE to match a Nmap port (highest CVSS first):
      - Upgrades evidence_strength to CORRELATED
      - Takes the higher CVSS score
      - Takes the higher exploit_status
      - Copies CVE ID if the Nmap finding doesn't have one

    Additional Vulners CVEs for the same matched port are only added as
    standalone findings if their CVSS >= _STANDALONE_MIN_CVSS (reduces noise).

    Vulners findings with no Nmap match become standalone entries.
    """
    nmap_index: dict[tuple, Finding] = {}
    for f in nmap_findings:
        if f.host and f.port is not None:
            nmap_index[(f.host, f.port)] = f

    merged_ports: set[tuple] = set()
    standalone: list[Finding] = []

    for vf in vulners_findings:
        key = (vf.host, vf.port) if (vf.host and vf.port is not None) else None
        nmap_match = nmap_index.get(key) if key else None

        if nmap_match and key not in merged_ports:
            nmap_match.evidence_strength = EvidenceStrength.CORRELATED
            if vf.cvss_score > nmap_match.cvss_score:
                nmap_match.cvss_score = vf.cvss_score
            nmap_match.exploit_status = _higher_exploit(nmap_match.exploit_status, vf.exploit_status)
            if not nmap_match.cve_id and vf.cve_id:
                nmap_match.cve_id = vf.cve_id
            merged_ports.add(key)
        elif nmap_match and key in merged_ports:
            # Secondary CVE on an already-matched port — add only if high severity
            if vf.cvss_score >= _STANDALONE_MIN_CVSS:
                standalone.append(vf)
        else:
            standalone.append(vf)

    return nmap_findings + standalone
