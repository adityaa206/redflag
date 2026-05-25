import xml.etree.ElementTree as ET
from analysis.schema import (
    Finding,
    ScannerSource,
    ExposureLevel,
    ExploitStatus,
    EvidenceStrength,
)
from scanners.kev_lookup import is_kev
from scanners.vulners_enrich import get_exploit_status_from_vulners


_EXPLOIT_RANK = {
    ExploitStatus.ACTIVE_EXPLOITATION: 3,
    ExploitStatus.PUBLIC_EXPLOIT: 2,
    ExploitStatus.UNKNOWN: 1,
    ExploitStatus.NO_EXPLOIT: 0,
}


def _higher_exploit(a: ExploitStatus, b: ExploitStatus) -> ExploitStatus:
    return a if _EXPLOIT_RANK.get(a, 0) >= _EXPLOIT_RANK.get(b, 0) else b


def _parse_port(port_str: str) -> tuple[int | None, str | None]:
    """'443/tcp' → (443, 'tcp').  'general/tcp' or '' → (None, None)."""
    if not port_str or "/" not in port_str:
        return None, None
    left, proto = port_str.split("/", 1)
    try:
        return int(left), proto
    except ValueError:
        return None, None


def _extract_cve(nvt_el) -> str | None:
    if nvt_el is None:
        return None
    # <cve>CVE-XXXX-XXXX</cve>
    cve_el = nvt_el.find("cve")
    if cve_el is not None and cve_el.text and cve_el.text.upper().startswith("CVE-"):
        return cve_el.text.strip()
    # <refs><ref type="cve" id="CVE-..."/></refs>
    for ref in nvt_el.findall(".//ref"):
        if ref.get("type", "").lower() == "cve":
            val = ref.get("id", "")
            if val.upper().startswith("CVE-"):
                return val
    return None


def _extract_cvss(result_el, nvt_el) -> float:
    """Prefer result-level severity, fall back to nvt cvss_base."""
    for tag in ["severity"]:
        el = result_el.find(tag)
        if el is not None and el.text:
            try:
                v = float(el.text.strip())
                if 0.0 <= v <= 10.0:
                    return v
            except ValueError:
                pass
    if nvt_el is not None:
        cb = nvt_el.find("cvss_base")
        if cb is not None and cb.text:
            try:
                v = float(cb.text.strip())
                if 0.0 <= v <= 10.0:
                    return v
            except ValueError:
                pass
    return 5.0


def _cvss_to_exploit(cvss: float, threat: str) -> ExploitStatus:
    t = threat.lower()
    if t in ("high", "critical") and cvss >= 9.0:
        return ExploitStatus.PUBLIC_EXPLOIT
    if cvss >= 7.0:
        return ExploitStatus.PUBLIC_EXPLOIT
    return ExploitStatus.UNKNOWN


def _exposure_from_port(port: int | None, service: str | None) -> ExposureLevel:
    internet_services = {"http", "https", "ftp", "telnet", "rdp", "smtp", "ssh", "vnc"}
    if service and any(s in (service or "").lower() for s in internet_services):
        return ExposureLevel.PARTNER
    return ExposureLevel.INTERNAL


def _find_results(root) -> list:
    """
    Handle both common Greenbone XML layouts:
      - <report><report><results><result>
      - <report><results><result>
    """
    for path in [".//results/result", ".//report/results/result"]:
        results = root.findall(path)
        if results:
            return results
    return []


def parse_openvas_xml(xml_file: str) -> list[Finding]:
    findings = []

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        raise ValueError(f"Could not parse OpenVAS XML: {e}")

    for result in _find_results(root):
        # Skip informational / log entries (severity 0 or threat = "Log")
        threat = (result.findtext("threat") or "").strip()
        if threat.lower() in ("log", "false positive", ""):
            sev_text = result.findtext("severity") or "0"
            try:
                if float(sev_text) <= 0:
                    continue
            except ValueError:
                continue

        nvt_el      = result.find("nvt")
        host        = (result.findtext("host") or "").strip() or None
        port_str    = (result.findtext("port") or "").strip()
        name        = (result.findtext("name") or nvt_el.findtext("name") if nvt_el is not None else None) or "Unknown OpenVAS Finding"
        description = (result.findtext("description") or "").strip() or "No description provided."
        solution    = (result.findtext("solution") or "").strip() or "Review vendor advisory and apply available patches."

        port, proto = _parse_port(port_str)
        service     = (proto or "").lower() if proto not in ("tcp", "udp", None) else None
        cvss        = _extract_cvss(result, nvt_el)
        cve_id      = _extract_cve(nvt_el)
        exploit     = ExploitStatus.ACTIVE_EXPLOITATION if (cve_id and is_kev(cve_id)) else _cvss_to_exploit(cvss, threat)
        if cve_id:
            exploit = get_exploit_status_from_vulners(cve_id, exploit)
        exposure    = _exposure_from_port(port, name)

        raw = {
            "source":        "openvas",
            "threat":        threat,
            "nvt_oid":       nvt_el.get("oid") if nvt_el is not None else None,
            "nvt_family":    nvt_el.findtext("family") if nvt_el is not None else None,
            "port_str":      port_str,
            "qod":           result.findtext("qod/value"),
        }

        findings.append(Finding(
            title=name,
            cve_id=cve_id,
            host=host,
            port=port,
            service=service or port_str or None,
            cvss_score=cvss,
            description=description,
            remediation=solution,
            exposure=exposure,
            exploit_status=exploit,
            scanner_source=ScannerSource.OPENVAS,
            evidence_strength=EvidenceStrength.CONFIRMED,
            raw_data=raw,
        ))

    return findings


def merge_openvas_with_nmap(
    nmap_findings: list[Finding],
    openvas_findings: list[Finding],
) -> list[Finding]:
    """
    Cross-reference OpenVAS findings against Nmap findings by (host, port).

    For each OpenVAS finding that matches a Nmap finding:
      - Upgrade the Nmap finding's evidence_strength to CONFIRMED
      - Take the higher CVSS score (OpenVAS verified > Nmap's default 3.5)
      - Take the higher exploit_status
      - Copy CVE ID if the Nmap finding doesn't have one

    OpenVAS findings with no Nmap match are returned as standalone entries.
    The final list is: upgraded Nmap findings + unmatched standalone OpenVAS findings.
    """
    # Index Nmap findings by (host, port) for O(1) lookup
    nmap_index: dict[tuple, Finding] = {}
    for f in nmap_findings:
        if f.host and f.port is not None:
            nmap_index[(f.host, f.port)] = f

    standalone: list[Finding] = []

    for ov in openvas_findings:
        key = (ov.host, ov.port) if (ov.host and ov.port is not None) else None
        nmap_match = nmap_index.get(key) if key else None

        if nmap_match:
            nmap_match.evidence_strength = EvidenceStrength.CONFIRMED
            if ov.cvss_score > nmap_match.cvss_score:
                nmap_match.cvss_score = ov.cvss_score
            nmap_match.exploit_status = _higher_exploit(nmap_match.exploit_status, ov.exploit_status)
            if not nmap_match.cve_id and ov.cve_id:
                nmap_match.cve_id = ov.cve_id
        else:
            standalone.append(ov)

    return nmap_findings + standalone
