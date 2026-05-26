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

# ZAP riskcode: 0=Informational, 1=Low, 2=Medium, 3=High
_RISK_TO_CVSS = {3: 7.5, 2: 5.0, 1: 2.5, 0: 0.0}

_RISK_TO_EXPLOIT = {
    3: ExploitStatus.PUBLIC_EXPLOIT,
    2: ExploitStatus.UNKNOWN,
    1: ExploitStatus.NO_EXPLOIT,
    0: ExploitStatus.NO_EXPLOIT,
}

_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}

_EXPLOIT_RANK = {
    ExploitStatus.ACTIVE_EXPLOITATION: 3,
    ExploitStatus.PUBLIC_EXPLOIT: 2,
    ExploitStatus.UNKNOWN: 1,
    ExploitStatus.NO_EXPLOIT: 0,
}


def _higher_exploit(a: ExploitStatus, b: ExploitStatus) -> ExploitStatus:
    return a if _EXPLOIT_RANK.get(a, 0) >= _EXPLOIT_RANK.get(b, 0) else b


def _exposure_from_port(port: int | None, ssl: bool) -> ExposureLevel:
    if port in _WEB_PORTS:
        return ExposureLevel.INTERNET_FACING if ssl or port in (443, 8443) else ExposureLevel.PARTNER
    return ExposureLevel.PARTNER


def parse_zap_xml(xml_file: str) -> list[Finding]:
    """
    Parse an OWASP ZAP XML report into Finding objects.

    ZAP report structure:
      <OWASPZAPReport>
        <site host="..." port="..." ssl="true|false">
          <alerts>
            <alertitem>
              <name>...</name>
              <riskcode>3</riskcode>   (0=Info, 1=Low, 2=Med, 3=High)
              <confidence>2</confidence>
              <desc>...</desc>
              <solution>...</solution>
              <cweid>79</cweid>
              <count>N</count>
            </alertitem>
          </alerts>
        </site>
      </OWASPZAPReport>

    Informational (riskcode 0) and False Positive (confidence 0) alerts are skipped.
    All included findings get EvidenceStrength.CONFIRMED — ZAP actively tested them.
    """
    findings = []

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError as e:
        raise ValueError(f"Could not parse ZAP XML: {e}")

    for site in root.findall(".//site"):
        host = site.get("host", "").strip() or None
        try:
            port = int(site.get("port", 0)) or None
        except ValueError:
            port = None
        ssl = site.get("ssl", "false").lower() == "true"
        exposure = _exposure_from_port(port, ssl)

        for alert in site.findall(".//alertitem"):
            try:
                riskcode = int((alert.findtext("riskcode") or "0").strip())
            except ValueError:
                riskcode = 0

            if riskcode == 0:
                continue

            try:
                confidence = int((alert.findtext("confidence") or "1").strip())
            except ValueError:
                confidence = 1

            if confidence == 0:
                continue

            name        = (alert.findtext("name") or alert.findtext("alert") or "Unknown ZAP Finding").strip()
            desc        = (alert.findtext("desc") or "").strip() or "No description provided."
            solution    = (alert.findtext("solution") or "").strip() or "Review vendor advisory and apply recommended fixes."
            cweid       = (alert.findtext("cweid") or "").strip()
            count_str   = (alert.findtext("count") or "1").strip()

            cvss        = _RISK_TO_CVSS.get(riskcode, 5.0)
            exploit     = _RISK_TO_EXPLOIT.get(riskcode, ExploitStatus.UNKNOWN)

            cve_id = None
            for ref_el in alert.findall(".//reference"):
                text = ref_el.text or ""
                for part in text.split():
                    if part.upper().startswith("CVE-"):
                        cve_id = part.strip().rstrip(".")
                        break
                if cve_id:
                    break

            if cve_id:
                if is_kev(cve_id):
                    exploit = ExploitStatus.ACTIVE_EXPLOITATION
                else:
                    exploit = get_exploit_status_from_vulners(cve_id, exploit)

            title_suffix = f" (CWE-{cweid})" if cweid else ""
            instance_count = int(count_str) if count_str.isdigit() else 1
            instance_note = f" — {instance_count} instance{'s' if instance_count != 1 else ''} found" if instance_count > 1 else ""

            findings.append(Finding(
                title=f"{name}{title_suffix}{instance_note}",
                cve_id=cve_id,
                host=host,
                port=port,
                service="http" if not ssl else "https",
                cvss_score=cvss,
                description=desc,
                remediation=solution,
                exposure=exposure,
                exploit_status=exploit,
                scanner_source=ScannerSource.ZAP,
                evidence_strength=EvidenceStrength.CONFIRMED,
                raw_data={
                    "source": "zap",
                    "riskcode": riskcode,
                    "confidence": confidence,
                    "cweid": cweid,
                    "ssl": ssl,
                    "instance_count": instance_count,
                },
            ))

    return findings


def merge_zap_with_nmap(
    nmap_findings: list[Finding],
    zap_findings: list[Finding],
) -> list[Finding]:
    """
    Cross-reference ZAP findings against Nmap findings by (host, port).

    Match → upgrade Nmap finding: CONFIRMED evidence, higher CVSS, higher exploit_status.
    No match → ZAP finding added as standalone (web-layer vulns have unique context).
    """
    nmap_index: dict[tuple, Finding] = {}
    for f in nmap_findings:
        if f.host and f.port is not None:
            nmap_index[(f.host, f.port)] = f

    standalone: list[Finding] = []

    for zf in zap_findings:
        key = (zf.host, zf.port) if (zf.host and zf.port is not None) else None
        nmap_match = nmap_index.get(key) if key else None

        if nmap_match:
            nmap_match.evidence_strength = EvidenceStrength.CONFIRMED
            if zf.cvss_score > nmap_match.cvss_score:
                nmap_match.cvss_score = zf.cvss_score
            nmap_match.exploit_status = _higher_exploit(nmap_match.exploit_status, zf.exploit_status)
            if not nmap_match.cve_id and zf.cve_id:
                nmap_match.cve_id = zf.cve_id
            # ZAP findings always kept as standalone — they carry URL/param-level detail
            standalone.append(zf)
        else:
            standalone.append(zf)

    return nmap_findings + standalone
