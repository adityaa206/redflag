"""
analysis/parser.py — Nmap XML into Finding objects. The base evidence layer.

Every other scanner either enriches these findings or adds to them, so this
module establishes the port inventory the rest of the pipeline correlates
against (see ADR-0008).

Two deliberate choices worth knowing:

  • CVSS is a flat 3.5 for every finding. Nmap confirms a service is OPEN, not
    that it is vulnerable — the real severity arrives later from Vulners, NVD,
    OpenVAS, ZAP or Nuclei.
  • evidence_strength is CONFIRMED, which looks generous but is honest: the port
    genuinely is open and Nmap tested it. The low CVSS, not the evidence
    strength, is what keeps these findings from dominating the ranking.

Exposure is set conservatively (PARTNER for commonly exposed services, INTERNAL
otherwise); Shodan upgrades it to INTERNET_FACING when it confirms visibility.

Triage happens LATER, after enrichment — never here.
"""
import xml.etree.ElementTree as ET
from analysis.schema import (
    Finding,
    ScannerSource,
    ExposureLevel,
    DataSensitivity,
    ExploitStatus,
    EvidenceStrength,
)



SERVICE_EXPOSED = {"http", "https", "ssh", "rdp", "ftp", "telnet", "vnc", "smb", "netbios-ssn"}

SERVICE_DESCRIPTIONS = {
    "telnet":        "Telnet transmits credentials in plaintext and is considered critically insecure for remote access.",
    "rdp":           "Remote Desktop Protocol exposed to the network — a frequent target for brute-force and exploitation.",
    "vnc":           "VNC remote desktop exposed — often misconfigured with weak or no authentication.",
    "ftp":           "FTP transmits credentials and data in plaintext and may allow anonymous access.",
    "smb":           "SMB exposed on the network — historically exploited by EternalBlue and similar vulnerabilities.",
    "docker":        "Docker API exposed — full container orchestration access if unauthenticated.",
    "redis":         "Redis exposed — typically unauthenticated by default; allows arbitrary data access or code execution.",
    "mongodb":       "MongoDB exposed — may allow unauthenticated access to all databases.",
    "elasticsearch": "Elasticsearch exposed — data indices may be publicly readable without authentication.",
    "snmp":          "SNMP exposed — community strings may leak sensitive device configuration.",
    "ms-sql-s":      "Microsoft SQL Server exposed — database access if credentials are weak or default.",
    "mysql":         "MySQL exposed — database access risk if not restricted to localhost.",
}

SERVICE_REMEDIATION = {
    "telnet":        "Disable Telnet and replace with SSH. Restrict remote administration to trusted networks.",
    "rdp":           "Place RDP behind VPN or jump host, enforce MFA, and restrict source IPs.",
    "vnc":           "Disable public VNC access; require VPN and strong authentication for remote desktop.",
    "ftp":           "Disable FTP; use SFTP or FTPS. Disable anonymous access and restrict to trusted IPs.",
    "smb":           "Block SMB from public exposure. Validate patching status and enforce SMB signing.",
    "docker":        "Bind Docker daemon to a Unix socket or require TLS client auth. Never expose publicly.",
    "redis":         "Bind Redis to internal interfaces and require authentication. Disable dangerous commands.",
    "mongodb":       "Require authentication, restrict network exposure, and review database ACLs.",
    "elasticsearch": "Enable security features, require authentication, and restrict public access.",
    "snmp":          "Use SNMPv3 with authentication and encryption. Restrict SNMP to management networks.",
    "ms-sql-s":      "Restrict SQL Server to internal networks, disable SA account, and enforce strong passwords.",
    "mysql":         "Bind MySQL to localhost unless remote access is required. Audit user privileges.",
}


def parse_nmap_xml(xml_file: str) -> list[Finding]:
    findings = []

    tree = ET.parse(xml_file)
    root = tree.getroot()

    for host in root.findall("host"):
        address_el = host.find("address")
        if address_el is None:
            continue

        host_ip = address_el.get("addr")

        status_el = host.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            port_id = port.get("portid")
            service_el = port.find("service")
            state_el = port.find("state")

            if state_el is not None and state_el.get("state") != "open":
                continue

            service_name = service_el.get("name") if service_el is not None else "unknown"
            svc_version  = service_el.get("version", "") if service_el is not None else ""
            svc_product  = service_el.get("product", "") if service_el is not None else ""

            cvss = 3.5  # Nmap confirms a service is open, not a specific vulnerability
            exposure = ExposureLevel.PARTNER if service_name in SERVICE_EXPOSED else ExposureLevel.INTERNAL

            version_str = f" ({svc_product} {svc_version})".strip(" ()") if (svc_product or svc_version) else ""
            title = f"{service_name.upper()} service exposed on port {port_id}{version_str}"

            description = SERVICE_DESCRIPTIONS.get(
                service_name,
                f"Nmap detected an open {service_name} service on {host_ip}:{port_id}. "
                "Verify whether this service is intended to be accessible and assess its authentication requirements."
            )
            remediation = SERVICE_REMEDIATION.get(
                service_name,
                "Review whether this service should be exposed. Restrict access to trusted sources and ensure strong authentication is enforced."
            )

            finding = Finding(
                title=title,
                host=host_ip,
                port=int(port_id),
                service=service_name,
                cvss_score=cvss,
                description=description,
                remediation=remediation,
                exposure=exposure,
                data_sensitivity=DataSensitivity.UNKNOWN,
                exploit_status=ExploitStatus.UNKNOWN,
                scanner_source=ScannerSource.NMAP,
                evidence_strength=EvidenceStrength.CONFIRMED,
                raw_data={
                    "host": host_ip,
                    "port": port_id,
                    "service": service_name,
                    "product": svc_product,
                    "version": svc_version,
                    "source": "nmap",
                }
            )

            findings.append(finding)

    return findings


def analyze_nmap_file(xml_file: str) -> list[Finding]:
    """
    Parse raw Nmap XML into Finding objects.
    Triage should happen later after enrichment from other scanners.
    """
    return parse_nmap_xml(xml_file)


if __name__ == "__main__":
    import sys
    from analysis.triage import triage_all

    xml_file = sys.argv[1]
    findings = analyze_nmap_file(xml_file)
    triaged = triage_all(findings)

    print(f"Parsed {len(triaged)} findings\n")

    for f in triaged:
        deal_tier_display = getattr(f.deal_tier, "value", f.deal_tier)
        exposure_display = getattr(f.exposure, "value", f.exposure)
        evidence_display = getattr(f.evidence_strength, "value", f.evidence_strength)

        print(f"Title: {f.title}")
        print(f"Host: {f.host}")
        print(f"Port: {f.port}")
        print(f"Service: {f.service}")
        print(f"Risk score: {f.risk_score}")
        print(f"Deal tier: {deal_tier_display}")
        print(f"Exposure: {exposure_display}")
        print(f"Evidence strength: {evidence_display}")
        print("-" * 50)