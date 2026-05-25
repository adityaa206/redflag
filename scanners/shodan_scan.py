import os
import time
import requests
from dotenv import load_dotenv
import shodan

from analysis.schema import (
    Finding,
    ExposureLevel,
    ExploitStatus,
    EvidenceStrength,
    ScannerSource,
)
from scanners.kev_lookup import is_kev, get_kev_entry
from scanners.vulners_enrich import get_exploit_status_from_vulners

load_dotenv()

_nvd_cache: dict[str, float] = {}

def fetch_cvss_from_nvd(cve_id: str) -> float:
    """
    Look up the CVSS v3.1 base score for a CVE from the NVD API.
    Falls back to v2 score, then 6.5 if unavailable.
    Results are cached in-process to avoid repeat calls.
    Rate limit: 5 req/30s without API key — add a small delay between calls.
    """
    if cve_id in _nvd_cache:
        return _nvd_cache[cve_id]

    score = 6.5
    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            timeout=8,
        )
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                metrics = vulns[0].get("cve", {}).get("metrics", {})
                v31 = metrics.get("cvssMetricV31", [])
                v30 = metrics.get("cvssMetricV30", [])
                v2  = metrics.get("cvssMetricV2",  [])
                if v31:
                    score = v31[0]["cvssData"]["baseScore"]
                elif v30:
                    score = v30[0]["cvssData"]["baseScore"]
                elif v2:
                    score = v2[0]["cvssData"]["baseScore"]
    except Exception:
        pass

    _nvd_cache[cve_id] = score
    return score


def fetch_cvss_batch(cve_ids: list[str], delay: float = 0.7) -> dict[str, float]:
    """
    Fetch CVSS scores for a list of CVEs with a small inter-request delay
    to stay within the NVD rate limit (5 req/30s without key).
    """
    results = {}
    for cve in cve_ids:
        results[cve] = fetch_cvss_from_nvd(cve)
        if cve not in _nvd_cache or _nvd_cache.get(cve) == 6.5:
            time.sleep(delay)
    return results


def lookup_host(ip_address):
    api_key = os.getenv("SHODAN_API_KEY")

    if not api_key:
        return {
            "success": False,
            "error": "SHODAN_API_KEY not found in .env"
        }

    try:
        api = shodan.Shodan(api_key)
        host = api.host(ip_address)

        return {
            "success": True,
            "ip": host.get("ip_str"),
            "organization": host.get("org"),
            "asn": host.get("asn"),
            "isp": host.get("isp"),
            "country": host.get("country_name"),
            "city": host.get("city"),
            "hostnames": host.get("hostnames", []),
            "domains": host.get("domains", []),
            "ports": host.get("ports", []),
            "os": host.get("os"),
            "vulns": list(host.get("vulns", [])) if host.get("vulns") else [],
            "raw": host
        }

    except shodan.APIError as e:
        return {
            "success": False,
            "error": f"Shodan API error: {str(e)}"
        }


def enrich_findings_with_shodan(findings, shodan_result):
    """
    Enrich findings using Shodan host data before triage.

    Rules:
    - Add general Shodan context to every finding.
    - Upgrade exposure to INTERNET_FACING only if the finding's port
      was actually observed by Shodan.
    - Only apply exploit/CVSS enrichment to findings whose ports match
      Shodan-observed ports.
    - Mark matched Nmap + Shodan findings as CORRELATED evidence.
    """
    if not shodan_result or not shodan_result.get("success"):
        return findings

    shodan_ports = set(shodan_result.get("ports", []))
    shodan_vulns = shodan_result.get("vulns", [])

    shodan_context = {
        "shodan_ip": shodan_result.get("ip"),
        "shodan_org": shodan_result.get("organization"),
        "shodan_asn": shodan_result.get("asn"),
        "shodan_isp": shodan_result.get("isp"),
        "shodan_country": shodan_result.get("country"),
        "shodan_city": shodan_result.get("city"),
        "shodan_hostnames": shodan_result.get("hostnames", []),
        "shodan_domains": shodan_result.get("domains", []),
        "shodan_ports": list(shodan_ports),
        "shodan_vulns": shodan_vulns,
    }

    for finding in findings:
        if finding.raw_data is None:
            finding.raw_data = {}

        finding.raw_data.update(shodan_context)
        finding.raw_data["shodan_port_match"] = finding.port in shodan_ports

        if finding.port in shodan_ports:
            finding.exposure = ExposureLevel.INTERNET_FACING
            finding.evidence_strength = EvidenceStrength.CORRELATED

            if shodan_vulns:
                kev_hits = [c for c in shodan_vulns if is_kev(c)]
                if kev_hits:
                    finding.exploit_status = ExploitStatus.ACTIVE_EXPLOITATION
                    kev_entry = get_kev_entry(kev_hits[0])
                    finding.raw_data["kev_hit"] = kev_hits[0]
                    finding.raw_data["kev_name"] = kev_entry.get("vulnerabilityName") if kev_entry else None
                    finding.raw_data["kev_action"] = kev_entry.get("requiredAction") if kev_entry else None
                elif finding.exploit_status == ExploitStatus.UNKNOWN:
                    finding.exploit_status = ExploitStatus.PUBLIC_EXPLOIT

                top_cve = shodan_vulns[0] if shodan_vulns else None
                if top_cve:
                    nvd_score = fetch_cvss_from_nvd(top_cve)
                    if nvd_score > finding.cvss_score:
                        finding.cvss_score = nvd_score
                        finding.raw_data["nvd_cvss_source"] = top_cve
                elif finding.cvss_score < 6.5:
                    finding.cvss_score = 6.5

                finding.raw_data["shodan_vuln_inference"] = True
            else:
                finding.raw_data["shodan_vuln_inference"] = False
        else:
            if not finding.raw_data.get("shodan_vuln_inference"):
                finding.raw_data["shodan_vuln_inference"] = False

    return findings


def create_shodan_findings(shodan_result, host, max_cves=10):
    """
    Create standalone findings directly from Shodan data.

    These findings are separate from Nmap-derived findings and should be
    appended before triage_all().
    """
    if not shodan_result or not shodan_result.get("success"):
        return []

    findings = []

    shodan_ip = shodan_result.get("ip") or host
    shodan_ports = shodan_result.get("ports", [])
    shodan_vulns = shodan_result.get("vulns", [])[:max_cves]

    cvss_scores = fetch_cvss_batch(shodan_vulns) if shodan_vulns else {}

    risky_ports = {
        21: ("FTP exposed to the internet", "Verify if anonymous access is disabled, require strong auth, restrict exposure, and prefer VPN-only administrative access."),
        23: ("Telnet exposed to the internet", "Disable Telnet and replace it with SSH. Restrict remote administration to trusted networks only."),
        25: ("SMTP exposed to the internet", "Verify relay restrictions, TLS settings, and hardening of the exposed mail service."),
        3389: ("RDP exposed to the internet", "Restrict RDP behind VPN or jump host, enforce MFA, and limit source IP access."),
        445: ("SMB exposed to the internet", "Block SMB from public exposure, restrict to internal networks, and validate patching and signing settings."),
        5900: ("VNC exposed to the internet", "Disable direct public access to VNC and place remote desktop access behind VPN and strong authentication."),
        6379: ("Redis exposed to the internet", "Bind Redis to internal interfaces, require authentication, and disable dangerous commands if exposure is necessary."),
        9200: ("Elasticsearch exposed to the internet", "Require authentication, restrict access, and ensure sensitive indices are not publicly reachable."),
        27017: ("MongoDB exposed to the internet", "Restrict network exposure, require authentication, and validate database access control settings."),
        5000: ("Potential admin/service API exposed", "Verify whether this service is intended for public access and restrict it if administrative."),
        8080: ("Alternate web/admin service exposed", "Confirm business necessity, review authentication, and restrict access if used for administration."),
        2375: ("Docker API exposed to the internet", "Immediately restrict Docker daemon exposure and require secure, authenticated access."),
    }

    base_raw = {
        "source": "shodan",
        "shodan_ip": shodan_result.get("ip"),
        "shodan_org": shodan_result.get("organization"),
        "shodan_asn": shodan_result.get("asn"),
        "shodan_isp": shodan_result.get("isp"),
        "shodan_country": shodan_result.get("country"),
        "shodan_city": shodan_result.get("city"),
        "shodan_hostnames": shodan_result.get("hostnames", []),
        "shodan_domains": shodan_result.get("domains", []),
        "shodan_ports": shodan_ports,
        "shodan_vulns": shodan_result.get("vulns", []),
    }

    for cve in shodan_vulns:
        real_cvss  = cvss_scores.get(cve, 6.5)
        kev_entry  = get_kev_entry(cve)
        in_kev     = kev_entry is not None
        base_exploit = ExploitStatus.ACTIVE_EXPLOITATION if in_kev else ExploitStatus.PUBLIC_EXPLOIT
        exploit      = get_exploit_status_from_vulners(cve, base_exploit)

        if in_kev:
            title       = f"[KEV] {cve} — {kev_entry.get('vulnerabilityName', cve)}"
            description = (
                f"CISA confirms {cve} is actively exploited in the wild. "
                f"{kev_entry.get('shortDescription', '')} "
                f"Shodan associates this CVE with host {shodan_ip}."
            )
            remediation = kev_entry.get("requiredAction") or "Apply vendor patch immediately per CISA KEV guidance."
        else:
            title       = f"Shodan observed vulnerability: {cve}"
            description = (
                f"Shodan reports that host {shodan_ip} is associated with {cve} (CVSS {real_cvss}). "
                "This is externally observed intelligence and should be validated against the affected exposed service."
            )
            remediation = "Validate whether the CVE applies to the live service, patch affected software, and limit internet exposure."

        findings.append(
            Finding(
                title=title,
                cve_id=cve,
                host=host,
                port=None,
                service="shodan-intelligence",
                scanner_source=ScannerSource.SHODAN,
                exposure=ExposureLevel.INTERNET_FACING,
                exploit_status=exploit,
                evidence_strength=EvidenceStrength.EXTERNAL,
                cvss_score=real_cvss,
                description=description,
                remediation=remediation,
                raw_data={
                    **base_raw,
                    "finding_type": "shodan_cve",
                    "cve": cve,
                    "nvd_cvss": real_cvss,
                    "kev": in_kev,
                    "kev_entry": kev_entry,
                }
            )
        )

    for port in shodan_ports:
        if port in risky_ports:
            title, remediation = risky_ports[port]

            findings.append(
                Finding(
                    title=title,
                    description=f"Shodan observed port {port} on host {shodan_ip}, indicating that a potentially sensitive service is externally reachable from the public internet.",
                    remediation=remediation,
                    host=host,
                    port=port,
                    service="unknown",
                    scanner_source=ScannerSource.SHODAN,
                    exposure=ExposureLevel.INTERNET_FACING,
                    exploit_status=ExploitStatus.UNKNOWN,
                    evidence_strength=EvidenceStrength.EXTERNAL,
                    cvss_score=6.5,
                    raw_data={
                        **base_raw,
                        "finding_type": "shodan_exposure",
                        "shodan_port_match": True,
                    }
                )
            )

    return findings