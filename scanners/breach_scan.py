"""
Dark Web & Breach Exposure Scanner — Feature 4
Uses the LeakIX free API to check for known breaches and exposures.
No API key required for basic queries.
"""

import requests

from analysis.schema import (
    Finding, ExposureLevel, DataSensitivity, ExploitStatus,
    ScannerSource, EvidenceStrength,
)

_BASE    = "https://leakix.net"
_HEADERS = {
    "Accept":     "application/json",
    "User-Agent": "RedFlag-M&A-Scanner/1.0",
}
_TIMEOUT = 12


def _is_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _get_domain_events(domain: str) -> list[dict]:
    try:
        r = requests.get(
            f"{_BASE}/domain/{domain}",
            headers=_HEADERS,
            timeout=_TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                return [e for e in data if isinstance(e, dict)]
            if isinstance(data, dict):
                svc = data.get("Services") or data.get("services") or []
                return [e for e in svc if isinstance(e, dict)]
    except Exception:
        pass
    return []


def _get_host_events(ip: str) -> list[dict]:
    try:
        r = requests.get(
            f"{_BASE}/host/{ip}",
            headers=_HEADERS,
            timeout=_TIMEOUT,
        )
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                return [e for e in data if isinstance(e, dict)]
            if isinstance(data, dict):
                svc = data.get("Services") or data.get("services") or []
                return [e for e in svc if isinstance(e, dict)]
    except Exception:
        pass
    return []


def _classify_event(event: dict) -> tuple[float, ExploitStatus, str]:
    """
    Return (cvss_score, exploit_status, short_description) for a LeakIX event.
    """
    plugin  = (event.get("plugin") or event.get("Plugin") or "").lower()
    summary = (event.get("summary") or event.get("Summary") or "").lower()
    tags    = [str(t).lower() for t in (event.get("tags") or event.get("Tags") or [])]

    # Credential / database leaks → highest severity
    if any(k in plugin for k in ("cred", "password", "secret", "leak", "dump")):
        return 9.5, ExploitStatus.ACTIVE_EXPLOITATION, "Credential or secret leak"
    if any(k in tags for k in ("credential", "password", "leak")):
        return 9.5, ExploitStatus.ACTIVE_EXPLOITATION, "Credential exposure"
    if any(k in plugin for k in ("mongo", "elastic", "redis", "cassandra", "couch", "mysql", "postgres")):
        return 8.5, ExploitStatus.ACTIVE_EXPLOITATION, "Exposed unauthenticated database"
    if any(k in tags for k in ("open_db", "database", "open_database")):
        return 8.5, ExploitStatus.ACTIVE_EXPLOITATION, "Open database exposure"
    # Git / backup / source exposure
    if "git" in plugin or "git" in tags:
        return 7.5, ExploitStatus.PUBLIC_EXPLOIT, "Exposed .git directory (source code)"
    if "backup" in plugin or "backup" in tags:
        return 7.0, ExploitStatus.PUBLIC_EXPLOIT, "Exposed backup file"
    # Generic exposure
    return 6.0, ExploitStatus.PUBLIC_EXPLOIT, "Indexed security exposure"


def run_breach_scan(domain: str, ips: list[str]) -> tuple[list[Finding], dict]:
    """
    Run breach/exposure checks via LeakIX.
    Returns (findings, summary_dict).
    """
    findings: list[Finding] = []
    summary: dict = {
        "domain_events": 0,
        "host_events":   0,
        "total":         0,
        "breach_found":  False,
        "error":         None,
    }

    # ── Domain check ──────────────────────────────────────────────────────────
    if not _is_ip(domain):
        try:
            events = _get_domain_events(domain)
            summary["domain_events"] = len(events)

            for ev in events:
                cvss, exploit, short = _classify_event(ev)
                plugin       = ev.get("plugin") or ev.get("Plugin") or "Unknown"
                ev_summary   = ev.get("summary") or ev.get("Summary") or "No details available."
                host_val     = ev.get("ip") or ev.get("Ip") or domain
                port_raw     = ev.get("port") or ev.get("Port")
                port_val     = int(port_raw) if port_raw else None

                summary["breach_found"] = True
                summary["total"]       += 1

                findings.append(Finding(
                    title=f"Breach Exposure Detected: {plugin} on {domain}",
                    host=host_val,
                    port=port_val,
                    service="breach",
                    cvss_score=cvss,
                    description=(
                        f"LeakIX has indexed a live security exposure for {domain} "
                        f"via its '{plugin}' detection plugin. "
                        f"Details: {ev_summary} "
                        "This is not a theoretical risk — it has been observed and catalogued "
                        "by a public scanner. Any attacker can find this through the same API."
                    ),
                    remediation=(
                        f"Investigate and remediate the '{plugin}' exposure on {domain} immediately. "
                        "If credentials or secrets were exposed, rotate all affected keys, "
                        "passwords, and tokens. Verify the service is no longer accessible "
                        "or has been properly secured before deal close."
                    ),
                    exposure=ExposureLevel.INTERNET_FACING,
                    data_sensitivity=DataSensitivity.UNKNOWN,
                    exploit_status=exploit,
                    scanner_source=ScannerSource.BREACH,
                    evidence_strength=EvidenceStrength.CONFIRMED,
                    raw_data={"source": "leakix_domain", "domain": domain, "event": ev},
                ))
        except Exception as e:
            summary["error"] = str(e)

    # ── Host (IP) checks ──────────────────────────────────────────────────────
    for ip in ips[:2]:  # Limit to 2 IPs to avoid rate limiting
        try:
            events = _get_host_events(ip)
            summary["host_events"] += len(events)

            for ev in events:
                cvss, exploit, short = _classify_event(ev)
                plugin     = ev.get("plugin") or ev.get("Plugin") or "Unknown"
                ev_summary = ev.get("summary") or ev.get("Summary") or "No details available."
                port_raw   = ev.get("port") or ev.get("Port")
                port_val   = int(port_raw) if port_raw else None

                summary["breach_found"] = True
                summary["total"]       += 1

                findings.append(Finding(
                    title=f"Breach Exposure Detected: {plugin} on {ip}",
                    host=ip,
                    port=port_val,
                    service="breach",
                    cvss_score=cvss,
                    description=(
                        f"LeakIX has indexed a live security exposure on {ip} "
                        f"via its '{plugin}' detection plugin. "
                        f"Details: {ev_summary} "
                        "This is publicly indexed and known to attackers."
                    ),
                    remediation=(
                        f"Investigate and remediate the '{plugin}' exposure on {ip}. "
                        "Rotate any credentials that may have been exposed. "
                        "Verify the service is secured before deal close."
                    ),
                    exposure=ExposureLevel.INTERNET_FACING,
                    data_sensitivity=DataSensitivity.UNKNOWN,
                    exploit_status=exploit,
                    scanner_source=ScannerSource.BREACH,
                    evidence_strength=EvidenceStrength.CONFIRMED,
                    raw_data={"source": "leakix_host", "ip": ip, "event": ev},
                ))
        except Exception as e:
            if summary["error"] is None:
                summary["error"] = str(e)

    return findings, summary
