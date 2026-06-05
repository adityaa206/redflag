"""
SSL/TLS Certificate Health Scanner — Feature 3
Checks certificate expiry, TLS version, and CT logs for shadow subdomains.
"""

import ssl
import socket
import datetime
import requests

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from analysis.schema import (
    Finding, ExposureLevel, DataSensitivity, ExploitStatus,
    ScannerSource, EvidenceStrength,
)

_WEAK_TLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}
_CONNECT_TIMEOUT = 8


def _is_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _get_cert_info(hostname: str, port: int) -> dict | None:
    """
    Connect via TLS and return cert + protocol details.
    Returns None if connection fails or host has no TLS on this port.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                der = tls.getpeercert(binary_form=True)
                version = tls.version()
                cipher  = tls.cipher()

                if der is None:
                    return None

                cert = x509.load_der_x509_certificate(der, default_backend())

                # cryptography >= 42: not_valid_after_utc is timezone-aware
                try:
                    expiry = cert.not_valid_after_utc
                except AttributeError:
                    expiry = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

                try:
                    issued = cert.not_valid_before_utc
                except AttributeError:
                    issued = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)

                # Subject Alternative Names
                sans: list[str] = []
                try:
                    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    sans = [str(n.value) for n in ext.value]
                except Exception:
                    pass

                return {
                    "tls_version":  version,
                    "cipher":       cipher[0] if cipher else None,
                    "cipher_bits":  cipher[2] if cipher and len(cipher) > 2 else None,
                    "expiry":       expiry,
                    "issued":       issued,
                    "subject":      cert.subject.rfc4514_string(),
                    "issuer":       cert.issuer.rfc4514_string(),
                    "sans":         sans,
                }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None


def _query_crt_sh(domain: str) -> list[str]:
    """
    Query crt.sh certificate transparency logs.
    Returns a list of unique subdomain names found.
    """
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=12,
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            return []

        records = resp.json()
        names: set[str] = set()
        for rec in records:
            raw = rec.get("name_value", "")
            for name in raw.split("\n"):
                name = name.strip().lstrip("*.")
                if name and name != domain and name.endswith(f".{domain}"):
                    names.add(name)
        return sorted(names)
    except Exception:
        return []


def run_tls_scan(domain: str, https_ports: list[int] | None = None) -> tuple[list[Finding], dict]:
    """
    Run TLS/certificate health checks against domain.
    Returns (findings, summary_dict).
    """
    if _is_ip(domain):
        return [], {"skipped": "bare IP — TLS scan requires a domain name"}

    ports = list(https_ports or [])
    if 443 not in ports:
        ports.insert(0, 443)

    findings: list[Finding] = []
    summary: dict = {
        "ports_checked": [],
        "certs_checked": 0,
        "weak_tls":      False,
        "expired":       False,
        "expiring_soon": False,
        "subdomains_ct": 0,
    }

    now = datetime.datetime.now(datetime.timezone.utc)

    # ── Per-port checks ───────────────────────────────────────────────────────
    for port in ports:
        info = _get_cert_info(domain, port)
        if not info:
            continue

        summary["ports_checked"].append(port)
        summary["certs_checked"] += 1

        tls_ver = info.get("tls_version", "")
        expiry  = info.get("expiry")

        # Weak TLS version
        if tls_ver in _WEAK_TLS:
            summary["weak_tls"] = True
            findings.append(Finding(
                title=f"Deprecated TLS Version Accepted: {tls_ver} on Port {port}",
                host=domain,
                port=port,
                service="tls",
                cvss_score=6.5,
                description=(
                    f"{domain}:{port} accepted a connection using {tls_ver}, which is "
                    "cryptographically deprecated. TLS 1.0 and 1.1 are prohibited under "
                    "PCI-DSS 4.0, deprecated by NIST SP 800-52r2, and vulnerable to known "
                    "attacks (BEAST on TLS 1.0, POODLE). Any service still accepting these "
                    "versions is a compliance violation that the acquirer inherits."
                ),
                remediation=(
                    f"Disable {tls_ver} on the server at port {port}. "
                    "Configure TLS to only accept TLS 1.2 and TLS 1.3. "
                    "nginx: 'ssl_protocols TLSv1.2 TLSv1.3;' | "
                    "Apache: 'SSLProtocol -all +TLSv1.2 +TLSv1.3' | "
                    "IIS: disable via Windows Registry or IIS Crypto tool."
                ),
                exposure=ExposureLevel.INTERNET_FACING,
                data_sensitivity=DataSensitivity.UNKNOWN,
                exploit_status=ExploitStatus.PUBLIC_EXPLOIT,
                scanner_source=ScannerSource.TLS,
                evidence_strength=EvidenceStrength.CONFIRMED,
                raw_data={"tls_version": tls_ver, "port": port, "cipher": info.get("cipher")},
            ))

        # Certificate expiry
        if expiry:
            days_left = (expiry - now).days

            if days_left < 0:
                summary["expired"] = True
                findings.append(Finding(
                    title=f"Expired TLS Certificate on Port {port} ({abs(days_left)} Days Ago)",
                    host=domain,
                    port=port,
                    service="tls",
                    cvss_score=7.5,
                    description=(
                        f"The TLS certificate for {domain}:{port} expired "
                        f"{abs(days_left)} day(s) ago (expiry: {expiry.strftime('%Y-%m-%d')}). "
                        "Expired certificates cause browser security errors, break API clients, "
                        "and may prevent the service from being accessed at all. "
                        "Post-acquisition this becomes the new owner's outage immediately."
                    ),
                    remediation=(
                        "Renew the certificate immediately. "
                        "For Let's Encrypt: run 'certbot renew --force-renewal'. "
                        "For commercial CAs: request a new certificate and deploy it. "
                        "Implement ACME-based auto-renewal to prevent recurrence."
                    ),
                    exposure=ExposureLevel.INTERNET_FACING,
                    data_sensitivity=DataSensitivity.UNKNOWN,
                    exploit_status=ExploitStatus.NO_EXPLOIT,
                    scanner_source=ScannerSource.TLS,
                    evidence_strength=EvidenceStrength.CONFIRMED,
                    raw_data={"expiry": expiry.isoformat(), "days_left": days_left, "port": port},
                ))

            elif days_left <= 7:
                summary["expiring_soon"] = True
                findings.append(Finding(
                    title=f"TLS Certificate Expiring in {days_left} Day(s) on Port {port}",
                    host=domain,
                    port=port,
                    service="tls",
                    cvss_score=7.0,
                    description=(
                        f"The TLS certificate for {domain}:{port} expires in {days_left} day(s) "
                        f"(expiry: {expiry.strftime('%Y-%m-%d')}). "
                        "At this proximity to expiry, certificate renewal must happen before "
                        "the deal closes to avoid an immediate post-acquisition service failure."
                    ),
                    remediation=(
                        "Renew immediately — do not wait. "
                        "This must be resolved before deal close or it will be the "
                        "acquirer's problem on Day 1."
                    ),
                    exposure=ExposureLevel.INTERNET_FACING,
                    data_sensitivity=DataSensitivity.UNKNOWN,
                    exploit_status=ExploitStatus.NO_EXPLOIT,
                    scanner_source=ScannerSource.TLS,
                    evidence_strength=EvidenceStrength.CONFIRMED,
                    raw_data={"expiry": expiry.isoformat(), "days_left": days_left, "port": port},
                ))

            elif days_left <= 30:
                summary["expiring_soon"] = True
                findings.append(Finding(
                    title=f"TLS Certificate Expiring in {days_left} Days on Port {port}",
                    host=domain,
                    port=port,
                    service="tls",
                    cvss_score=5.0,
                    description=(
                        f"The TLS certificate for {domain}:{port} expires in {days_left} days "
                        f"(expiry: {expiry.strftime('%Y-%m-%d')}). "
                        "This will likely expire during or shortly after the M&A process, "
                        "creating a service disruption risk post-close."
                    ),
                    remediation=(
                        "Plan certificate renewal as part of pre-close remediation. "
                        "Verify whether auto-renewal is configured. "
                        "If manually managed, schedule renewal before deal close."
                    ),
                    exposure=ExposureLevel.INTERNET_FACING,
                    data_sensitivity=DataSensitivity.UNKNOWN,
                    exploit_status=ExploitStatus.NO_EXPLOIT,
                    scanner_source=ScannerSource.TLS,
                    evidence_strength=EvidenceStrength.CONFIRMED,
                    raw_data={"expiry": expiry.isoformat(), "days_left": days_left, "port": port},
                ))

    # ── Certificate transparency log scan ─────────────────────────────────────
    subdomains = _query_crt_sh(domain)
    summary["subdomains_ct"] = len(subdomains)

    if subdomains:
        preview = subdomains[:10]
        extra   = len(subdomains) - 10
        findings.append(Finding(
            title=f"CT Logs Reveal {len(subdomains)} Subdomain(s) — Review for Shadow IT",
            host=domain,
            service="tls",
            cvss_score=3.5,
            description=(
                f"Certificate transparency logs (crt.sh) show {len(subdomains)} subdomain(s) "
                f"have had TLS certificates issued for {domain}. "
                "These may include forgotten staging servers, old admin panels, or decommissioned "
                "services that still resolve and have not been patched in years. "
                f"Subdomains found: {', '.join(preview)}"
                + (f" (+{extra} more)" if extra > 0 else "")
            ),
            remediation=(
                "Review each subdomain. Verify it is actively maintained, receiving "
                "security patches, and is within the intended attack surface. "
                "Decommission any subdomains that are no longer required. "
                "Ensure all active subdomains are included in the vulnerability scan scope."
            ),
            exposure=ExposureLevel.INTERNET_FACING,
            data_sensitivity=DataSensitivity.UNKNOWN,
            exploit_status=ExploitStatus.UNKNOWN,
            scanner_source=ScannerSource.TLS,
            evidence_strength=EvidenceStrength.CONFIRMED,
            raw_data={"subdomains": subdomains, "count": len(subdomains)},
        ))

    return findings, summary
