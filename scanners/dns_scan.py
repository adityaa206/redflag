"""
DNS & Email Security Scanner — Feature 2
Checks SPF, DMARC, DKIM, and DNSSEC for a target domain.
Each gap becomes a Finding object that feeds into the triage pipeline.
"""

import dns.resolver
import dns.exception

from analysis.schema import (
    Finding, ExposureLevel, DataSensitivity, ExploitStatus,
    ScannerSource, EvidenceStrength,
)

_DKIM_SELECTORS = [
    "default", "google", "mail", "selector1", "selector2",
    "dkim", "k1", "s1", "s2", "email", "mandrill", "protonmail",
]


def _txt_records(domain: str) -> list[str]:
    """Return all TXT record values for a domain. Returns [] on any failure."""
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=8)
        return [
            "".join(
                part.decode("utf-8", errors="replace") if isinstance(part, bytes) else part
                for part in rdata.strings
            )
            for rdata in answers
        ]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.exception.Timeout,
        dns.resolver.NoNameservers,
        Exception,
    ):
        return []


def _has_dnssec(domain: str) -> bool:
    """Return True if DNSKEY records exist for the domain."""
    try:
        dns.resolver.resolve(domain, "DNSKEY", lifetime=8)
        return True
    except Exception:
        return False


def _is_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def run_dns_scan(domain: str) -> list[Finding]:
    """
    Run DNS & email security checks against a domain.
    Returns a list of Finding objects — one per gap found.
    Skips silently if domain is a bare IP address.
    """
    if _is_ip(domain):
        return []

    findings: list[Finding] = []

    # ── SPF ───────────────────────────────────────────────────────────────────
    root_txts  = _txt_records(domain)
    spf_records = [r for r in root_txts if r.startswith("v=spf1")]

    if not spf_records:
        findings.append(Finding(
            title="Missing SPF Record",
            host=domain,
            service="dns",
            cvss_score=5.3,
            description=(
                f"No SPF (Sender Policy Framework) record exists for {domain}. "
                "SPF defines which mail servers are authorised to send email on behalf "
                "of this domain. Without it, any attacker can send spoofed emails "
                "that appear to originate from this domain — enabling phishing campaigns "
                "against the acquirer's employees and the target's customers post-merger."
            ),
            remediation=(
                f"Add a TXT record at {domain}: 'v=spf1 include:<mail-provider> -all'. "
                "Replace <mail-provider> with your provider's SPF include "
                "(e.g. include:_spf.google.com for Google Workspace). "
                "Use -all (hard fail) rather than ~all (soft fail) for strict enforcement."
            ),
            exposure=ExposureLevel.INTERNET_FACING,
            data_sensitivity=DataSensitivity.UNKNOWN,
            exploit_status=ExploitStatus.NO_EXPLOIT,
            scanner_source=ScannerSource.DNS,
            evidence_strength=EvidenceStrength.CONFIRMED,
            raw_data={"check": "spf", "domain": domain, "txt_records_found": root_txts},
        ))
    elif len(spf_records) > 1:
        findings.append(Finding(
            title="Multiple SPF Records Detected",
            host=domain,
            service="dns",
            cvss_score=4.0,
            description=(
                f"{len(spf_records)} SPF records were found for {domain}. "
                "RFC 7208 requires exactly one SPF TXT record per domain. "
                "Multiple records cause SPF validation to return PermError, "
                "which means legitimate emails may be rejected and spoofing protection is broken."
            ),
            remediation=(
                "Remove all but one SPF record and consolidate all includes into it. "
                "Example: 'v=spf1 include:provider1 include:provider2 -all'."
            ),
            exposure=ExposureLevel.INTERNET_FACING,
            data_sensitivity=DataSensitivity.UNKNOWN,
            exploit_status=ExploitStatus.NO_EXPLOIT,
            scanner_source=ScannerSource.DNS,
            evidence_strength=EvidenceStrength.CONFIRMED,
            raw_data={"check": "spf", "domain": domain, "spf_records": spf_records},
        ))
    else:
        spf = spf_records[0]
        if "+all" in spf:
            findings.append(Finding(
                title="SPF Record Uses +all (Allow All Mail Servers)",
                host=domain,
                service="dns",
                cvss_score=6.0,
                description=(
                    f"The SPF record for {domain} uses '+all', which explicitly authorises "
                    "any mail server in the world to send email as this domain. "
                    "This renders SPF completely ineffective as an anti-spoofing control."
                ),
                remediation=(
                    f"Replace '+all' with '-all' (hard fail) in the SPF record. "
                    f"Current record: {spf}"
                ),
                exposure=ExposureLevel.INTERNET_FACING,
                data_sensitivity=DataSensitivity.UNKNOWN,
                exploit_status=ExploitStatus.NO_EXPLOIT,
                scanner_source=ScannerSource.DNS,
                evidence_strength=EvidenceStrength.CONFIRMED,
                raw_data={"check": "spf", "domain": domain, "spf_record": spf},
            ))
        elif "~all" in spf:
            findings.append(Finding(
                title="SPF Policy Uses ~all (Soft Fail — No Enforcement)",
                host=domain,
                service="dns",
                cvss_score=3.5,
                description=(
                    f"The SPF record for {domain} uses '~all' (soft fail). "
                    "Soft fail means spoofed emails are accepted and optionally tagged, "
                    "but not rejected. Most email providers do not quarantine soft-fail "
                    "messages, making this policy nearly equivalent to no SPF protection."
                ),
                remediation=(
                    f"Change '~all' to '-all' (hard fail) to enforce strict rejection "
                    f"of unauthorised senders. Current record: {spf}"
                ),
                exposure=ExposureLevel.INTERNET_FACING,
                data_sensitivity=DataSensitivity.UNKNOWN,
                exploit_status=ExploitStatus.NO_EXPLOIT,
                scanner_source=ScannerSource.DNS,
                evidence_strength=EvidenceStrength.CONFIRMED,
                raw_data={"check": "spf", "domain": domain, "spf_record": spf},
            ))

    # ── DMARC ─────────────────────────────────────────────────────────────────
    dmarc_txts    = _txt_records(f"_dmarc.{domain}")
    dmarc_records = [r for r in dmarc_txts if r.startswith("v=DMARC1")]

    if not dmarc_records:
        findings.append(Finding(
            title="Missing DMARC Record",
            host=domain,
            service="dns",
            cvss_score=6.5,
            description=(
                f"No DMARC record was found at _dmarc.{domain}. "
                "DMARC builds on SPF and DKIM to specify a policy for what happens "
                "to emails that fail authentication checks. Without it, there is no "
                "enforcement — spoofed emails pass through even if SPF or DKIM fails. "
                "This is a direct liability the acquirer inherits on Day 1."
            ),
            remediation=(
                f"Add a TXT record at _dmarc.{domain}: "
                "'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourdomain.com'. "
                "Start with p=quarantine, monitor reports for 2-4 weeks, "
                "then move to p=reject for full enforcement."
            ),
            exposure=ExposureLevel.INTERNET_FACING,
            data_sensitivity=DataSensitivity.UNKNOWN,
            exploit_status=ExploitStatus.NO_EXPLOIT,
            scanner_source=ScannerSource.DNS,
            evidence_strength=EvidenceStrength.CONFIRMED,
            raw_data={"check": "dmarc", "domain": domain},
        ))
    else:
        dmarc = dmarc_records[0]
        if "p=none" in dmarc:
            findings.append(Finding(
                title="DMARC Policy is p=none (Monitoring Only, No Enforcement)",
                host=domain,
                service="dns",
                cvss_score=4.5,
                description=(
                    f"DMARC is configured for {domain} but with policy p=none, "
                    "which only monitors and reports — it does not quarantine or reject "
                    "failing emails. This means spoofed emails are still delivered. "
                    "p=none is intended as a temporary monitoring phase, not a permanent policy."
                ),
                remediation=(
                    "Review DMARC aggregate reports (rua) to understand legitimate mail flows, "
                    "then upgrade to p=quarantine and eventually p=reject. "
                    f"Current record: {dmarc}"
                ),
                exposure=ExposureLevel.INTERNET_FACING,
                data_sensitivity=DataSensitivity.UNKNOWN,
                exploit_status=ExploitStatus.NO_EXPLOIT,
                scanner_source=ScannerSource.DNS,
                evidence_strength=EvidenceStrength.CONFIRMED,
                raw_data={"check": "dmarc", "domain": domain, "dmarc_record": dmarc},
            ))

    # ── DKIM ──────────────────────────────────────────────────────────────────
    dkim_found    = False
    dkim_selector = None
    for selector in _DKIM_SELECTORS:
        txts = _txt_records(f"{selector}._domainkey.{domain}")
        if any("v=DKIM1" in r or "k=rsa" in r or ("p=" in r and len(r) > 20) for r in txts):
            dkim_found    = True
            dkim_selector = selector
            break

    if not dkim_found:
        findings.append(Finding(
            title="No DKIM Selector Found",
            host=domain,
            service="dns",
            cvss_score=4.0,
            description=(
                f"No DKIM public key was found for {domain} across "
                f"{len(_DKIM_SELECTORS)} common selector names. "
                "DKIM cryptographically signs outgoing emails so recipients can verify "
                "the message was not altered in transit. Without DKIM, DMARC enforcement "
                "is weaker (relying on SPF alone) and email deliverability may suffer. "
                "Note: DKIM selectors are custom names — this check covers common ones "
                "but custom selectors may exist."
            ),
            remediation=(
                "Configure DKIM signing through your email provider. "
                "Google Workspace, Microsoft 365, and most ESP platforms have "
                "built-in DKIM setup. The public key is then published as a TXT record "
                "at <selector>._domainkey.yourdomain.com."
            ),
            exposure=ExposureLevel.INTERNET_FACING,
            data_sensitivity=DataSensitivity.UNKNOWN,
            exploit_status=ExploitStatus.NO_EXPLOIT,
            scanner_source=ScannerSource.DNS,
            evidence_strength=EvidenceStrength.INFERRED,
            raw_data={"check": "dkim", "domain": domain, "selectors_checked": _DKIM_SELECTORS},
        ))

    # ── DNSSEC ────────────────────────────────────────────────────────────────
    if not _has_dnssec(domain):
        findings.append(Finding(
            title="DNSSEC Not Enabled",
            host=domain,
            service="dns",
            cvss_score=3.0,
            description=(
                f"DNSSEC is not enabled for {domain}. Without DNSSEC, DNS responses "
                "cannot be cryptographically verified, leaving the domain vulnerable to "
                "DNS cache poisoning attacks where attackers redirect traffic to malicious servers. "
                "This is a lower-severity but foundational DNS hygiene issue."
            ),
            remediation=(
                "Enable DNSSEC through your domain registrar or DNS provider. "
                "Cloudflare, AWS Route 53, and most major registrars support one-click "
                "DNSSEC activation. The process takes minutes and adds no maintenance overhead."
            ),
            exposure=ExposureLevel.INTERNET_FACING,
            data_sensitivity=DataSensitivity.UNKNOWN,
            exploit_status=ExploitStatus.NO_EXPLOIT,
            scanner_source=ScannerSource.DNS,
            evidence_strength=EvidenceStrength.CONFIRMED,
            raw_data={"check": "dnssec", "domain": domain},
        ))

    return findings
