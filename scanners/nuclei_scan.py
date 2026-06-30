"""
nuclei_scan.py — ProjectDiscovery Nuclei integration (free, template-based DAST).

Nuclei confirms *actual* vulnerabilities (CVEs, exposed panels, default creds,
misconfigurations) rather than just open ports, so its findings carry CONFIRMED
evidence strength. Two entry points:

  • run_nuclei_scan(target)   — run the local nuclei binary (degrades to [] if
    it isn't installed, like the Vulners NSE), parse its JSONL output.
  • parse_nuclei_jsonl(text)  — parse nuclei JSONL produced anywhere (upload),
    so users without the binary can still feed nuclei results in.

merge_nuclei_with_nmap() correlates results into the Nmap layer by (host, port),
upgrading matched findings — exactly like the OpenVAS/ZAP merges.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from analysis.schema import (
    Finding, ScannerSource, ExposureLevel, ExploitStatus, EvidenceStrength,
)
from scanners.kev_lookup import is_kev


_SEVERITY_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.5, "low": 3.0, "info": 0.0}
_WEB_SERVICES = {"http", "https", "ssl"}

_EXPLOIT_RANK = {
    ExploitStatus.ACTIVE_EXPLOITATION: 3, ExploitStatus.PUBLIC_EXPLOIT: 2,
    ExploitStatus.UNKNOWN: 1, ExploitStatus.NO_EXPLOIT: 0,
}


def _higher_exploit(a, b):
    return a if _EXPLOIT_RANK.get(a, 0) >= _EXPLOIT_RANK.get(b, 0) else b


def find_nuclei() -> str | None:
    """Locate the nuclei binary cross-platform (PATH first, then common spots)."""
    found = shutil.which("nuclei")
    if found:
        return found
    candidates = [
        os.path.expanduser(os.path.join("~", "go", "bin", "nuclei")),
        os.path.expanduser(os.path.join("~", "go", "bin", "nuclei.exe")),
        r"C:\Program Files\Nuclei\nuclei.exe",
        "/usr/local/bin/nuclei", "/opt/homebrew/bin/nuclei",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def nuclei_available() -> bool:
    return find_nuclei() is not None


# ── parsing ───────────────────────────────────────────────────────────────────
def _host_port(rec: dict) -> tuple[str | None, int | None, str | None]:
    """Best-effort (host, port, service) from a nuclei record."""
    host = None
    port = None
    service = None
    raw_host = rec.get("host") or rec.get("matched-at") or rec.get("ip") or ""
    raw_host = str(raw_host)

    # strip scheme
    m = re.match(r"^([a-zA-Z]+)://(.*)$", raw_host)
    if m:
        scheme, rest = m.group(1).lower(), m.group(2)
        service = scheme if scheme in ("http", "https") else service
        if scheme == "https":
            port = 443
        elif scheme == "http":
            port = 80
        raw_host = rest

    raw_host = raw_host.split("/", 1)[0]          # drop any path
    if ":" in raw_host:
        h, p = raw_host.rsplit(":", 1)
        host = h or None
        try:
            port = int(p)
        except ValueError:
            pass
    else:
        host = raw_host or None

    if rec.get("port"):
        try:
            port = int(rec["port"])
        except (TypeError, ValueError):
            pass
    return host, port, service


def _record_to_finding(rec: dict) -> Finding | None:
    info = rec.get("info") or {}
    severity = str(info.get("severity", "")).lower()
    classification = info.get("classification") or {}

    cve_list = classification.get("cve-id") or classification.get("cve") or []
    if isinstance(cve_list, str):
        cve_list = [cve_list]
    cve_id = next((c for c in cve_list if str(c).upper().startswith("CVE-")), None)

    # drop pure-informational findings unless they carry a CVE
    if severity in ("info", "") and not cve_id:
        return None

    cvss = classification.get("cvss-score")
    try:
        cvss = float(cvss) if cvss is not None else _SEVERITY_CVSS.get(severity, 4.0)
    except (TypeError, ValueError):
        cvss = _SEVERITY_CVSS.get(severity, 4.0)
    cvss = max(0.0, min(10.0, cvss))

    host, port, service = _host_port(rec)
    name = info.get("name") or rec.get("template-id") or "Nuclei finding"

    if cve_id and is_kev(cve_id):
        exploit = ExploitStatus.ACTIVE_EXPLOITATION
    elif cvss >= 7.0:
        exploit = ExploitStatus.PUBLIC_EXPLOIT
    else:
        exploit = ExploitStatus.UNKNOWN

    exposure = (ExposureLevel.INTERNET_FACING
                if (service in _WEB_SERVICES or port in (80, 443, 8080, 8443))
                else ExposureLevel.PARTNER)

    raw = {
        "source": "nuclei",
        "template_id": rec.get("template-id"),
        "severity": severity,
        "matched_at": rec.get("matched-at"),
        "type": rec.get("type"),
        "tags": info.get("tags"),
    }
    return Finding(
        title=name,
        cve_id=cve_id,
        host=host,
        port=port,
        service=service or rec.get("type") or None,
        cvss_score=cvss,
        description=str(info.get("description") or name),
        remediation=str(info.get("remediation") or "Review the matched template and patch/lock down the affected service."),
        exposure=exposure,
        exploit_status=exploit,
        scanner_source=ScannerSource.NUCLEI,
        evidence_strength=EvidenceStrength.CONFIRMED,
        raw_data=raw,
    )


def parse_nuclei_jsonl(text_or_path: str) -> list[Finding]:
    """Parse nuclei JSONL (one JSON object per line). Accepts a path or raw text.

    Also tolerates a single JSON array (`-json` output on some versions).
    """
    if not text_or_path:
        return []
    text = text_or_path
    try:
        if "\n" not in text_or_path and os.path.exists(text_or_path):
            with open(text_or_path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
    except (OSError, ValueError):
        text = text_or_path

    records: list[dict] = []
    stripped = text.strip()
    if stripped.startswith("["):
        try:
            arr = json.loads(stripped)
            if isinstance(arr, list):
                records = [r for r in arr if isinstance(r, dict)]
        except json.JSONDecodeError:
            records = []
    if not records:
        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
                if isinstance(rec, dict):
                    records.append(rec)
            except json.JSONDecodeError:
                continue

    findings: list[Finding] = []
    for rec in records:
        try:
            f = _record_to_finding(rec)
            if f is not None:
                findings.append(f)
        except Exception:
            continue
    return findings


# ── live scan ─────────────────────────────────────────────────────────────────
def run_nuclei_scan(target: str, fast_mode: bool = False, timeout: int = 300) -> list[Finding]:
    """Run the local nuclei binary against `target`; [] if it isn't installed."""
    exe = find_nuclei()
    if not exe or not target:
        return []
    args = [exe, "-u", target, "-jsonl", "-silent", "-disable-update-check",
            "-severity", "low,medium,high,critical"]
    if fast_mode:
        args += ["-rate-limit", "200", "-timeout", "5"]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return parse_nuclei_jsonl(proc.stdout or "")
    except Exception:
        return []


# ── correlation merge (mirrors merge_openvas_with_nmap) ──────────────────────
def merge_nuclei_with_nmap(nmap_findings: list[Finding],
                           nuclei_findings: list[Finding]) -> list[Finding]:
    """Correlate nuclei findings into the Nmap layer by (host, port).

    A matched Nmap finding is upgraded to CONFIRMED, takes the higher CVSS and
    exploit status, and inherits a CVE if it had none. Unmatched nuclei findings
    are appended standalone.
    """
    index: dict[tuple, Finding] = {}
    for f in nmap_findings:
        if f.host and f.port is not None:
            index[(f.host, f.port)] = f

    standalone: list[Finding] = []
    for nf in nuclei_findings:
        key = (nf.host, nf.port) if (nf.host and nf.port is not None) else None
        match = index.get(key) if key else None
        if match:
            match.evidence_strength = EvidenceStrength.CONFIRMED
            if nf.cvss_score > match.cvss_score:
                match.cvss_score = nf.cvss_score
            match.exploit_status = _higher_exploit(match.exploit_status, nf.exploit_status)
            if not match.cve_id and nf.cve_id:
                match.cve_id = nf.cve_id
        else:
            standalone.append(nf)
    return nmap_findings + standalone
