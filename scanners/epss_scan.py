"""
epss_scan.py — enrich findings with FIRST.org EPSS scores (free, no API key).

EPSS (Exploit Prediction Scoring System) gives, per CVE, the probability it will
be exploited in the wild in the next 30 days. We attach that to each finding and
let a high probability upgrade an otherwise-unknown exploit_status — which makes
the risk model forward-looking (likelihood of exploitation), not severity-only.

Best-effort: a network failure or unknown CVE simply leaves findings untouched.
Pure stdlib — no third-party deps.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request

from analysis.schema import ExploitStatus

_EPSS_API = "https://api.first.org/data/v1/epss"
_BATCH = 100

# Promotion threshold. A CVE at least this likely to be exploited within 30
# days, with no exploit flag yet, is treated as having a public exploit.
#
# Why promotion exists: CISA KEV is RETROSPECTIVE — a CVE enters it after
# exploitation has been observed. That leaves a window where a vulnerability is
# trivially exploitable with PoC code circulating, but still scores UNKNOWN (30).
# EPSS is predictive and closes that window.
#
# Why 0.50: a coin-flip chance of exploitation within a month is clearly
# material. It is a judgement, not a calibrated value — EPSS distributions skew
# hard toward zero, so a much lower threshold would promote most CVEs and
# destroy the signal, while a much higher one would miss the window entirely.
EPSS_PROMOTE_THRESHOLD = 0.50


def _norm(x) -> str:
    return str(getattr(x, "value", x))


def fetch_epss(cve_ids) -> dict:
    """Return {cve_id: {"epss": float, "percentile": float}} for known CVEs.

    Batches the comma-separated FIRST.org API; best-effort per batch.
    """
    out: dict = {}
    cves = sorted({c for c in cve_ids if c and str(c).upper().startswith("CVE-")})
    for i in range(0, len(cves), _BATCH):
        chunk = cves[i:i + _BATCH]
        url = _EPSS_API + "?" + urllib.parse.urlencode({"cve": ",".join(chunk)})
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "RedFlag/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                payload = json.load(resp)
        except Exception:
            continue
        for row in payload.get("data", []):
            cid = row.get("cve")
            if not cid:
                continue
            try:
                out[cid] = {"epss": float(row.get("epss", 0)),
                            "percentile": float(row.get("percentile", 0))}
            except (TypeError, ValueError):
                continue
    return out


def enrich_findings_with_epss(findings: list, scores: dict | None = None) -> list:
    """Attach EPSS scores to findings; promote exploit_status when very likely.

    `scores` may be supplied (tests / offline); otherwise fetched live. The
    promotion never downgrades an already-active-exploitation finding, and never
    raises — EPSS is an enrichment layer, not a hard dependency.
    """
    if not findings:
        return findings
    cve_ids = [getattr(f, "cve_id", None) for f in findings if getattr(f, "cve_id", None)]
    if not cve_ids:
        return findings
    if scores is None:
        try:
            scores = fetch_epss(cve_ids)
        except Exception:
            scores = {}
    if not scores:
        return findings

    for f in findings:
        cid = getattr(f, "cve_id", None)
        s = scores.get(cid) if cid else None
        if not s:
            continue
        # The probability is attached to every matched finding regardless of
        # promotion, so the UI can show "EPSS 92%" even when the tier is unchanged.
        f.epss_score = s.get("epss")
        f.epss_percentile = s.get("percentile")

        # Promotion is deliberately constrained three ways:
        #   • only UNKNOWN / NO_EXPLOIT are promoted — never a downgrade;
        #   • the ceiling is PUBLIC_EXPLOIT (65), NEVER ACTIVE_EXPLOITATION (100),
        #     because that value forces a deal-killer verdict and a prediction
        #     must not, on its own, stop a deal;
        #   • the result is marked in raw_data so a reader can tell an inferred
        #     status from a sourced one.
        if (s.get("epss") or 0) >= EPSS_PROMOTE_THRESHOLD and \
                _norm(f.exploit_status) in ("unknown", "no_exploit"):
            f.exploit_status = ExploitStatus.PUBLIC_EXPLOIT
            if isinstance(f.raw_data, dict):
                f.raw_data["epss_promoted"] = True
            elif f.raw_data is None:
                f.raw_data = {"epss_promoted": True}
    return findings
