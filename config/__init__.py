# config package
# Re-exports both the original constants (previously in root config.py) and the
# new YAML-backed loader helpers so existing imports like
#   from config import WEIGHT_CVSS
# continue to work alongside
#   from config import get_pricing_benchmarks

# ── Triage scoring weights ────────────────────────────────────────────────────
# MUST sum to 1.0, or risk_score stops being a 0-100 scale.
#
# Aligned with SSVC (CISA / Carnegie Mellon Stakeholder-Specific Vulnerability
# Categorisation) and EPSS (Exploit Prediction Scoring System) methodology.
#
# Rationale:
#   Exploit Status  (0.30) — highest weight: active/public exploitation is the
#       primary triage signal per CISA KEV guidance and EPSS research. A known-
#       exploited vulnerability demands immediate action regardless of CVSS.
#   Exposure        (0.25) — attack surface drives reachability; internet-facing
#       assets face orders-of-magnitude more threat activity than internal ones.
#       Mirrors the CVSS Attack Vector dimension.
#   CVSS Score      (0.25) — technical severity baseline; kept equal to exposure
#       because a high CVSS on an unreachable service is lower priority than a
#       moderate CVSS on an internet-facing one.
#   Data Sensitivity(0.20) — business / regulatory impact layer; lower than the
#       three technical factors but still material for deal-killer classification.
#
# Changing any of these changes every score RedFlag has ever produced — treat it
# as a versioned decision, and re-read tests/test_triage.py first.
WEIGHT_CVSS        = 0.25
WEIGHT_EXPOSURE    = 0.25
WEIGHT_SENSITIVITY = 0.20
WEIGHT_EXPLOIT     = 0.30

# ── Score-to-tier thresholds ──────────────────────────────────────────────────
# >= 75 CRITICAL · >= 50 MODERATE · below MANAGEABLE.
# DEAL_KILLER is NOT on this scale — it is reachable only via an override rule
# in analysis/triage.py, so it stays a categorical verdict.
TIER_THRESHOLD_CRITICAL   = 75
TIER_THRESHOLD_MODERATE   = 50

# ── Shodan ────────────────────────────────────────────────────────────────────
SHODAN_MAX_CVES = 10          # max standalone CVE findings created from Shodan vulns

# ── Vulners NSE ───────────────────────────────────────────────────────────────
VULNERS_MIN_CVSS            = 5.0   # ignore CVEs below this CVSS from NSE output
VULNERS_STANDALONE_MIN_CVSS = 7.0   # min CVSS for secondary CVEs on a matched port

# ── Nmap ──────────────────────────────────────────────────────────────────────
# -T4             : aggressive timing (default T3 is ~2x slower, T5 can miss ports)
# --max-retries 2 : fewer retransmissions without losing reliability
NMAP_SCAN_ARGS = "-sV --open -T4 --max-retries 2"

# Fast mode: top 200 ports, lower version probe intensity, one retry.
# Cuts scan time to ~15-25s vs 40-70s for the full args above — and is gentler
# on a fragile target.
NMAP_FAST_ARGS = "-sV --open -T4 --top-ports 200 --version-intensity 3 --max-retries 1"

# ── YAML-backed loader helpers ────────────────────────────────────────────────
from config.loader import (
    get_maturity_questions,
    get_corporate_standard,
    get_pricing_benchmarks,
    get_remediation_catalog,
    get_narrative_blocks,
    get_labour_rate,
    get_effort_hours,
    get_tool_cost,
    get_domain_standard,
    get_overall_deal_blocker_threshold,
    reload_all,
)

__all__ = [
    # constants
    "WEIGHT_CVSS", "WEIGHT_EXPOSURE", "WEIGHT_SENSITIVITY", "WEIGHT_EXPLOIT",
    "TIER_THRESHOLD_CRITICAL", "TIER_THRESHOLD_MODERATE",
    "SHODAN_MAX_CVES",
    "VULNERS_MIN_CVSS", "VULNERS_STANDALONE_MIN_CVSS",
    "NMAP_SCAN_ARGS", "NMAP_FAST_ARGS",
    # loader helpers
    "get_maturity_questions", "get_corporate_standard",
    "get_pricing_benchmarks", "get_remediation_catalog",
    "get_narrative_blocks",
    "get_labour_rate", "get_effort_hours", "get_tool_cost",
    "get_domain_standard", "get_overall_deal_blocker_threshold",
    "reload_all",
]
