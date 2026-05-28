# config package
# Re-exports both the original constants (previously in root config.py) and the
# new YAML-backed loader helpers so existing imports like
#   from config import WEIGHT_CVSS
# continue to work alongside
#   from config import get_pricing_benchmarks

# ── Original triage / scanner constants ───────────────────────────────────────
WEIGHT_CVSS        = 0.25
WEIGHT_EXPOSURE    = 0.25
WEIGHT_SENSITIVITY = 0.20
WEIGHT_EXPLOIT     = 0.30

TIER_THRESHOLD_CRITICAL   = 75
TIER_THRESHOLD_MODERATE   = 50

SHODAN_MAX_CVES = 10

VULNERS_MIN_CVSS            = 5.0
VULNERS_STANDALONE_MIN_CVSS = 7.0

NMAP_SCAN_ARGS = "-sV --open -T4 --max-retries 2"
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
