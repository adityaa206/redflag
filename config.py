# ── Triage scoring weights ─────────────────────────────────────────────────────
# Must sum to 1.0
WEIGHT_CVSS        = 0.35
WEIGHT_EXPOSURE    = 0.25
WEIGHT_SENSITIVITY = 0.25
WEIGHT_EXPLOIT     = 0.15

# ── Score-to-tier thresholds ───────────────────────────────────────────────────
TIER_THRESHOLD_CRITICAL   = 75
TIER_THRESHOLD_MODERATE   = 50

# ── Shodan ────────────────────────────────────────────────────────────────────
SHODAN_MAX_CVES = 10          # max standalone CVE findings created from Shodan vulns

# ── Vulners NSE ───────────────────────────────────────────────────────────────
VULNERS_MIN_CVSS            = 5.0   # ignore CVEs below this CVSS from NSE output
VULNERS_STANDALONE_MIN_CVSS = 7.0   # min CVSS for secondary CVEs on a matched port

# ── Nmap ──────────────────────────────────────────────────────────────────────
NMAP_SCAN_ARGS = "-sV --open"       # base arguments (Vulners NSE appended if installed
