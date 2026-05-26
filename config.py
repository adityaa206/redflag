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
# -T4             : aggressive timing (default T3 is ~2x slower, T5 can miss ports)
# --max-retries 2 : fewer retransmissions without losing reliability
NMAP_SCAN_ARGS = "-sV --open -T4 --max-retries 2"

# Fast mode: top 200 ports, lower version probe intensity, one retry
# Cuts scan time to ~15-25s vs 40-70s for the full args above
NMAP_FAST_ARGS = "-sV --open -T4 --top-ports 200 --version-intensity 3 --max-retries 1"
