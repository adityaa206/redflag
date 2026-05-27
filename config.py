# ── Triage scoring weights ─────────────────────────────────────────────────────
# Must sum to 1.0
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
#       Mirrors CVSS Attack Vector dimension.
#   CVSS Score      (0.25) — technical severity baseline; kept equal to exposure
#       because a high CVSS on an unreachable service is lower priority than a
#       moderate CVSS on an internet-facing one.
#   Data Sensitivity(0.20) — business / regulatory impact layer; lower than the
#       three technical factors but still material for deal-killer classification.
WEIGHT_CVSS        = 0.25
WEIGHT_EXPOSURE    = 0.25
WEIGHT_SENSITIVITY = 0.20
WEIGHT_EXPLOIT     = 0.30

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
