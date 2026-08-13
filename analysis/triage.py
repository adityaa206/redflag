"""
analysis/triage.py — the risk scoring model. The heart of RedFlag.

Turns a Finding into a 0-100 `risk_score` and a `deal_tier`. The score is not a
severity rating: it estimates COMMERCIAL risk to the deal, which is why a CVSS
9.8 on an unreachable internal box can rank below a CVSS 7.5 on an
internet-facing system holding regulated data.

Two stages, in this order:

  1. Deal-killer overrides (check_override_rules) run FIRST and short-circuit.
     A match forces risk_score = 100.0 and tier = DEAL_KILLER outright — these
     are categorical verdicts, not "a very high score".
  2. Otherwise: a weighted sum of four factors, multiplied by an
     evidence-strength factor.

        base  = exploit*0.30 + exposure*0.25 + cvss*0.25 + sensitivity*0.20
        score = base * evidence_multiplier          # 0.80 – 1.00

Weights live in config/__init__.py (they must sum to 1.0 or the score stops
being 0-100). The lookup tables below are the other half of the model.

Deterministic and pure — no network, no config file reads beyond the constants,
no side effects other than mutating the Finding it is handed. 24 tests in
tests/test_triage.py pin this behaviour; read them before changing anything here.
"""
from analysis.schema import (
    Finding,
    DealTier,
    ExposureLevel,
    DataSensitivity,
    ExploitStatus,
    EvidenceStrength,
)
from config import (
    WEIGHT_CVSS,
    WEIGHT_EXPOSURE,
    WEIGHT_SENSITIVITY,
    WEIGHT_EXPLOIT,
    TIER_THRESHOLD_CRITICAL,
    TIER_THRESHOLD_MODERATE,
)


# ── Lookup tables ─────────────────────────────────────────────────────────────
# Each maps an enum to a 0-100 sub-score. UNKNOWN sits mid-scale (50) rather than
# at either extreme: "we don't know" should neither inflate nor suppress a score.

# Can an attacker reach it? Set by the parser (PARTNER/INTERNAL, conservative),
# then upgraded to INTERNET_FACING when Shodan confirms the port is visible.
# The INTERNAL -> INTERNET_FACING jump is worth 17.5 points of base score — the
# single biggest mover in the model, and it usually comes from Shodan.
EXPOSURE_SCORES = {
    ExposureLevel.INTERNET_FACING: 100,
    ExposureLevel.PARTNER: 60,
    ExposureLevel.INTERNAL: 30,
    ExposureLevel.UNKNOWN: 50,
}


# What is at risk behind it? Set ONLY from the asset-inventory Excel upload.
# Without that upload every finding stays UNKNOWN (50) — and override rules 2
# and 3 below become unreachable, since both require CROWN_JEWEL or REGULATED.
SENSITIVITY_SCORES = {
    DataSensitivity.CROWN_JEWEL: 100,
    DataSensitivity.REGULATED: 85,
    DataSensitivity.SENSITIVE: 55,
    DataSensitivity.LOW: 20,
    DataSensitivity.UNKNOWN: 50,
}


# Is it actually exploitable? Carries the heaviest weight (0.30) per CISA SSVC
# and EPSS research: a known-exploited vulnerability demands action regardless
# of CVSS, while a theoretical CVSS 10 with no exploit is a backlog item.
#
# Note UNKNOWN (30) scores ABOVE NO_EXPLOIT (10). Deliberate: absence of
# evidence is treated as more dangerous than evidence of absence.
EXPLOIT_SCORES = {
    ExploitStatus.ACTIVE_EXPLOITATION: 100,
    ExploitStatus.PUBLIC_EXPLOIT: 65,
    ExploitStatus.NO_EXPLOIT: 10,
    ExploitStatus.UNKNOWN: 30,
}


# How well corroborated is the finding? Multiplies the weighted base score so a
# verified OpenVAS/ZAP/Nuclei result outranks a banner-only inference at equal
# severity — and so uploading better evidence visibly improves the ranking.
#
# The 0.80-1.00 range is deliberately NARROW (max 20% discount). Evidence
# quality must adjust the ranking, never suppress a finding: a CVSS 10 /
# internet-facing / actively-exploited finding with the weakest evidence still
# scores ~80 and stays in the Critical tier. Under-ranking a real vulnerability
# is a worse failure than over-ranking a false positive.
EVIDENCE_MULTIPLIERS = {
    EvidenceStrength.CONFIRMED: 1.00,
    EvidenceStrength.CORRELATED: 0.95,
    EvidenceStrength.INFERRED: 0.85,
    EvidenceStrength.EXTERNAL: 0.80,
    EvidenceStrength.UNKNOWN: 0.90,
}


def check_override_rules(finding: Finding) -> tuple[bool, str]:
    """
    Deal-killer overrides. Evaluated BEFORE any scoring; a match short-circuits
    triage entirely and forces risk_score = 100.0.

    These are categorical verdicts, not high scores: each says "this finding
    alone should stop the deal until it is resolved or contractually mitigated".
    That is why they bypass the weighted model rather than feeding into it — no
    combination of good hygiene elsewhere should be able to dilute them.

    Four rules, in evaluation order:
      1. The CVE is in CISA KEV (confirmed exploited in the wild).
      2. Crown-jewel asset, CVSS >= 9.0, internet-facing.
      3. Regulated-data asset, CVSS >= 9.5, internet-facing.
      4. An analyst manually flagged it via override_reason.

    Rules 2 and 3 can only fire if an asset inventory was uploaded — without one,
    data_sensitivity stays UNKNOWN for every finding.

    Returns (is_deal_killer, reason).
    """
    if finding.exploit_status == ExploitStatus.ACTIVE_EXPLOITATION:
        return True, "Active exploitation in the wild detected for this CVE."

    if (
        finding.data_sensitivity == DataSensitivity.CROWN_JEWEL
        and finding.cvss_score >= 9.0
        and finding.exposure == ExposureLevel.INTERNET_FACING
    ):
        return True, (
            f"Crown jewel asset is internet-facing with critical CVSS {finding.cvss_score}. "
            "This combination represents unacceptable pre-close risk."
        )

    if (
        finding.data_sensitivity == DataSensitivity.REGULATED
        and finding.cvss_score >= 9.5
        and finding.exposure == ExposureLevel.INTERNET_FACING
    ):
        return True, (
            f"Regulated data asset is internet-facing with CVSS {finding.cvss_score}. "
            "Regulatory liability risk is too high to proceed without remediation."
        )

    # Manual analyst escape hatch: override_reason is dual-purpose — triage
    # WRITES it to explain a forced verdict, and also READS it here as an input.
    if finding.override_reason and "active compromise" in finding.override_reason.lower():
        return True, "Finding manually flagged as active compromise indicator."

    return False, ""


def calculate_base_score(finding: Finding) -> float:
    """
    The weighted sum of the four risk factors, before evidence adjustment.

    Returns 0-100, because the four weights sum to 1.0 and every sub-score is
    itself 0-100. CVSS is the only factor needing conversion (0-10 -> 0-100).

    The `.get(..., default)` fallbacks mirror the UNKNOWN row of each table, so
    a Finding carrying an unexpected value scores mid-scale rather than raising.
    """
    cvss_normalized = (finding.cvss_score / 10.0) * 100

    exposure_score = EXPOSURE_SCORES.get(finding.exposure, 50)
    sensitivity_score = SENSITIVITY_SCORES.get(finding.data_sensitivity, 50)
    exploit_score = EXPLOIT_SCORES.get(finding.exploit_status, 30)

    score = (
        (cvss_normalized * WEIGHT_CVSS) +
        (exposure_score * WEIGHT_EXPOSURE) +
        (sensitivity_score * WEIGHT_SENSITIVITY) +
        (exploit_score * WEIGHT_EXPLOIT)
    )

    return score


def apply_evidence_adjustment(score: float, finding: Finding) -> float:
    """
    Discount the base score by how well corroborated the finding is.

    Multiplicative, not additive — evidence strength is a statement about how
    much to trust the other four factors, not a risk factor of its own. Added,
    a well-verified finding with no actual risk would score points for being
    well-verified.
    """
    multiplier = EVIDENCE_MULTIPLIERS.get(finding.evidence_strength, 0.90)
    return round(score * multiplier, 2)


def calculate_score(finding: Finding) -> float:
    """Full non-override score: weighted base, then evidence adjustment."""
    base_score = calculate_base_score(finding)
    adjusted_score = apply_evidence_adjustment(base_score, finding)
    return round(adjusted_score, 2)


def score_to_tier(score: float) -> DealTier:
    """Map a 0-100 score onto a deal tier. Thresholds from config/__init__.py.

    Never returns DEAL_KILLER — that tier is reachable only through an override
    rule, so it stays a categorical verdict rather than the top of a scale.
    """
    if score >= TIER_THRESHOLD_CRITICAL:
        return DealTier.CRITICAL
    elif score >= TIER_THRESHOLD_MODERATE:
        return DealTier.MODERATE
    else:
        return DealTier.MANAGEABLE


def triage(finding: Finding) -> Finding:
    """Score and classify one Finding, MUTATING and returning the same object."""
    is_deal_killer, reason = check_override_rules(finding)

    if is_deal_killer:
        # Short-circuit: skip the weighted model entirely. Note this overwrites
        # override_reason with the explanation of why the rule fired.
        finding.risk_score = 100.0
        finding.deal_tier = DealTier.DEAL_KILLER
        finding.override_reason = reason
        return finding

    score = calculate_score(finding)

    finding.risk_score = score
    finding.deal_tier = score_to_tier(score)
    return finding


def triage_all(findings: list[Finding]) -> list[Finding]:
    """Score every Finding and return them sorted highest-risk first.

    The sort order is the contract: the UI tables, the PDF and the CSV all
    render this list as-is and rely on it being descending by risk_score.

    Note the inputs are mutated in place (triage does), but a NEW list is
    returned — callers should use the return value, not the argument.
    """
    triaged = [triage(f) for f in findings]
    return sorted(triaged, key=lambda f: f.risk_score, reverse=True)