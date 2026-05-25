from analysis.schema import (
    Finding,
    DealTier,
    ExposureLevel,
    DataSensitivity,
    ExploitStatus,
    EvidenceStrength,
)


WEIGHT_CVSS = 0.35
WEIGHT_EXPOSURE = 0.25
WEIGHT_SENSITIVITY = 0.25
WEIGHT_EXPLOIT = 0.15


EXPOSURE_SCORES = {
    ExposureLevel.INTERNET_FACING: 100,
    ExposureLevel.PARTNER: 60,
    ExposureLevel.INTERNAL: 30,
    ExposureLevel.UNKNOWN: 50,
}


SENSITIVITY_SCORES = {
    DataSensitivity.CROWN_JEWEL: 100,
    DataSensitivity.REGULATED: 85,
    DataSensitivity.SENSITIVE: 55,
    DataSensitivity.LOW: 20,
    DataSensitivity.UNKNOWN: 50,
}


EXPLOIT_SCORES = {
    ExploitStatus.ACTIVE_EXPLOITATION: 100,
    ExploitStatus.PUBLIC_EXPLOIT: 65,
    ExploitStatus.NO_EXPLOIT: 10,
    ExploitStatus.UNKNOWN: 30,
}


EVIDENCE_MULTIPLIERS = {
    EvidenceStrength.CONFIRMED: 1.00,
    EvidenceStrength.CORRELATED: 0.95,
    EvidenceStrength.INFERRED: 0.85,
    EvidenceStrength.EXTERNAL: 0.80,
    EvidenceStrength.UNKNOWN: 0.90,
}


def check_override_rules(finding: Finding) -> tuple[bool, str]:
    """
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

    if finding.override_reason and "active compromise" in finding.override_reason.lower():
        return True, "Finding manually flagged as active compromise indicator."

    return False, ""


def calculate_base_score(finding: Finding) -> float:
    """
    Computes the raw weighted score before evidence adjustment.
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
    Adjust the score based on how strong the supporting evidence is.
    """
    multiplier = EVIDENCE_MULTIPLIERS.get(finding.evidence_strength, 0.90)
    return round(score * multiplier, 2)


def calculate_score(finding: Finding) -> float:
    base_score = calculate_base_score(finding)
    adjusted_score = apply_evidence_adjustment(base_score, finding)
    return round(adjusted_score, 2)


def score_to_tier(score: float) -> DealTier:
    if score >= 75:
        return DealTier.CRITICAL
    elif score >= 50:
        return DealTier.MODERATE
    else:
        return DealTier.MANAGEABLE


def triage(finding: Finding) -> Finding:
    is_deal_killer, reason = check_override_rules(finding)

    if is_deal_killer:
        finding.risk_score = 100.0
        finding.deal_tier = DealTier.DEAL_KILLER
        finding.override_reason = reason
        return finding

    score = calculate_score(finding)

    finding.risk_score = score
    finding.deal_tier = score_to_tier(score)
    return finding


def triage_all(findings: list[Finding]) -> list[Finding]:
    triaged = [triage(f) for f in findings]
    return sorted(triaged, key=lambda f: f.risk_score, reverse=True)