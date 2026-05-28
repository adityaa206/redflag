"""
analysis/maturity.py — Inside-Out Maturity Assessment engine.

Converts questionnaire answers (0-5 per question) into domain maturity scores,
then compares against the corporate standard from config/corporate_standard.yaml.

All computation is deterministic — no external API calls.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from config.loader import (
    get_maturity_questions,
    get_corporate_standard,
    get_overall_deal_blocker_threshold,
)


# ── Enums ─────────────────────────────────────────────────────────────────────

class MaturityGapSeverity(str, Enum):
    DEAL_BLOCKER = "deal_blocker"   # Below deal_blocker threshold
    BELOW_MIN    = "below_min"      # Below acceptable_min but not deal_blocker
    ACCEPTABLE   = "acceptable"     # At or above acceptable_min
    AT_TARGET    = "at_target"      # At or above recommended level


# ── Value objects ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DomainScore:
    """Maturity score for a single domain."""
    domain:           str                 # domain key from YAML
    label:            str                 # human-readable label
    score:            float               # weighted average 0–5
    answered:         int                 # number of questions answered
    total_questions:  int                 # total questions in domain
    gap_severity:     MaturityGapSeverity
    acceptable_min:   int
    recommended:      int
    deal_blocker:     int
    rationale:        str = ""

    @property
    def coverage(self) -> float:
        """Fraction of questions answered (0–1)."""
        return self.answered / self.total_questions if self.total_questions else 0.0

    @property
    def gap_to_acceptable(self) -> float:
        """How far below acceptable_min (0 if at or above)."""
        return max(0.0, self.acceptable_min - self.score)

    @property
    def gap_to_recommended(self) -> float:
        """How far below recommended (0 if at or above)."""
        return max(0.0, self.recommended - self.score)

    @property
    def is_deal_blocker(self) -> bool:
        return self.gap_severity == MaturityGapSeverity.DEAL_BLOCKER

    @property
    def is_below_acceptable(self) -> bool:
        return self.gap_severity in (
            MaturityGapSeverity.DEAL_BLOCKER,
            MaturityGapSeverity.BELOW_MIN,
        )


@dataclass
class MaturityAssessment:
    """Full maturity assessment result."""
    id:               str   = field(default_factory=lambda: str(uuid.uuid4()))
    target:           str   = ""
    domain_scores:    list  = field(default_factory=list)   # list[DomainScore]
    overall_score:    float = 0.0
    is_deal_blocker:  bool  = False
    deal_blocker_domains:  list = field(default_factory=list)   # list[str]
    below_acceptable_domains: list = field(default_factory=list)  # list[str]
    completion_pct:   float = 0.0   # fraction of all questions answered

    @property
    def has_gaps(self) -> bool:
        return len(self.below_acceptable_domains) > 0

    @property
    def gap_domains(self) -> list[DomainScore]:
        """Return only domain scores that are below acceptable minimum."""
        return [d for d in self.domain_scores if d.is_below_acceptable]

    @property
    def blocker_domains(self) -> list[DomainScore]:
        return [d for d in self.domain_scores if d.is_deal_blocker]


# ── Engine ────────────────────────────────────────────────────────────────────

def score_domain(domain_key: str, answers: dict[str, int]) -> Optional[DomainScore]:
    """
    Compute the maturity score for a single domain.

    Args:
        domain_key: domain key as per maturity_questions.yaml
        answers:    {question_id: level (0-5)}  — missing = not answered

    Returns:
        DomainScore or None if the domain is not in the config.
    """
    questions_cfg = get_maturity_questions()
    standard_cfg  = get_corporate_standard()

    domain_cfg = questions_cfg.get("domains", {}).get(domain_key)
    if not domain_cfg:
        return None

    questions       = domain_cfg.get("questions", [])
    domain_label    = domain_cfg.get("label", domain_key)
    standard        = standard_cfg.get("domains", {}).get(domain_key, {})
    acceptable_min  = int(standard.get("acceptable_min", 2))
    recommended     = int(standard.get("recommended", 3))
    deal_blocker    = int(standard.get("deal_blocker", 1))
    rationale       = standard.get("rationale", "")

    total_weight = 0.0
    weighted_sum = 0.0
    answered = 0

    for q in questions:
        qid    = q["id"]
        weight = float(q.get("weight", 1.0))
        total_weight += weight

        if qid in answers:
            level = int(answers[qid])
            level = max(0, min(5, level))
            weighted_sum += level * weight
            answered += 1

    if answered == 0:
        score = 0.0
    else:
        # Scale: only count answered questions' weight in denominator
        answered_weight = sum(
            float(q.get("weight", 1.0))
            for q in questions
            if q["id"] in answers
        )
        score = weighted_sum / answered_weight if answered_weight else 0.0

    # Determine gap severity
    if score <= deal_blocker and answered > 0:
        severity = MaturityGapSeverity.DEAL_BLOCKER
    elif score < acceptable_min:
        severity = MaturityGapSeverity.BELOW_MIN
    elif score < recommended:
        severity = MaturityGapSeverity.ACCEPTABLE
    else:
        severity = MaturityGapSeverity.AT_TARGET

    return DomainScore(
        domain=domain_key,
        label=domain_label,
        score=round(score, 2),
        answered=answered,
        total_questions=len(questions),
        gap_severity=severity,
        acceptable_min=acceptable_min,
        recommended=recommended,
        deal_blocker=deal_blocker,
        rationale=str(rationale).strip(),
    )


def run_assessment(answers: dict[str, int], target: str = "") -> MaturityAssessment:
    """
    Run the full maturity assessment from a flat dict of question answers.

    Args:
        answers: {question_id: level (0-5)}
        target:  scan target string for labelling

    Returns:
        MaturityAssessment with all domain scores computed.
    """
    questions_cfg = get_maturity_questions()
    domains       = list(questions_cfg.get("domains", {}).keys())

    domain_scores: list[DomainScore] = []
    total_questions_all = 0
    answered_all        = 0

    for domain_key in domains:
        ds = score_domain(domain_key, answers)
        if ds:
            domain_scores.append(ds)
            total_questions_all += ds.total_questions
            answered_all        += ds.answered

    # Compute overall weighted average (weight all domains equally)
    if domain_scores:
        overall_score = sum(ds.score for ds in domain_scores) / len(domain_scores)
    else:
        overall_score = 0.0

    # Determine overall deal-blocker
    threshold         = get_overall_deal_blocker_threshold()
    blocker_domains   = [ds.domain for ds in domain_scores if ds.is_deal_blocker]
    is_deal_blocker   = (overall_score <= threshold and answered_all > 0) or bool(blocker_domains)

    below_acceptable  = [ds.domain for ds in domain_scores if ds.is_below_acceptable]

    completion_pct = (answered_all / total_questions_all * 100) if total_questions_all else 0.0

    return MaturityAssessment(
        target=target,
        domain_scores=domain_scores,
        overall_score=round(overall_score, 2),
        is_deal_blocker=is_deal_blocker,
        deal_blocker_domains=blocker_domains,
        below_acceptable_domains=below_acceptable,
        completion_pct=round(completion_pct, 1),
    )


def get_all_question_ids() -> list[str]:
    """Return all question IDs across all domains (used to build the Streamlit form)."""
    questions_cfg = get_maturity_questions()
    ids = []
    for domain in questions_cfg.get("domains", {}).values():
        for q in domain.get("questions", []):
            ids.append(q["id"])
    return ids


def get_domain_questions(domain_key: str) -> list[dict]:
    """Return list of question dicts for a domain."""
    questions_cfg = get_maturity_questions()
    return questions_cfg.get("domains", {}).get(domain_key, {}).get("questions", [])


def get_all_domains() -> list[tuple[str, str]]:
    """Return list of (domain_key, label) tuples."""
    questions_cfg = get_maturity_questions()
    return [
        (k, v.get("label", k))
        for k, v in questions_cfg.get("domains", {}).items()
    ]
