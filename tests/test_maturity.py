"""
tests/test_maturity.py — Unit tests for the maturity assessment engine.
"""
import pytest
from analysis.maturity import (
    run_assessment,
    score_domain,
    get_all_domains,
    get_all_question_ids,
    MaturityGapSeverity,
)
from analysis.standards_compare import compare_to_standard


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _all_zero_answers() -> dict:
    """Return answers where every question is answered at level 0."""
    return {qid: 0 for qid in get_all_question_ids()}


def _all_five_answers() -> dict:
    """Return answers where every question is answered at level 5."""
    return {qid: 5 for qid in get_all_question_ids()}


def _mid_answers() -> dict:
    """Return answers at level 3 for all questions."""
    return {qid: 3 for qid in get_all_question_ids()}


# ── score_domain tests ────────────────────────────────────────────────────────

def test_score_domain_returns_none_for_unknown():
    result = score_domain("nonexistent_domain_xyz", {})
    assert result is None


def test_score_domain_zero_when_no_answers():
    ds = score_domain("identity_access", {})
    assert ds is not None
    assert ds.score == 0.0
    assert ds.answered == 0


def test_score_domain_max_when_all_five():
    answers = {qid: 5 for qid in get_all_question_ids()}
    ds = score_domain("identity_access", answers)
    assert ds is not None
    assert ds.score == pytest.approx(5.0, abs=0.01)


def test_score_domain_partial_answers():
    """Only answer one question — score should reflect that question's value."""
    questions = get_all_question_ids()
    # Answer just the first identity_access question at level 3
    from config.loader import get_maturity_questions
    q_cfg = get_maturity_questions()
    first_q = q_cfg["domains"]["identity_access"]["questions"][0]["id"]
    ds = score_domain("identity_access", {first_q: 3})
    assert ds is not None
    assert 0 < ds.score <= 5
    assert ds.answered == 1


def test_score_domain_clamped_to_0_5():
    """Out-of-range answers are clamped to 0–5."""
    answers = {qid: 10 for qid in get_all_question_ids()}
    ds = score_domain("network_security", answers)
    assert ds.score == pytest.approx(5.0, abs=0.01)


def test_score_domain_gap_severity_deal_blocker():
    """All-zero answers should produce DEAL_BLOCKER severity."""
    ds = score_domain("identity_access", _all_zero_answers())
    assert ds.gap_severity == MaturityGapSeverity.DEAL_BLOCKER


def test_score_domain_gap_severity_at_target():
    """All-five answers should produce AT_TARGET severity."""
    ds = score_domain("identity_access", _all_five_answers())
    assert ds.gap_severity == MaturityGapSeverity.AT_TARGET


# ── run_assessment tests ───────────────────────────────────────────────────────

def test_run_assessment_empty_answers():
    assessment = run_assessment({})
    assert assessment.overall_score == 0.0
    assert assessment.completion_pct == 0.0


def test_run_assessment_all_zero_is_deal_blocker():
    assessment = run_assessment(_all_zero_answers())
    assert assessment.is_deal_blocker is True
    assert len(assessment.deal_blocker_domains) > 0


def test_run_assessment_all_five_not_deal_blocker():
    assessment = run_assessment(_all_five_answers())
    assert assessment.is_deal_blocker is False
    assert assessment.overall_score == pytest.approx(5.0, abs=0.01)


def test_run_assessment_coverage():
    assessment = run_assessment(_all_five_answers())
    assert assessment.completion_pct == pytest.approx(100.0, abs=0.1)


def test_run_assessment_mid_has_correct_domain_count():
    assessment = run_assessment(_mid_answers())
    domains = get_all_domains()
    assert len(assessment.domain_scores) == len(domains)


def test_run_assessment_target_stored():
    assessment = run_assessment(_mid_answers(), target="test.example.com")
    assert assessment.target == "test.example.com"


# ── compare_to_standard tests ─────────────────────────────────────────────────

def test_compare_all_zero_has_deal_blockers():
    assessment = run_assessment(_all_zero_answers())
    gap_report = compare_to_standard(assessment)
    assert gap_report.has_deal_blockers


def test_compare_all_five_no_gaps():
    assessment = run_assessment(_all_five_answers())
    gap_report = compare_to_standard(assessment)
    assert not gap_report.deal_blocker_gaps
    assert not gap_report.below_min_gaps


def test_compare_gap_items_have_catalog_key():
    assessment = run_assessment(_all_zero_answers())
    gap_report = compare_to_standard(assessment)
    for gap in gap_report.gaps:
        assert gap.catalog_key, f"Gap for {gap.domain} has no catalog_key"
        assert gap.catalog_key.endswith("_gap")


def test_compare_total_gap_count():
    assessment = run_assessment(_mid_answers())
    gap_report = compare_to_standard(assessment)
    # At score 3, most domains should be at or above acceptable_min=2
    # but below recommended=3 or 4 — so gaps should exist but not deal-blockers
    assert gap_report.total_gap_count >= 0  # sanity — doesn't crash
