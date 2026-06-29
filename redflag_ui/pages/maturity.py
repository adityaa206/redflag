"""Maturity — inside-out control assessment questionnaire + RAG results."""
from __future__ import annotations

import reflex as rx

from redflag_ui.state import RedFlagState, DomainRow, MATURITY_FORM
from redflag_ui.components.shell import shell
from redflag_ui.components.ui import section


# ── results (dynamic) ────────────────────────────────────────────────────────
def _domain_result(d: DomainRow) -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.div(d.name, class_name="mat-name"),
            rx.el.div(
                rx.el.span(d.score, class_name="mat-score"),
                rx.el.span("/ 5", class_name="mat-score-max"),
                rx.el.span(d.rag_label, class_name=d.rag_class),
                class_name="mat-right",
            ),
            class_name="mat-row-head",
        ),
        rx.el.div(
            rx.el.div(class_name="mat-bar-fill " + d.bar_class, style={"width": d.score_w}),
            class_name="mat-bar",
        ),
        rx.el.div(d.detail, class_name="mat-detail"),
        class_name="mat-result",
    )


def _results() -> rx.Component:
    return rx.fragment(
        section("Assessment result", "Domain maturity scoring", rule=True),
        rx.el.div(
            rx.el.div(
                rx.el.div(RedFlagState.mat_overall, class_name="mat-overall-fig"),
                rx.el.span("Overall maturity / 5", class_name="mat-overall-cap"),
                class_name="mat-overall",
            ),
            rx.el.div(
                rx.cond(
                    RedFlagState.mat_blocker,
                    rx.el.span("Deal-blocker maturity gap", class_name="rag red"),
                    rx.el.span("No deal-blocker maturity gap", class_name="rag green"),
                ),
                rx.el.div(
                    RedFlagState.mat_completion, "% of questions answered",
                    class_name="mat-completion",
                ),
                rx.el.p(RedFlagState.mat_narrative, class_name="mat-narrative"),
                rx.el.button("Clear assessment", on_click=RedFlagState.reset_maturity, class_name="btn ghost"),
                class_name="mat-overall-side",
            ),
            class_name="mat-summary",
        ),
        rx.el.div(
            rx.foreach(RedFlagState.mat_domains, _domain_result),
            class_name="mat-results",
        ),
    )


# ── questionnaire (static, from YAML) ────────────────────────────────────────
def _question(q: dict) -> rx.Component:
    options = [rx.el.option("— Not assessed —", value="")]
    for i, opt in enumerate(q["options"]):
        options.append(rx.el.option(f"Level {i}  ·  {opt}", value=str(i)))
    return rx.el.div(
        rx.el.label(q["text"], class_name="mat-q"),
        rx.el.select(*options, name=q["id"], default_value="", class_name="mat-select"),
        class_name="mat-qrow",
    )


def _domain(dom: dict) -> rx.Component:
    return rx.el.div(
        rx.el.div(dom["label"], class_name="mat-domain-title"),
        rx.el.div(dom["description"], class_name="mat-domain-desc"),
        *[_question(q) for q in dom["questions"]],
        class_name="mat-domain",
    )


def _form() -> rx.Component:
    return rx.form(
        *[_domain(dom) for dom in MATURITY_FORM],
        rx.el.div(
            rx.el.button("Score maturity", type="submit", class_name="btn"),
            rx.el.span(
                "Unanswered questions are skipped — score reflects only what you answer.",
                class_name="mat-hint",
            ),
            class_name="mat-actions",
        ),
        on_submit=RedFlagState.submit_maturity,
        reset_on_submit=False,
    )


def maturity() -> rx.Component:
    return shell(
        "Maturity",
        section(
            "Security maturity",
            "Inside-out control assessment",
            "Self-reported control maturity across seven domains. Feeds the Day-1 identity "
            "and network pillars and the cost model.",
        ),
        rx.cond(RedFlagState.mat_done, _results()),
        section("Questionnaire", "Rate each control 0 (none) to 5 (optimised)"),
        _form(),
    )
