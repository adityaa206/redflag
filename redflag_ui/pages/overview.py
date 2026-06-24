"""Overview — the editorial diligence summary (mirrors mockup 05)."""
from __future__ import annotations

import reflex as rx

from redflag_ui.state import RedFlagState, FindingRow, LadderStep, PillarRow
from redflag_ui.components.shell import shell
from redflag_ui.components.ui import section


def _article_head() -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.span(class_name="pulse"),
            rx.el.span("Diligence summary"),
            rx.el.span("·", class_name="sep"),
            rx.el.span(RedFlagState.target),
            rx.el.span("·", class_name="sep"),
            rx.el.span(RedFlagState.scan_date),
            class_name="dateline",
        ),
        rx.el.h1(RedFlagState.headline, class_name="headline"),
        rx.el.p(RedFlagState.standfirst, class_name="standfirst"),
        rx.el.div(
            rx.el.span(rx.el.strong("Prepared by"), " RedFlag engine"),
            rx.el.span("/", class_name="sep"),
            rx.el.span(RedFlagState.scanner_count, " scanners"),
            rx.el.span("/", class_name="sep"),
            rx.el.span(RedFlagState.scan_seconds, "-second scan"),
            rx.el.span("/", class_name="sep"),
            rx.el.span(rx.el.strong("For"), " Acquirer M&A team"),
            class_name="byline",
        ),
        class_name="article-head",
    )


def _verdict() -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.div(RedFlagState.avg_score, class_name="v"),
            rx.el.span("Average risk score", class_name="cap"),
            class_name="verdict-figure",
        ),
        rx.el.div(
            rx.el.div("The verdict", class_name="verdict-kicker"),
            rx.el.div(RedFlagState.verdict_label, class_name="verdict-label"),
            rx.el.div(RedFlagState.verdict_msg, class_name="verdict-msg"),
            class_name="verdict-main",
        ),
        rx.el.div(
            rx.el.div(rx.el.span(RedFlagState.n_dk, class_name="num c-dk"), rx.el.span("Killers", class_name="lbl"), class_name="col"),
            rx.el.div(rx.el.span(RedFlagState.n_crit, class_name="num c-cr"), rx.el.span("Critical", class_name="lbl"), class_name="col"),
            rx.el.div(rx.el.span(RedFlagState.n_mod, class_name="num c-mo"), rx.el.span("Moderate", class_name="lbl"), class_name="col"),
            rx.el.div(rx.el.span(RedFlagState.n_man, class_name="num c-ma"), rx.el.span("Manageable", class_name="lbl"), class_name="col"),
            class_name="verdict-stats",
        ),
        class_name="verdict",
    )


def _tier_stats() -> rx.Component:
    def stat(figure_var, fig_class, label, sub):
        return rx.el.div(
            rx.el.div(figure_var, class_name=f"figure {fig_class}"),
            rx.el.div(label, class_name="label"),
            rx.el.div(sub, class_name="sub"),
            class_name="tier-stat",
        )
    return rx.el.div(
        stat(RedFlagState.n_dk, "dk", "Deal killer", "Blocks the close"),
        stat(RedFlagState.n_crit, "cr", "Critical", "Remediate within 30 days"),
        stat(RedFlagState.n_mod, "mo", "Moderate", "90-day integration item"),
        stat(RedFlagState.n_man, "ma", "Manageable", "Post-close hygiene"),
        class_name="tier-stats",
    )


def _editors_note() -> rx.Component:
    return rx.el.div(
        rx.el.p(RedFlagState.exec_summary),
        rx.el.div("“", RedFlagState.pull_quote, "”", class_name="pullquote"),
        rx.el.p(RedFlagState.day1_narrative),
        class_name="article",
    )


def _ladder_step(step: LadderStep) -> rx.Component:
    return rx.el.li(
        rx.el.span(step.num, class_name="step-num mono"),
        rx.el.div(
            rx.el.div(step.name, class_name="step-name"),
            rx.el.div(step.desc, class_name="step-desc"),
        ),
        rx.el.span(step.status_label, class_name="step-stat"),
        class_name=step.li_class,
    )


def _pillar(p: PillarRow) -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.div(p.name, class_name="pillar-name"),
            rx.el.div(p.rag_label, class_name=p.rag_class),
            class_name="pillar-row",
        ),
        rx.el.div(p.evidence, class_name="pillar-evidence"),
        rx.el.div(p.recommendation, class_name="pillar-rec"),
        class_name="pillar-block",
    )


def _day1_spread() -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.div("Recommended posture", class_name="posture-figure"),
            rx.el.div(RedFlagState.posture_name, class_name="posture-name"),
            rx.el.div(RedFlagState.posture_desc, class_name="posture-desc"),
            rx.el.ul(rx.foreach(RedFlagState.ladder, _ladder_step), class_name="ladder-list"),
            class_name="col-left",
        ),
        rx.el.div(
            rx.foreach(RedFlagState.pillars, _pillar),
            class_name="col-right",
        ),
        class_name="spread",
    )


def _finding_row(row: FindingRow) -> rx.Component:
    return rx.el.tr(
        rx.el.td(
            rx.el.div(row.title, class_name="title-c"),
            rx.el.div(row.cve_line, class_name="cve"),
        ),
        rx.el.td(rx.el.div(row.host_line, rx.el.br(), row.service, class_name="host")),
        rx.el.td(row.exposure_label),
        rx.el.td(rx.el.span(row.tier_label, class_name=row.tag_class)),
        rx.el.td(rx.el.span(row.risk, class_name=row.risk_class), class_name="num"),
    )


def _findings_table() -> rx.Component:
    return rx.el.table(
        rx.el.thead(
            rx.el.tr(
                rx.el.th("Finding"),
                rx.el.th("Host · service"),
                rx.el.th("Exposure"),
                rx.el.th("Tier"),
                rx.el.th("Risk", class_name="num"),
            )
        ),
        rx.el.tbody(rx.foreach(RedFlagState.findings_rows, _finding_row)),
        class_name="tbl",
    )


def overview() -> rx.Component:
    return shell(
        "Overview",
        _article_head(),
        _verdict(),
        section("By the numbers", "One verdict, four tiers"),
        _tier_stats(),
        section("Editor’s note", "What this scan tells us", rule=True),
        _editors_note(),
        section("Day 1 Safe Harbor Blueprint", "A staged connectivity ladder", rule=True),
        _day1_spread(),
        section("The findings", "In order of risk"),
        _findings_table(),
    )
