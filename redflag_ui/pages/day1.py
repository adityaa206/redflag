"""Day 1 plan — the full Safe Harbor Blueprint."""
from __future__ import annotations

import reflex as rx

from redflag_ui.state import (
    RedFlagState, LadderStep, PillarRow, GateRow, CritRow, ModelCard, PhaseGroup, ActionRow,
)
from redflag_ui.components.shell import shell
from redflag_ui.components.ui import section, empty_state


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


def _crit(c: CritRow) -> rx.Component:
    return rx.el.div(
        rx.el.span(c.ico, class_name="ico"),
        rx.el.div(c.label, rx.cond(c.detail != "", rx.el.span("  ·  ", c.detail))),
        class_name=c.row_class,
    )


def _gate(g: GateRow) -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.div(g.name, class_name="gate-name"),
            rx.el.div(g.status_label, class_name=g.status_class),
            class_name="gate-head",
        ),
        rx.foreach(g.criteria, _crit),
        class_name=g.card_class,
    )


def _model(m: ModelCard) -> rx.Component:
    return rx.el.div(
        rx.cond(m.badge != "", rx.el.div(m.badge, class_name="model-badge")),
        rx.el.div(m.name, class_name="model-name"),
        rx.el.div(m.summary, class_name="model-summary"),
        rx.el.ul(rx.foreach(m.controls, lambda c: rx.el.li(c)), class_name="model-controls"),
        rx.cond(
            m.sources.length() > 0,
            rx.el.div(
                rx.el.div("References", class_name="model-src-head"),
                rx.foreach(
                    m.sources,
                    lambda s: rx.el.div(
                        rx.el.span("·", class_name="model-src-bullet"),
                        rx.el.span(s),
                        class_name="model-src-cite",
                    ),
                ),
                class_name="model-sources",
            ),
        ),
        class_name=m.card_class,
    )


def _action(a: ActionRow) -> rx.Component:
    return rx.el.div(
        rx.el.div(a.risk, class_name=a.risk_class),
        rx.el.div(
            rx.el.div(a.title, class_name="action-title"),
            rx.el.div(a.meta, class_name="action-meta"),
            rx.el.div(a.rationale, class_name="action-rationale"),
        ),
        rx.el.span(a.tag_label, class_name="action-tag"),
        class_name="action-card",
    )


def _phase(p: PhaseGroup) -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.span(p.tag, class_name=p.tag_class),
            rx.el.span(p.title, class_name="phase-title"),
            rx.el.span(p.count_label, class_name="phase-count"),
            class_name="phase-head",
        ),
        rx.cond(
            p.has_items,
            rx.foreach(p.actions, _action),
            rx.el.div("No items in this phase — clear.", class_name="placeholder"),
        ),
        class_name="phase-block",
    )


def _content() -> rx.Component:
    return rx.fragment(
        section("Day 1 Safe Harbor Blueprint", "Recommended connectivity posture", rule=True),
        rx.el.div(
            rx.el.div("Recommended posture", class_name="posture-figure"),
            rx.el.div(RedFlagState.posture_name, class_name="posture-name"),
            rx.el.div(RedFlagState.posture_desc, class_name="posture-desc"),
            rx.el.p(RedFlagState.day1_narrative, class_name="pillar-rec"),
            style={"maxWidth": "760px", "marginTop": "8px"},
        ),
        section("The ladder", "Escalate connectivity only as controls are proven"),
        rx.el.ul(rx.foreach(RedFlagState.ladder, _ladder_step), class_name="ladder-list"),
        section("Tier gates", "What unlocks each posture"),
        rx.el.div(rx.foreach(RedFlagState.gates, _gate), class_name="gate-grid"),
        section("Review pillars", "Identity · network · remote access", rule=True),
        rx.el.div(rx.foreach(RedFlagState.pillars, _pillar), class_name="pillar-grid"),
        section("Fix-first roadmap", "Sequenced P0 → P3 against cutover", rule=True),
        rx.foreach(RedFlagState.phases, _phase),
        section("Architecture catalog", "The four connectivity models", rule=True),
        rx.el.div(rx.foreach(RedFlagState.models, _model), class_name="model-grid"),
    )


def day1() -> rx.Component:
    return shell(
        "Day 1 plan",
        rx.cond(
            RedFlagState.scanned | RedFlagState.mat_done,
            _content(),
            empty_state(
                "Day 1 plan awaits ",
                "data.",
                "Run a scan (or fill the Maturity questionnaire) and the Safe Harbor Blueprint — "
                "posture, ladder, tier gates, pillars and the P0→P3 roadmap — builds automatically.",
            ),
        ),
    )
