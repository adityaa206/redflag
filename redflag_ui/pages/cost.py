"""Cost — remediation budget roll-up + What-If simulator."""
from __future__ import annotations

import reflex as rx

from redflag_ui.state import (
    RedFlagState, CostScenarioRow, CostCatRow, CostItemRow, CostLadderRow, QuoteRow,
)
from redflag_ui.components.shell import shell
from redflag_ui.components.ui import section, placeholder, empty_state


def _scn(s: CostScenarioRow) -> rx.Component:
    return rx.el.div(
        rx.el.div(s.name, class_name="cost-scn-name"),
        rx.el.div(s.total, class_name="cost-scn-total"),
        rx.el.div("capex ", s.capex, "  ·  opex ", s.opex, class_name="cost-scn-split"),
        rx.el.div(s.count_label, class_name="cost-scn-count"),
        class_name=s.active_class,
    )


def _cat(c: CostCatRow) -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.span(c.name, class_name="cost-cat-name"),
            rx.el.span(c.base, class_name="cost-cat-val"),
            class_name="cost-cat-head",
        ),
        rx.el.div(
            rx.el.div(class_name="cost-cat-fill", style={"width": c.bar_w}),
            class_name="cost-cat-bar",
        ),
        class_name="cost-cat",
    )


def _item(it: CostItemRow) -> rx.Component:
    return rx.el.tr(
        rx.el.td(
            rx.el.div(it.title, class_name="title-c"),
            rx.el.div(it.category, class_name="cve"),
        ),
        rx.el.td(it.kind),
        rx.el.td(it.confidence),
        rx.el.td(
            rx.cond(
                it.flag != "",
                rx.el.span(it.flag, class_name="cost-flag on"),
                rx.el.span("—", class_name="cost-flag"),
            )
        ),
        rx.el.td(it.base, class_name="num cost-item-base"),
    )


def _accuracy() -> rx.Component:
    """Prominent estimate-accuracy readout (confidence % + ± band)."""
    return rx.el.div(
        rx.el.div(
            rx.el.div("Estimate accuracy", class_name="acc-kicker"),
            rx.el.div(
                rx.el.span(RedFlagState.cost_accuracy_pct, class_name="acc-pct-num"),
                rx.el.span("%", class_name="acc-pct-sym"),
                class_name="acc-pct-wrap " + RedFlagState.cost_accuracy_class,
            ),
            rx.el.div("± ", RedFlagState.cost_accuracy_band, "% around the base case",
                      class_name="acc-band"),
            class_name="acc-left",
        ),
        rx.el.div(
            rx.el.div(
                rx.el.div(class_name="acc-bar-fill " + RedFlagState.cost_accuracy_class,
                          style={"width": RedFlagState.cost_accuracy_w}),
                class_name="acc-bar",
            ),
            rx.el.div(
                rx.el.span("80% confidence range  ", class_name="acc-ci-k"),
                rx.el.span(RedFlagState.cost_ci_low, class_name="acc-ci-v"),
                rx.el.span("  –  ", class_name="acc-ci-dash"),
                rx.el.span(RedFlagState.cost_ci_high, class_name="acc-ci-v"),
                class_name="acc-ci",
            ),
            rx.el.div(
                "Variance-based across every line item's sourced-pricing confidence "
                "(independent errors partly cancel). ",
                rx.cond(
                    RedFlagState.cost_headcount_assumed,
                    rx.el.span("Using an assumed headcount — enter the acquired employee "
                               "count to tighten it.", class_name="acc-hint"),
                    rx.el.span("Add vendor quotes to raise items to high confidence.",
                               class_name="acc-hint"),
                ),
                class_name="acc-note",
            ),
            class_name="acc-right",
        ),
        class_name="acc-card",
    )


def _split() -> rx.Component:
    """Remediation + Integration = combined Day-1 budget."""
    return rx.el.div(
        rx.el.div(
            rx.el.div("Remediation", class_name="split-k"),
            rx.el.div(RedFlagState.cost_remediation_base, class_name="split-v"),
            rx.el.div("fix findings + maturity gaps", class_name="split-sub"),
            class_name="split-cell",
        ),
        rx.el.div("+", class_name="split-op"),
        rx.el.div(
            rx.el.div("Integration", class_name="split-k"),
            rx.el.div(RedFlagState.cost_integration_base, class_name="split-v c-teal"),
            rx.el.div(RedFlagState.cost_integration_label, class_name="split-sub"),
            class_name="split-cell",
        ),
        rx.el.div("=", class_name="split-op"),
        rx.el.div(
            rx.el.div("Total Day-1", class_name="split-k"),
            rx.el.div(RedFlagState.cost_base, class_name="split-v split-total"),
            rx.el.div("base case", class_name="split-sub"),
            class_name="split-cell",
        ),
        class_name="cost-split",
    )


def _rung(r: CostLadderRow) -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.span(r.name, class_name="rung-name"),
            rx.cond(r.tag != "", rx.el.span(r.tag, class_name="rung-tag")),
            rx.el.span(r.base, class_name="rung-val"),
            class_name="rung-head",
        ),
        rx.el.div(
            rx.el.div(class_name="rung-fill", style={"width": r.bar_w}),
            class_name="rung-bar",
        ),
        class_name=r.active_class,
    )


def _quote_input(q: QuoteRow) -> rx.Component:
    return rx.el.div(
        rx.el.label(q.title, class_name="quote-label"),
        rx.el.input(
            name=q.key,
            default_value=q.quoted,
            placeholder=q.benchmark,
            type="number",
            min="0",
            class_name=rx.cond(q.is_quoted, "quote-input quoted", "quote-input"),
        ),
        class_name="quote-row",
    )


def _quotes() -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.div("Vendor quotes", class_name="quote-kicker"),
            rx.el.span(
                "Paste a real quoted total for any item — it replaces the benchmark, pins "
                "that line to high confidence, and tightens the accuracy toward it.",
                class_name="quote-help",
            ),
            class_name="quote-head",
        ),
        rx.form(
            rx.el.div(rx.foreach(RedFlagState.cost_quote_rows, _quote_input), class_name="quote-grid"),
            rx.el.div(
                rx.el.button("Apply quotes", type="submit", class_name="btn"),
                rx.el.button("Clear", type="button", on_click=RedFlagState.clear_quotes,
                             class_name="btn ghost"),
                rx.cond(
                    RedFlagState.cost_quotes_n > 0,
                    rx.el.span(RedFlagState.cost_quotes_n, " quote(s) applied",
                               class_name="quote-count"),
                ),
                class_name="quote-actions",
            ),
            on_submit=RedFlagState.apply_quotes,
            reset_on_submit=False,
        ),
        class_name="quote-box",
    )


def _integration() -> rx.Component:
    return rx.fragment(
        section("Day-1 integration budget",
                "What it costs to safely connect the acquired company",
                "Prices the recommended connectivity model on sourced 2026 benchmarks "
                "(VDI/DaaS, SSO, ZTNA, EDR, PAM, SIEM, migration, TSA). Separate from "
                "remediation — this is the integration spend.", rule=True),
        rx.el.div(
            rx.el.div(
                rx.el.div(RedFlagState.cost_integration_base, class_name="cost-big"),
                rx.el.div(RedFlagState.cost_integration_label, class_name="cost-big-cap"),
                class_name="cost-big-wrap",
            ),
            rx.el.div(
                rx.el.div(rx.el.span("Low", class_name="cost-k"),
                          rx.el.span(RedFlagState.cost_integration_low, class_name="cost-vv"), class_name="cost-kv"),
                rx.el.div(rx.el.span("High", class_name="cost-k"),
                          rx.el.span(RedFlagState.cost_integration_high, class_name="cost-vv"), class_name="cost-kv"),
                class_name="cost-grid",
            ),
            class_name="cost-headline",
        ),
        rx.el.div("Cost of each connectivity tier — the price of integrating faster",
                  class_name="rung-caption"),
        rx.el.div(rx.foreach(RedFlagState.cost_ladder, _rung), class_name="cost-ladder"),
        rx.el.table(
            rx.el.thead(
                rx.el.tr(
                    rx.el.th("Integration item"),
                    rx.el.th("Capex / Opex"),
                    rx.el.th("Confidence"),
                    rx.el.th("Review"),
                    rx.el.th("Base cost", class_name="num"),
                )
            ),
            rx.el.tbody(rx.foreach(RedFlagState.cost_integration_items, _item)),
            class_name="tbl",
            style={"marginTop": "14px"},
        ),
        _quotes(),
    )


def _scn_btn(value: str, label: str) -> rx.Component:
    return rx.el.button(
        label,
        on_click=RedFlagState.set_cost_scenario(value),
        class_name=rx.cond(RedFlagState.cost_scenario == value, "cost-tab active", "cost-tab"),
    )


def _controls() -> rx.Component:
    return rx.el.div(
        rx.el.div(
            _scn_btn("low", "Best case"),
            _scn_btn("base", "Most likely"),
            _scn_btn("high", "Worst case"),
            class_name="cost-tabs",
        ),
        rx.el.div(
            rx.el.label("Budget scope"),
            rx.el.select(
                rx.el.option("All findings", value="all"),
                rx.el.option("Deal-killers + critical", value="dk_cr"),
                rx.el.option("Deal-killers only", value="dk"),
                value=RedFlagState.cost_scope,
                on_change=RedFlagState.set_cost_scope,
                class_name="cost-select",
            ),
            class_name="cost-control",
        ),
        rx.el.div(
            rx.el.label("Acquired employees"),
            rx.el.input(
                value=RedFlagState.cost_headcount.to_string(),
                on_change=RedFlagState.set_cost_headcount,
                type="number",
                min="0",
                class_name="cost-select",
            ),
            class_name="cost-control",
        ),
        rx.el.label(
            rx.checkbox(
                checked=RedFlagState.cost_include_maturity,
                on_change=RedFlagState.toggle_cost_maturity,
            ),
            rx.el.span("Include maturity-gap remediation"),
            class_name="cost-check",
        ),
        class_name="cost-controls",
    )


def _headline() -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.div(RedFlagState.cost_headline, class_name="cost-big"),
            rx.el.div(RedFlagState.cost_headline_label, class_name="cost-big-cap"),
            class_name="cost-big-wrap",
        ),
        rx.el.div(
            rx.el.div(rx.el.span("Low", class_name="cost-k"), rx.el.span(RedFlagState.cost_low, class_name="cost-vv"), class_name="cost-kv"),
            rx.el.div(rx.el.span("Base", class_name="cost-k"), rx.el.span(RedFlagState.cost_base, class_name="cost-vv"), class_name="cost-kv"),
            rx.el.div(rx.el.span("High", class_name="cost-k"), rx.el.span(RedFlagState.cost_high, class_name="cost-vv"), class_name="cost-kv"),
            rx.el.div(rx.el.span("Capex", class_name="cost-k"), rx.el.span(RedFlagState.cost_capex, class_name="cost-vv"), class_name="cost-kv"),
            rx.el.div(rx.el.span("Opex", class_name="cost-k"), rx.el.span(RedFlagState.cost_opex, class_name="cost-vv"), class_name="cost-kv"),
            class_name="cost-grid",
        ),
        class_name="cost-headline",
    )


def _details() -> rx.Component:
    return rx.fragment(
        _headline(),
        _accuracy(),
        _split(),
        rx.cond(
            RedFlagState.cost_flagged_n > 0,
            rx.el.div(
                rx.el.strong(RedFlagState.cost_flagged_n),
                " line item(s) flagged for human review before this budget is signed off.",
                class_name="cost-review-note",
            ),
        ),
        rx.el.p(RedFlagState.cost_narrative, class_name="pillar-rec", style={"maxWidth": "820px", "marginTop": "18px"}),
        section("Scenarios", "Sensitivity across best / likely / worst case"),
        rx.el.div(rx.foreach(RedFlagState.cost_scenarios, _scn), class_name="cost-scn-grid"),
        section("By category", "Where the combined budget goes"),
        rx.el.div(rx.foreach(RedFlagState.cost_categories, _cat), class_name="cost-cats"),
        _integration(),
        section("Remediation line items", "Every estimated remediation, highest first", rule=True),
        rx.el.table(
            rx.el.thead(
                rx.el.tr(
                    rx.el.th("Remediation"),
                    rx.el.th("Capex / Opex"),
                    rx.el.th("Confidence"),
                    rx.el.th("Review"),
                    rx.el.th("Base cost", class_name="num"),
                )
            ),
            rx.el.tbody(rx.foreach(RedFlagState.cost_items, _item)),
            class_name="tbl",
        ),
    )


def _content() -> rx.Component:
    return rx.fragment(
        section(
            "Cost & budget",
            "Remediation + Day-1 integration, with a stated accuracy",
            "Benchmark-based estimates: deduplicated remediation per finding PLUS the "
            "Day-1 integration budget for the recommended connectivity model. Every "
            "estimate carries a confidence %. Use the What-If controls to scope and "
            "stress-test the budget.",
        ),
        _controls(),
        rx.cond(
            RedFlagState.cost_ready,
            _details(),
            placeholder("No remediation cost lines were estimated for the current scope."),
        ),
    )


def cost() -> rx.Component:
    return shell(
        "Cost",
        rx.cond(
            RedFlagState.scanned,
            _content(),
            empty_state(
                "No budget ",
                "yet.",
                "Run a scan or upload findings — RedFlag estimates a deduplicated remediation "
                "budget with best / likely / worst-case sensitivity.",
            ),
        ),
    )
