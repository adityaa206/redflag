"""Cost — remediation budget roll-up + What-If simulator."""
from __future__ import annotations

import reflex as rx

from redflag_ui.state import RedFlagState, CostScenarioRow, CostCatRow, CostItemRow
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
        section("By category", "Where the remediation budget goes"),
        rx.el.div(rx.foreach(RedFlagState.cost_categories, _cat), class_name="cost-cats"),
        section("Line items", "Every estimated remediation, highest first"),
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
            "What remediation will cost the deal",
            "Benchmark-based estimates per finding, deduplicated and rolled up. "
            "Use the What-If controls to scope and stress-test the budget.",
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
