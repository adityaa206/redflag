"""On-brand placeholders for tabs not yet ported (engines already exist)."""
from __future__ import annotations

import reflex as rx

from redflag_ui.components.shell import shell
from redflag_ui.components.ui import section, placeholder


def attack() -> rx.Component:
    return shell(
        "Attack path",
        section("Attack path", "How an intruder chains exposure into impact"),
        placeholder(
            "The attack-path graph (pyvis/network model) will render here, reusing the "
            "existing graph builder. Port scheduled after the core editorial views."
        ),
    )


def maturity() -> rx.Component:
    return shell(
        "Maturity",
        section("Security maturity", "Inside-out control assessment"),
        placeholder(
            "The maturity questionnaire and domain RAG scoring (analysis.maturity) will "
            "render here, feeding the Day 1 identity & network pillars."
        ),
    )


def cost() -> rx.Component:
    return shell(
        "Cost",
        section("Cost & budget", "What remediation will cost the deal"),
        placeholder(
            "The remediation cost roll-up and What-If simulator (cost.rollup) will render "
            "here in the emerald design language."
        ),
    )


def export() -> rx.Component:
    return shell(
        "Export",
        section("Export", "Deal-room deliverables"),
        rx.el.div(
            rx.el.button("Download CSV", class_name="btn ghost", disabled=True),
            rx.el.button("Download PDF report", class_name="btn ghost", disabled=True),
            rx.el.button("Day 1 blueprint PDF", class_name="btn ghost", disabled=True),
            style={"display": "flex", "gap": "12px", "marginTop": "16px", "flexWrap": "wrap"},
        ),
        placeholder(
            "CSV and PDF export run through the existing reports/ engine "
            "(generator.py, pdf_report.py). Buttons activate once wired to the Reflex "
            "download handler."
        ),
    )
