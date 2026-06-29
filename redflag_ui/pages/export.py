"""Export — deal-room deliverables (CSV + PDF) via the reports/ engine."""
from __future__ import annotations

import reflex as rx

from redflag_ui.state import RedFlagState
from redflag_ui.components.shell import shell
from redflag_ui.components.ui import section, empty_state


def _deliverable(title: str, desc: str, button_label: str, handler, kind: str) -> rx.Component:
    return rx.el.div(
        rx.el.div(kind, class_name="exp-kind"),
        rx.el.div(title, class_name="exp-title"),
        rx.el.div(desc, class_name="exp-desc"),
        rx.el.button(button_label, on_click=handler, class_name="btn"),
        class_name="exp-card",
    )


def _content() -> rx.Component:
    return rx.fragment(
        section(
            "Export",
            "Deal-room deliverables",
            "Generated on demand from the same engines that drive every tab — nothing is cached or stale.",
        ),
        rx.el.div(
            _deliverable(
                "Findings CSV",
                "Every finding with CVE, host, scanner, CVSS, risk score, tier, exposure and remediation — ready for the data room.",
                "Download CSV", RedFlagState.download_csv, "Spreadsheet",
            ),
            _deliverable(
                "Full PDF report",
                "The branded diligence report: verdict, tier summary and the ranked finding detail.",
                "Download PDF", RedFlagState.download_pdf, "Report",
            ),
            _deliverable(
                "Day 1 blueprint PDF",
                "The Safe Harbor Blueprint — recommended posture, pillars and the P0→P3 fix-first roadmap.",
                "Download Day 1 PDF", RedFlagState.download_day1_pdf, "Blueprint",
            ),
            _deliverable(
                "Cost budget PDF",
                "The remediation cost roll-up with best / likely / worst-case sensitivity and category breakdown.",
                "Download cost PDF", RedFlagState.download_cost_pdf, "Budget",
            ),
            class_name="exp-grid",
        ),
    )


def export() -> rx.Component:
    return shell(
        "Export",
        rx.cond(
            RedFlagState.scanned,
            _content(),
            empty_state(
                "Nothing to export ",
                "yet.",
                "Run a scan or upload findings, then download the CSV, full PDF, Day-1 blueprint and cost budget.",
            ),
        ),
    )
