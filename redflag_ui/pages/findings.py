"""Findings — the full ranked finding list."""
from __future__ import annotations

import reflex as rx

from redflag_ui.state import RedFlagState
from redflag_ui.components.shell import shell
from redflag_ui.components.ui import section
from redflag_ui.pages.overview import _finding_row


def findings() -> rx.Component:
    return shell(
        "Findings",
        section("All findings", "Every signal, highest risk first"),
        rx.el.table(
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
        ),
    )
