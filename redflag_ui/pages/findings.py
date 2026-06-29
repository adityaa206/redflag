"""Findings — the full ranked finding list."""
from __future__ import annotations

import reflex as rx

from redflag_ui.state import RedFlagState
from redflag_ui.components.shell import shell
from redflag_ui.components.ui import section, empty_state
from redflag_ui.pages.overview import _finding_row


def _content() -> rx.Component:
    return rx.fragment(
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


def findings() -> rx.Component:
    return shell(
        "Findings",
        rx.cond(
            RedFlagState.scanned,
            _content(),
            empty_state(
                "No findings ",
                "yet.",
                "Run a scan or upload OpenVAS / ZAP / Shodan output above to populate the ranked finding list.",
            ),
        ),
    )
