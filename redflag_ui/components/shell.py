"""App shell — top bar, navigation, scan controls, and the page container."""
from __future__ import annotations

import reflex as rx

from redflag_ui.state import RedFlagState

NAV = [
    ("Overview", "/"),
    ("Findings", "/findings"),
    ("Attack path", "/attack"),
    ("Maturity", "/maturity"),
    ("Day 1 plan", "/day1"),
    ("Cost", "/cost"),
    ("Export", "/export"),
]


def _topbar(active: str) -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.div("R", class_name="logo"),
            rx.el.div(
                rx.el.div("RedFlag", class_name="brand-name"),
                rx.el.span("M&A cybersecurity intelligence", class_name="brand-sub"),
            ),
            class_name="brand",
        ),
        rx.el.div(
            *[
                rx.link(
                    label,
                    href=href,
                    class_name="nav-tab active" if label == active else "nav-tab",
                )
                for label, href in NAV
            ],
            class_name="nav",
        ),
        class_name="topbar",
    )


def _scanbar() -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.label("Target host or IP"),
            rx.el.input(
                value=RedFlagState.target,
                on_change=RedFlagState.set_target,
                placeholder="example.com",
            ),
            class_name="field",
        ),
        rx.cond(
            RedFlagState.is_demo,
            rx.el.span("Sample data", class_name="sample-pill"),
        ),
        rx.el.button(
            rx.cond(RedFlagState.scanning, "Scanning…", "Run scan"),
            on_click=RedFlagState.run_scan,
            disabled=RedFlagState.scanning,
            class_name="btn",
        ),
        rx.el.button("Load sample", on_click=RedFlagState.load_sample, class_name="btn ghost"),
        class_name="scanbar",
    )


def _colophon() -> rx.Component:
    return rx.el.div(
        rx.el.span("RedFlag  ·  Reflex UI  ·  engine: redflag-core / 0.6.0"),
        rx.el.span("Confidential"),
        class_name="colophon",
    )


def shell(active: str, *children: rx.Component) -> rx.Component:
    """Wrap page content in the standard RedFlag chrome."""
    return rx.el.div(
        _topbar(active),
        _scanbar(),
        rx.cond(
            RedFlagState.error != "",
            rx.el.div(RedFlagState.error, class_name="placeholder"),
        ),
        *children,
        _colophon(),
        class_name="app",
    )
