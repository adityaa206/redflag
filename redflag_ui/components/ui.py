"""Small presentational helpers shared across pages."""
from __future__ import annotations

import reflex as rx


def section(eyebrow: str, title: str, sub: str | None = None, rule: bool = False) -> rx.Component:
    children = [
        rx.el.div(eyebrow, class_name="section-eyebrow"),
        rx.el.div(title, class_name="section-title"),
    ]
    if sub:
        children.append(rx.el.div(sub, class_name="section-sub"))
    if rule:
        children.append(rx.el.div(class_name="section-rule"))
    return rx.el.div(*children, class_name="section")


def placeholder(text: str) -> rx.Component:
    return rx.el.div(text, class_name="placeholder")


def empty_state(lead: str, grad: str, sub: str) -> rx.Component:
    """Pre-scan welcome / no-data state."""
    return rx.el.div(
        rx.el.div(lead, rx.el.span(grad, class_name="grad"), class_name="es-title"),
        rx.el.div(sub, class_name="es-sub"),
        rx.el.div(
            rx.el.div(rx.el.span("01", class_name="es-n"), "Enter a target above, or upload scan files", class_name="es-step"),
            rx.el.div(rx.el.span("02", class_name="es-n"), "Run the sweep — Nmap · Shodan · DNS · TLS · breach", class_name="es-step"),
            rx.el.div(rx.el.span("03", class_name="es-n"), "Read the verdict, Day-1 plan, cost and export", class_name="es-step"),
            class_name="es-steps",
        ),
        class_name="empty-state",
    )
