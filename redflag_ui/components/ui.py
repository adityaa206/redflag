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
