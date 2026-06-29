"""App shell — top bar, navigation, scan + upload controls, page container."""
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

XML_ACCEPT = {"text/xml": [".xml"], "application/xml": [".xml"]}
# (kind, upload_id, title, sub, accept)
UPLOAD_SLOTS = [
    ("shodan", "up_shodan", "Shodan JSON", "Exposure intel · 0 credits",
     {"application/json": [".json"]}),
    ("openvas", "up_openvas", "OpenVAS XML", "Verified CVEs", XML_ACCEPT),
    ("zap", "up_zap", "OWASP ZAP XML", "Web-app layer", XML_ACCEPT),
    ("asset", "up_asset", "Asset inventory", "Data sensitivity · Excel",
     {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [".xlsx"],
      "application/vnd.ms-excel": [".xls"]}),
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
        rx.el.div(
            rx.el.button(
                rx.cond(RedFlagState.scanning, "Scanning…", "Run scan"),
                on_click=RedFlagState.run_scan,
                disabled=RedFlagState.scanning,
                class_name=rx.cond(RedFlagState.scanning, "btn scanning", "btn"),
            ),
            rx.el.label(
                rx.checkbox(
                    checked=RedFlagState.fast_mode,
                    on_change=RedFlagState.toggle_fast_mode,
                ),
                rx.el.span("Fast scan mode"),
                rx.el.span("top 200 ports · ~2× faster", class_name="fast-hint"),
                class_name="fast-toggle",
            ),
            class_name="scan-actions",
        ),
        class_name="scanbar",
    )


UPLOAD_HANDLERS = {
    "shodan": RedFlagState.upload_shodan,
    "openvas": RedFlagState.upload_openvas,
    "zap": RedFlagState.upload_zap,
    "asset": RedFlagState.upload_asset,
}
UPLOAD_LABELS = {
    "shodan": RedFlagState.up_shodan_label,
    "openvas": RedFlagState.up_openvas_label,
    "zap": RedFlagState.up_zap_label,
    "asset": RedFlagState.up_asset_label,
}
CLEAR_HANDLERS = {
    "shodan": RedFlagState.clear_shodan,
    "openvas": RedFlagState.clear_openvas,
    "zap": RedFlagState.clear_zap,
    "asset": RedFlagState.clear_asset,
}


def _upload_slot(kind: str, uid: str, title: str, sub: str, accept: dict) -> rx.Component:
    label = UPLOAD_LABELS[kind]
    return rx.el.div(
        rx.upload(
            rx.el.div(
                rx.el.span(title, class_name="us-title"),
                rx.el.span(sub, class_name="us-sub"),
                class_name="us-inner",
            ),
            id=uid,
            multiple=False,
            accept=accept,
            on_drop=UPLOAD_HANDLERS[kind](rx.upload_files(upload_id=uid)),
            class_name="up-slot",
            border="0",
            padding="0",
        ),
        rx.cond(
            label != "",
            rx.el.div(
                rx.el.span("✓", class_name="us-chip-ico"),
                rx.el.span(label, class_name="us-chip-name"),
                rx.el.button(
                    "✕",
                    on_click=CLEAR_HANDLERS[kind],
                    type="button",
                    class_name="us-chip-x",
                ),
                class_name="us-chip",
            ),
        ),
        class_name=rx.cond(label != "", "up-slot-wrap staged", "up-slot-wrap"),
    )


def _uploadbar() -> rx.Component:
    return rx.el.div(
        rx.el.div("Intelligence uploads", class_name="up-head"),
        rx.el.div(
            *[_upload_slot(*slot) for slot in UPLOAD_SLOTS],
            class_name="up-slots",
        ),
        rx.el.div(
            "Stage files here, then Run scan — uploads are fused with the live scan into one report.",
            class_name="up-foot",
        ),
        class_name="uploadbar",
    )


def _banner() -> rx.Component:
    return rx.fragment(
        rx.cond(
            RedFlagState.error != "",
            rx.el.div(
                rx.el.span(RedFlagState.error),
                rx.el.button("✕", on_click=RedFlagState.clear_notice, class_name="banner-x"),
                class_name="banner error",
            ),
        ),
        rx.cond(
            (RedFlagState.notice != "") & (RedFlagState.error == ""),
            rx.el.div(
                rx.el.span(RedFlagState.notice),
                rx.el.button("✕", on_click=RedFlagState.clear_notice, class_name="banner-x"),
                class_name="banner ok",
            ),
        ),
    )


def _colophon() -> rx.Component:
    return rx.el.div(
        rx.el.span("RedFlag  ·  Reflex UI  ·  engine: redflag-core / 0.6.0", class_name="colo-meta"),
        rx.el.div(
            rx.link("Privacy policy", href="/privacy", class_name="colo-link"),
            rx.el.span("·", class_name="colo-dot"),
            rx.link("Contact us", href="/contact", class_name="colo-link"),
            rx.el.span("·", class_name="colo-dot"),
            rx.el.span("Confidential", class_name="colo-conf"),
            class_name="colo-links",
        ),
        class_name="colophon",
    )


def shell(active: str, *children: rx.Component, bare: bool = False) -> rx.Component:
    """Wrap page content in the standard RedFlag chrome.

    bare=True drops the scan/upload/banner controls (for static pages like the
    privacy policy and contact page) while keeping the top bar + footer.
    """
    chrome = [_topbar(active)]
    if not bare:
        chrome += [_scanbar(), _uploadbar(), _banner()]
    chrome.append(rx.el.div(*children, class_name="page-body"))
    chrome.append(_colophon())
    return rx.el.div(*chrome, class_name="app")
