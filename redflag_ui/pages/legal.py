"""Static legal / contact pages (linked from the footer)."""
from __future__ import annotations

import reflex as rx

from redflag_ui.components.shell import shell
from redflag_ui.components.ui import section


def _p(*children) -> rx.Component:
    return rx.el.p(*children, class_name="legal-p")


def _privacy_body() -> rx.Component:
    return rx.fragment(
        section(
            "Privacy policy",
            "How RedFlag handles your data",
            "Last updated 25 June 2026. RedFlag is a due-diligence tool; it is built to "
            "keep sensitive assessment data under your control.",
            rule=True,
        ),
        rx.el.div(
            rx.el.h3("What we process", class_name="legal-h"),
            _p(
                "RedFlag processes the scan target you enter and any intelligence files you "
                "upload (Shodan JSON, OpenVAS / OWASP ZAP XML, asset inventories). These are "
                "used solely to produce your risk assessment, Day-1 plan and cost model."
            ),
            rx.el.h3("Where it runs", class_name="legal-h"),
            _p(
                "Scans and parsing run locally in your own environment. Uploaded files are held "
                "in memory for the duration of a scan and written only to a temporary working "
                "directory — never committed to source control or shared externally."
            ),
            rx.el.h3("Third-party lookups", class_name="legal-h"),
            _p(
                "When you run a live scan, RedFlag may query external enrichment services "
                "(e.g. Shodan, Vulners, breach databases) using the target IP/host. Only the "
                "target identifier is sent — never your uploaded files. Provide your own API "
                "keys via the .env file; they are never transmitted to RedFlag's authors."
            ),
            rx.el.h3("Retention", class_name="legal-h"),
            _p(
                "Findings live in your browser session and the local results directory. Clearing "
                "the session or deleting the exported CSV/PDF removes the data. RedFlag keeps no "
                "central copy of your assessments."
            ),
            rx.el.h3("Your control", class_name="legal-h"),
            _p(
                "You decide what to scan, what to upload, and what to export. Remove any staged "
                "file with the ✕ on its chip before running a scan."
            ),
            class_name="legal-body",
        ),
    )


def _contact_body() -> rx.Component:
    return rx.fragment(
        section(
            "Contact us",
            "Talk to the RedFlag team",
            "Questions about a finding, the scoring model, or running RedFlag on an engagement? "
            "Reach out through any of the channels below.",
            rule=True,
        ),
        rx.el.div(
            rx.el.div(
                rx.el.div("Email", class_name="contact-k"),
                rx.el.a("redflag@example.com", href="mailto:redflag@example.com", class_name="contact-v"),
                class_name="contact-row",
            ),
            rx.el.div(
                rx.el.div("Security disclosures", class_name="contact-k"),
                rx.el.a("security@example.com", href="mailto:security@example.com", class_name="contact-v"),
                class_name="contact-row",
            ),
            rx.el.div(
                rx.el.div("Project", class_name="contact-k"),
                rx.el.span("RedFlag — M&A cybersecurity due-diligence", class_name="contact-v"),
                class_name="contact-row",
            ),
            rx.el.div(
                rx.el.div("Response time", class_name="contact-k"),
                rx.el.span("Within 2 business days", class_name="contact-v"),
                class_name="contact-row",
            ),
            class_name="contact-card",
        ),
    )


def privacy() -> rx.Component:
    return shell("", _privacy_body(), bare=True)


def contact() -> rx.Component:
    return shell("", _contact_body(), bare=True)
