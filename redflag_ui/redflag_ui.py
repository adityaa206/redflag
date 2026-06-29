"""RedFlag — Reflex UI (Executive Editorial / emerald).

Presentation layer only. All scoring, sequencing, scanning, and narrative logic
is imported unchanged from the existing analysis/, narrative/, scanners/ engines
via redflag_ui.state.RedFlagState.
"""
import reflex as rx

from redflag_ui.state import RedFlagState
from redflag_ui.pages.overview import overview
from redflag_ui.pages.findings import findings
from redflag_ui.pages.day1 import day1
from redflag_ui.pages.attack import attack
from redflag_ui.pages.maturity import maturity
from redflag_ui.pages.cost import cost
from redflag_ui.pages.export import export
from redflag_ui.pages.legal import privacy, contact

app = rx.App(
    stylesheets=[
        "https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700"
        "&family=Geist+Mono:wght@400;500;600&display=swap",
        "/redflag.css",
    ],
    theme=rx.theme(appearance="light", has_background=False, accent_color="green", radius="large"),
)

_PAGES = [
    (overview, "/", "RedFlag — Overview"),
    (findings, "/findings", "RedFlag — Findings"),
    (attack, "/attack", "RedFlag — Attack path"),
    (maturity, "/maturity", "RedFlag — Maturity"),
    (day1, "/day1", "RedFlag — Day 1 plan"),
    (cost, "/cost", "RedFlag — Cost"),
    (export, "/export", "RedFlag — Export"),
    (privacy, "/privacy", "RedFlag — Privacy policy"),
    (contact, "/contact", "RedFlag — Contact us"),
]

for _fn, _route, _title in _PAGES:
    app.add_page(_fn, route=_route, title=_title, on_load=RedFlagState.ensure_loaded)
