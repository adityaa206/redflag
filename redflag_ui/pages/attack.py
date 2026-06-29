"""Attack path — layered kill-chain from the existing graph model."""
from __future__ import annotations

import reflex as rx

from redflag_ui.state import (
    RedFlagState, AttackHostVM, AttackService, AttackStepVM, BrainInsightVM,
)
from redflag_ui.components.shell import shell
from redflag_ui.components.ui import section, empty_state


def _svc(s: AttackService) -> rx.Component:
    return rx.el.div(
        rx.el.div(s.label, class_name="atk-svc-label mono"),
        rx.el.div(
            rx.cond(s.cve != "", rx.el.span(s.cve, class_name="atk-cve mono")),
            rx.el.span(s.tier_label, class_name="atk-tag " + s.tier_class),
            rx.el.span(s.risk, class_name="atk-risk " + s.tier_class),
            class_name="atk-svc-right",
        ),
        class_name="atk-svc",
    )


def _host(h: AttackHostVM) -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.div(h.host, class_name="atk-host-name mono"),
            rx.el.span(h.exposure_label, class_name="atk-exposure " + h.exposure_class),
            class_name="atk-host-head",
        ),
        rx.el.div(h.count_label, class_name="atk-host-count"),
        rx.el.div(rx.foreach(h.services, _svc), class_name="atk-svcs"),
        class_name=rx.cond(h.internet_facing, "atk-host inet", "atk-host"),
    )


def _legend() -> rx.Component:
    def dot(cls, label):
        return rx.el.div(rx.el.span(class_name="atk-dot " + cls), label, class_name="atk-leg-item")
    return rx.el.div(
        dot("dk", "Deal killer"),
        dot("cr", "Critical"),
        dot("mo", "Moderate"),
        dot("ma", "Manageable"),
        class_name="atk-legend",
    )


def _kc_node(step, figure, label, accent) -> rx.Component:
    return rx.el.div(
        rx.el.div(step, class_name="kc-step"),
        rx.el.div(figure, class_name="kc-figure " + accent),
        rx.el.div(label, class_name="kc-label"),
        class_name="atk-kc-node " + accent,
    )


def _kc_arrow() -> rx.Component:
    return rx.el.div(
        rx.el.span("→", class_name="kc-arrow-glyph"),
        class_name="atk-kc-arrow",
    )


def _killchain() -> rx.Component:
    """Left-to-right visual of how an external attacker reaches impact."""
    return rx.el.div(
        _kc_node("Entry point", "WAN", "Public internet", "neutral"),
        _kc_arrow(),
        _kc_node("Exposed surface", RedFlagState.attack_inet_hosts, "internet-facing hosts", "cr"),
        _kc_arrow(),
        _kc_node("Open doors", RedFlagState.attack_entry_services, "exploitable services", "dk"),
        _kc_arrow(),
        _kc_node("Impact", RedFlagState.avg_score, RedFlagState.attack_impact_label,
                 RedFlagState.attack_impact_class),
        class_name="atk-killchain",
    )


def _brain_summary() -> rx.Component:
    return rx.el.div(
        rx.el.div("Attacker-brain", class_name="brain-kicker"),
        rx.el.p(RedFlagState.attack_summary, class_name="brain-summary"),
        rx.el.div(
            "Knowledge base: MITRE ATT&CK · CISA KEV · service-exposure heuristics — reasoned "
            "locally, no external calls.",
            class_name="brain-note",
        ),
        class_name="brain-box",
    )


def _mindmap() -> rx.Component:
    return rx.el.div(
        rx.html(RedFlagState.mindmap_svg),
        class_name="mindmap-wrap",
    )


def _mem_item(b: BrainInsightVM) -> rx.Component:
    return rx.el.div(
        rx.el.div(
            rx.el.span(b.label, class_name="mem-item-label mono"),
            rx.el.span(b.sub, class_name="mem-item-sub"),
            class_name="mem-item-head",
        ),
        rx.cond(
            b.bar_w != "",
            rx.el.div(
                rx.el.div(class_name="mem-bar-fill " + b.kind_class, style={"width": b.bar_w}),
                class_name="mem-bar",
            ),
        ),
        class_name="mem-item",
    )


def _brain_memory() -> rx.Component:
    """What the brain has accumulated across every prior scan — its memory."""
    return rx.el.div(
        rx.el.div(
            rx.el.div("Brain memory", class_name="mem-kicker"),
            rx.el.button(
                "Refresh threat intel",
                on_click=RedFlagState.refresh_threat_intel,
                class_name="mem-refresh",
                type="button",
            ),
            class_name="mem-head",
        ),
        rx.el.div(RedFlagState.brain_stat_line, class_name="mem-stat"),
        rx.el.p(RedFlagState.brain_recall_summary, class_name="mem-recall"),
        rx.el.div(
            rx.el.div(
                rx.el.div("Most-seen attacker techniques", class_name="mem-col-h"),
                rx.el.div(rx.foreach(RedFlagState.brain_known, _mem_item), class_name="mem-list"),
                class_name="mem-col",
            ),
            rx.cond(
                RedFlagState.brain_recall.length() > 0,
                rx.el.div(
                    rx.el.div("Recognised from prior scans", class_name="mem-col-h"),
                    rx.el.div(rx.foreach(RedFlagState.brain_recall, _mem_item), class_name="mem-list"),
                    class_name="mem-col",
                ),
                rx.el.div(
                    rx.el.div("Recognised from prior scans", class_name="mem-col-h"),
                    rx.el.div(
                        "Nothing recognised yet — patterns appear here once a target or CVE "
                        "recurs across scans.",
                        class_name="mem-empty",
                    ),
                    class_name="mem-col",
                ),
            ),
            class_name="mem-grid",
        ),
        rx.el.div(
            rx.el.span("Vault  ", class_name="mem-vault-k"),
            rx.el.span(RedFlagState.brain_vault_path, class_name="mono"),
            rx.el.span("  — open this folder in Obsidian, then Graph View, to see the brain.",
                       class_name="mem-vault-hint"),
            class_name="mem-vault",
        ),
        class_name="brain-mem",
    )


def _step(s: AttackStepVM) -> rx.Component:
    return rx.el.div(
        rx.el.div(s.order, class_name="atk-step-num " + s.tier_class),
        rx.el.div(
            rx.el.div(
                rx.el.span(s.stage, class_name="atk-step-stage"),
                rx.el.a(s.tid, href=s.ref, target="_blank", class_name="atk-step-tid"),
                class_name="atk-step-head",
            ),
            rx.el.div(s.title, class_name="atk-step-title"),
            rx.el.div(s.detail, class_name="atk-step-detail"),
            rx.el.div(rx.el.span("Technique  ", class_name="atk-step-k"), s.technique,
                      class_name="atk-step-tech"),
            class_name="atk-step-body",
        ),
        class_name="atk-step",
    )


def _content() -> rx.Component:
    return rx.fragment(
        section(
            "Attack path",
            "How an attacker would think about this estate",
            "RedFlag's attacker-brain maps every finding to the MITRE ATT&CK techniques it enables, "
            "then chains them: internet entry → exploitation → lateral movement → impact.",
        ),
        _brain_summary(),
        rx.cond(RedFlagState.brain_active, _brain_memory()),
        _mindmap(),
        _legend(),
        section("The attacker's playbook", "Each move, and the technique it maps to", rule=True),
        rx.cond(
            RedFlagState.attack_has_paths,
            rx.el.div(rx.foreach(RedFlagState.attack_steps, _step), class_name="atk-steps"),
            rx.el.div("No external attack path — nothing reachable from the public internet.",
                      class_name="placeholder"),
        ),
        section("Reachability detail", "Internet entry → host → service", rule=True),
        _killchain(),
        rx.el.div(
            rx.el.div(
                rx.el.div("INTERNET", class_name="atk-entry-label"),
                rx.el.div(RedFlagState.attack_internet_label, class_name="atk-entry-sub"),
                class_name="atk-entry",
            ),
            rx.el.div(rx.foreach(RedFlagState.attack_hosts, _host), class_name="atk-hosts"),
            class_name="atk-flow",
        ),
    )


def attack() -> rx.Component:
    return shell(
        "Attack path",
        rx.cond(
            RedFlagState.scanned,
            _content(),
            empty_state(
                "No attack path ",
                "yet.",
                "Run a scan or upload findings to map how an external attacker would chain "
                "exposure into impact across the estate.",
            ),
        ),
    )
