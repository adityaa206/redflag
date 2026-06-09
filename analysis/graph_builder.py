from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from analysis.schema import Finding, ExposureLevel, DealTier


# ── Colour palette (matches Design System v4) ─────────────────────────────────
_TIER_COLORS: dict[str, str] = {
    "deal_killer": "#e6394a",
    "critical":    "#f97316",
    "moderate":    "#f59e0b",
    "manageable":  "#10b981",
    "unscored":    "#3a5070",
}
_INTERNET_COLOR = "#3d7fff"
_EDGE_DEFAULT   = "#1a2640"


def _tier_val(finding: Finding) -> str:
    return str(getattr(finding.deal_tier, "value", finding.deal_tier))


def _exposure_val(finding: Finding) -> str:
    return str(getattr(finding.exposure, "value", finding.exposure))


def _worst_tier(tiers: list[str]) -> str:
    order = ["deal_killer", "critical", "moderate", "manageable", "unscored"]
    for t in order:
        if t in tiers:
            return t
    return "unscored"


# ── Graph data containers ─────────────────────────────────────────────────────

@dataclass
class GraphNode:
    id: str
    label: str
    title: str          # tooltip
    color: str
    size: int
    shape: str = "dot"
    font_color: str = "#c8daf5"


@dataclass
class GraphEdge:
    source: str
    target: str
    color: str
    width: float = 1.5
    label: str = ""


@dataclass
class AttackGraph:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)


# ── Builder ───────────────────────────────────────────────────────────────────

def build_attack_graph(findings: list[Finding]) -> AttackGraph:
    """
    Constructs a layered attack-path graph from a list of triaged findings.

    Layers:
      INTERNET (root) → HOST → SERVICE (port/name) → CVE
    Only internet-facing hosts get an edge from INTERNET.
    Internal/partner hosts are still shown but not connected to INTERNET.
    """
    graph = AttackGraph()
    added_node_ids: set[str] = set()

    def _add_node(node: GraphNode) -> None:
        if node.id not in added_node_ids:
            graph.nodes.append(node)
            added_node_ids.add(node.id)

    def _add_edge(edge: GraphEdge) -> None:
        graph.edges.append(edge)

    # ── Root: INTERNET node ───────────────────────────────────────────────────
    internet_id = "INTERNET"
    _add_node(GraphNode(
        id=internet_id,
        label="INTERNET",
        title="External attacker entry point",
        color=_INTERNET_COLOR,
        size=28,
        shape="diamond",
        font_color="#6fa3ff",
    ))

    # ── Collect per-host and per-service metadata ─────────────────────────────
    # host_id → worst tier across all findings for that host
    host_tiers: dict[str, list[str]] = {}
    # service_id → worst tier
    svc_tiers: dict[str, list[str]] = {}
    # host_id → is internet-facing?
    host_internet: dict[str, bool] = {}

    for f in findings:
        host = f.host or "unknown"
        host_id = f"HOST:{host}"
        port = f.port
        svc  = f.service or "unknown"
        svc_id = f"SVC:{host}:{port}:{svc}"
        tier = _tier_val(f)
        exposure = _exposure_val(f)

        host_tiers.setdefault(host_id, []).append(tier)
        svc_tiers.setdefault(svc_id, []).append(tier)

        if exposure == ExposureLevel.INTERNET_FACING or exposure == "internet_facing":
            host_internet[host_id] = True
        else:
            host_internet.setdefault(host_id, False)

    # ── Create HOST nodes ─────────────────────────────────────────────────────
    for host_id, tiers in host_tiers.items():
        host_label = host_id.replace("HOST:", "")
        worst = _worst_tier(tiers)
        color = _TIER_COLORS.get(worst, _EDGE_DEFAULT)
        is_inet = host_internet.get(host_id, False)
        inet_str = "Internet-facing" if is_inet else "Internal / Partner"
        _add_node(GraphNode(
            id=host_id,
            label=host_label,
            title=(
                f"<b>{host_label}</b><br>"
                f"Exposure: {inet_str}<br>"
                f"Worst tier: {worst.replace('_', ' ').title()}"
            ),
            color=color,
            size=22,
            shape="dot",
        ))
        if is_inet:
            _add_edge(GraphEdge(
                source=internet_id,
                target=host_id,
                color=color,
                width=2.0,
            ))

    # ── Create SERVICE nodes and CVE nodes ────────────────────────────────────
    for f in findings:
        host    = f.host or "unknown"
        host_id = f"HOST:{host}"
        port    = f.port
        svc     = f.service or "unknown"
        svc_id  = f"SVC:{host}:{port}:{svc}"
        tier    = _tier_val(f)
        color   = _TIER_COLORS.get(tier, _EDGE_DEFAULT)

        port_label = f":{port}" if port else ""
        svc_label  = f"{port_label}/{svc}" if svc != "unknown" else port_label or svc

        worst_svc = _worst_tier(svc_tiers.get(svc_id, [tier]))
        svc_color = _TIER_COLORS.get(worst_svc, _EDGE_DEFAULT)

        exposure_str = _exposure_val(f).replace("_", " ").title()
        _add_node(GraphNode(
            id=svc_id,
            label=svc_label,
            title=(
                f"<b>{svc_label}</b><br>"
                f"Host: {host}<br>"
                f"Service: {svc}  Port: {port}<br>"
                f"Exposure: {exposure_str}<br>"
                f"Worst tier: {worst_svc.replace('_', ' ').title()}"
            ),
            color=svc_color,
            size=16,
            shape="dot",
        ))

        # HOST → SERVICE (deduplicated by node id — edge added per unique svc_id)
        edge_key = f"{host_id}→{svc_id}"
        if not any(e.source == host_id and e.target == svc_id for e in graph.edges):
            _add_edge(GraphEdge(
                source=host_id,
                target=svc_id,
                color=svc_color,
                width=1.5,
            ))

        # CVE node (one per unique CVE ID on this service)
        if f.cve_id:
            cve_id_node = f"CVE:{f.cve_id}"
            _add_node(GraphNode(
                id=cve_id_node,
                label=f.cve_id,
                title=(
                    f"<b>{f.cve_id}</b><br>"
                    f"{f.title[:70]}<br>"
                    f"CVSS: {f.cvss_score:.1f}  Risk score: {f.risk_score:.0f}<br>"
                    f"Tier: {tier.replace('_', ' ').title()}"
                ),
                color=color,
                size=max(10, int(f.risk_score / 8)),
                shape="dot",
            ))
            if not any(e.source == svc_id and e.target == cve_id_node for e in graph.edges):
                _add_edge(GraphEdge(
                    source=svc_id,
                    target=cve_id_node,
                    color=color,
                    width=max(1.0, f.risk_score / 40),
                    label=f"{f.risk_score:.0f}",
                ))

    return graph
