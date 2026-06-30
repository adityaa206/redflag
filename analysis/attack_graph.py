"""
attack_graph.py — quantitative attack-graph analytics over the findings.

Where attack_brain.py *narrates* how an attacker moves, this module *measures*
the estate as a directed graph and answers questions the narrative can't:

  • Chokepoints  — which host/service, if fixed, severs the most attack paths
                   (the highest-leverage remediation), via removal-impact +
                   betweenness centrality.
  • Blast radius — how many assets are reachable from the public internet.
  • Crown-jewel paths — the shortest route from the internet to sensitive data.

Graph model (directed):  INTERNET → internet-facing host → host:port service;
plus pivot edges (internet-facing host → internal host) to model post-foothold
lateral movement. Crown-jewel / regulated assets are goal nodes.

networkx is the only dependency. Pure analysis — no Reflex.
"""
from __future__ import annotations

from dataclasses import dataclass, field

try:
    import networkx as nx
    _HAS_NX = True
except Exception:                      # networkx missing → degrade to empty report
    _HAS_NX = False


_TIER_ORDER = ["deal_killer", "critical", "moderate", "manageable", "unscored"]


def _v(x) -> str:
    return str(getattr(x, "value", x))


def _worst(tiers: list[str]) -> str:
    for t in _TIER_ORDER:
        if t in tiers:
            return t
    return "unscored"


# ── output containers ─────────────────────────────────────────────────────────
@dataclass
class Chokepoint:
    label: str
    kind: str          # "host" | "service"
    isolates: int      # assets cut off from the internet if this node is removed
    centrality: float  # betweenness centrality (0–1)
    tier: str


@dataclass
class CrownPath:
    target_label: str
    sensitivity: str   # "crown_jewel" | "regulated"
    hops: list[str]
    length: int


@dataclass
class GraphReport:
    has_graph: bool = False
    n_nodes: int = 0
    n_edges: int = 0
    blast_radius: int = 0
    internet_hosts: int = 0
    chokepoints: list[Chokepoint] = field(default_factory=list)
    crown_paths: list[CrownPath] = field(default_factory=list)
    summary: str = ""


def analyze_graph(findings: list, target: str = "") -> GraphReport:
    if not _HAS_NX or not findings:
        return GraphReport(summary="" if findings else "No findings to model.")

    G = nx.DiGraph()
    G.add_node("INTERNET", kind="internet", label="INTERNET")

    by_host: dict[str, list] = {}
    for f in findings:
        by_host.setdefault(f.host or "unknown", []).append(f)

    internet_hosts: list[str] = []
    internal_hosts: list[str] = []
    goals: list[tuple[str, str, str]] = []   # (node_id, label, sensitivity)

    for host, fs in by_host.items():
        host_id = f"host:{host}"
        is_inet = any(_v(x.exposure) == "internet_facing" for x in fs)
        tier = _worst([_v(x.deal_tier) for x in fs])
        G.add_node(host_id, kind="host", label=host, tier=tier)
        if is_inet:
            internet_hosts.append(host_id)
            G.add_edge("INTERNET", host_id, kind="entry")
        else:
            internal_hosts.append(host_id)

        for x in fs:
            if x.port:
                svc_id = f"svc:{host}:{x.port}"
                svc_label = f"{host}:{x.port}" + (f"/{x.service}" if x.service else "")
                if not G.has_node(svc_id):
                    G.add_node(svc_id, kind="service", label=svc_label, tier=_v(x.deal_tier))
                    G.add_edge(host_id, svc_id, kind="service")
            sens = _v(x.data_sensitivity)
            if sens in ("crown_jewel", "regulated"):
                gid = f"svc:{host}:{x.port}" if x.port else host_id
                glabel = G.nodes.get(gid, {}).get("label", host)
                goals.append((gid, glabel, sens))

    # lateral movement: any internet foothold can pivot to any internal host
    for ih in internet_hosts:
        for nh in internal_hosts:
            G.add_edge(ih, nh, kind="pivot")

    reachable = nx.descendants(G, "INTERNET") if G.has_node("INTERNET") else set()
    blast_radius = len(reachable)

    # chokepoints — removal impact (how many assets get cut off) + centrality
    try:
        centrality = nx.betweenness_centrality(G)
    except Exception:
        centrality = {}
    chokepoints: list[Chokepoint] = []
    candidates = [n for n in reachable if G.nodes[n].get("kind") in ("host", "service")]
    for v in candidates:
        H = G.copy()
        H.remove_node(v)
        after = nx.descendants(H, "INTERNET") if H.has_node("INTERNET") else set()
        isolates = len((reachable - after) - {v})
        if isolates <= 0 and centrality.get(v, 0) <= 0:
            continue
        chokepoints.append(Chokepoint(
            label=G.nodes[v].get("label", v),
            kind=G.nodes[v].get("kind", "host"),
            isolates=isolates,
            centrality=round(centrality.get(v, 0.0), 3),
            tier=G.nodes[v].get("tier", "unscored"),
        ))
    chokepoints.sort(key=lambda c: (c.isolates, c.centrality), reverse=True)
    chokepoints = chokepoints[:6]

    # crown-jewel paths — shortest internet→sensitive-asset route
    crown_paths: list[CrownPath] = []
    seen_goal: set[str] = set()
    # crown jewels before regulated, dedup by node
    for gid, glabel, sens in sorted(goals, key=lambda g: 0 if g[2] == "crown_jewel" else 1):
        if gid in seen_goal or not G.has_node(gid):
            continue
        seen_goal.add(gid)
        try:
            if nx.has_path(G, "INTERNET", gid):
                path = nx.shortest_path(G, "INTERNET", gid)
                hops = [G.nodes[n].get("label", n) for n in path]
                crown_paths.append(CrownPath(glabel, sens, hops, len(path) - 1))
        except Exception:
            continue
    crown_paths.sort(key=lambda p: (0 if p.sensitivity == "crown_jewel" else 1, p.length))
    crown_paths = crown_paths[:4]

    # summary
    bits = []
    if internet_hosts:
        bits.append(f"{len(internet_hosts)} internet entry point"
                    + ("" if len(internet_hosts) == 1 else "s")
                    + f" expose {blast_radius} reachable asset" + ("" if blast_radius == 1 else "s"))
    else:
        bits.append("No internet-facing entry points — the estate is not reachable externally")
    if chokepoints and chokepoints[0].isolates > 0:
        c = chokepoints[0]
        bits.append(f"fixing {c.label} alone would isolate {c.isolates} asset"
                    + ("" if c.isolates == 1 else "s"))
    if crown_paths:
        bits.append(f"shortest path to sensitive data is {crown_paths[0].length} hop"
                    + ("" if crown_paths[0].length == 1 else "s"))
    summary = "; ".join(bits) + "."

    return GraphReport(
        has_graph=bool(internet_hosts or blast_radius),
        n_nodes=G.number_of_nodes(),
        n_edges=G.number_of_edges(),
        blast_radius=blast_radius,
        internet_hosts=len(internet_hosts),
        chokepoints=chokepoints,
        crown_paths=crown_paths,
        summary=summary,
    )
