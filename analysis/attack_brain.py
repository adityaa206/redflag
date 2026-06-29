"""
attack_brain.py — a free, offline "attacker-brain" for RedFlag.

This is NOT an LLM. It is a knowledge-based expert engine: it encodes how real
attackers operate (the MITRE ATT&CK kill-chain) and reasons over the actual scan
findings to build a chained attack path — Internet entry → exploitation →
lateral movement → impact — and renders it as a radial mind-map.

No API key, no network calls, no cost. The MITRE technique knowledge below is the
"ideas" source; every technique links to its public attack.mitre.org page so the
analyst can dig deeper. KEV / exploit status comes from the findings themselves
(already enriched by the scanners), so live attacker intel rides along for free.

Pure functions only — no Reflex imports — so any UI can consume it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from math import cos, sin, pi
from typing import Any


# ── helpers ───────────────────────────────────────────────────────────────────
def _v(x) -> str:
    return str(getattr(x, "value", x))


def _esc(s: Any) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


_TIER_HEX = {
    "deal_killer": "#b13b2a", "critical": "#a16207",
    "moderate": "#0e4f6b", "manageable": "#0f5e3a", "unscored": "#6b7785",
}
_TIER_ORDER = ["deal_killer", "critical", "moderate", "manageable", "unscored"]
_MITRE = "https://attack.mitre.org/techniques/"


def _worst(tiers: list[str]) -> str:
    for t in _TIER_ORDER:
        if t in tiers:
            return t
    return "unscored"


# ── MITRE ATT&CK knowledge base: finding → likely attacker techniques ─────────
@dataclass
class Technique:
    tactic: str
    tid: str
    name: str
    how: str

    @property
    def ref(self) -> str:
        return _MITRE + self.tid.replace(".", "/") + "/"


def _techniques_for(f) -> list[Technique]:
    """Map a single finding to the attacker techniques it most likely enables."""
    svc = (f.service or "").lower()
    port = f.port or 0
    raw = f.raw_data or {}
    src = str(raw.get("source", "")).lower()
    has_cve = bool(f.cve_id)
    out: list[Technique] = []

    web = any(k in svc for k in ("http", "ssl", "https")) or port in (80, 443, 8080, 8443, 8000, 8888)
    if web:
        out.append(Technique("Initial Access", "T1190", "Exploit Public-Facing Application",
                             "Attack the exposed web service directly over the internet."))
        if src == "zap" or "sql" in (f.title or "").lower() or "xss" in (f.title or "").lower():
            out.append(Technique("Initial Access", "T1659", "Content Injection / Web App Abuse",
                                 "Abuse the web-layer flaw (injection / XSS / misconfig) ZAP surfaced."))
    if "ssh" in svc or port == 22:
        out.append(Technique("Initial Access", "T1110", "Brute Force",
                             "Spray or brute-force SSH credentials on the exposed service."))
        out.append(Technique("Initial Access", "T1133", "External Remote Services",
                             "Log in over SSH with valid or stolen credentials."))
    if "rdp" in svc or port == 3389:
        out.append(Technique("Initial Access", "T1133", "External Remote Services",
                             "Reach the internet-exposed RDP endpoint."))
        out.append(Technique("Initial Access", "T1110", "Brute Force",
                             "Brute-force / password-spray RDP logins."))
    if "smb" in svc or port in (139, 445):
        out.append(Technique("Lateral Movement", "T1210", "Exploitation of Remote Services",
                             "Exploit the SMB service (e.g. EternalBlue-class flaws) to move laterally."))
    if "ftp" in svc or "telnet" in svc or port in (21, 23):
        out.append(Technique("Initial Access", "T1078", "Valid Accounts",
                             "Capture cleartext credentials on the unencrypted protocol and reuse them."))
    if port in (3306, 5432, 1433, 27017, 6379, 9200) or any(k in svc for k in ("mysql", "postgres", "mongo", "redis", "mssql", "elastic")):
        out.append(Technique("Collection", "T1190", "Exploit Public-Facing Application",
                             "Reach the internet-exposed database / data store directly."))
    if has_cve and not any(t.tid == "T1190" for t in out):
        out.append(Technique("Initial Access", "T1190", "Exploit Public-Facing Application",
                             f"Weaponise {f.cve_id} against the exposed service."))
    if not out:
        out.append(Technique("Initial Access", "T1595", "Active Scanning",
                             "Enumerate the exposed service for an exploitable weakness."))
    return out


def _exploit_note(f) -> str:
    es = _v(f.exploit_status)
    if es == "active_exploitation":
        return "actively exploited in the wild (CISA KEV) — a weaponised exploit is available"
    if es == "public_exploit":
        return "a public proof-of-concept exploit exists"
    if f.cvss_score and f.cvss_score >= 9.0:
        return "critical severity — likely exploitable"
    if f.cve_id:
        return "carries a known CVE"
    return "exposed service worth probing"


# ── output containers ─────────────────────────────────────────────────────────
@dataclass
class AttackStep:
    order: int
    stage: str
    title: str
    detail: str
    technique: str
    tid: str
    ref: str
    tier: str


@dataclass
class MindChild:
    label: str
    sub: str
    tier: str


@dataclass
class MindStage:
    name: str
    accent: str          # hex
    children: list[MindChild] = field(default_factory=list)


@dataclass
class AttackPlan:
    summary: str
    steps: list[AttackStep] = field(default_factory=list)
    stages: list[MindStage] = field(default_factory=list)
    n_entry: int = 0
    n_exploit: int = 0
    n_lateral: int = 0
    has_paths: bool = False


# ── the brain: chain findings into an attack plan ─────────────────────────────
def analyze_attack_paths(findings: list, target: str = "") -> AttackPlan:
    findings = [f for f in (findings or [])]
    if not findings:
        return AttackPlan(summary="No findings to analyse.")

    inet = [f for f in findings if _v(f.exposure) == "internet_facing"]
    internal = [f for f in findings if _v(f.exposure) in ("internal", "partner")]
    # exploitable entry candidates = internet-facing, ranked by risk
    entry = sorted(inet, key=lambda f: f.risk_score, reverse=True)
    crown = [f for f in findings if _v(f.data_sensitivity) in ("crown_jewel", "regulated")]

    inet_hosts = sorted({f.host for f in inet if f.host})
    internal_hosts = sorted({f.host for f in internal if f.host} - set(inet_hosts))

    # ── mind-map stages (only populated ones appear) ─────────────────────────
    stages: list[MindStage] = []

    # Stage 1 — Entry points (internet-facing hosts)
    if inet_hosts:
        st = MindStage("Entry points", "#0e4f6b")
        by_host: dict[str, list] = {}
        for f in inet:
            by_host.setdefault(f.host or "?", []).append(f)
        for host in sorted(by_host, key=lambda h: max(x.risk_score for x in by_host[h]), reverse=True)[:4]:
            fs = by_host[host]
            worst = _worst([_v(x.deal_tier) for x in fs])
            st.children.append(MindChild(host, f"{len(fs)} exposed", worst))
        stages.append(st)

    # Stage 2 — Exploitation (the weaponizable services / CVEs), deduplicated
    weapon = [f for f in entry if _v(f.exploit_status) in ("active_exploitation", "public_exploit")
              or (f.cvss_score or 0) >= 7.0 or f.cve_id]
    weapon = weapon if weapon else entry
    multi = len(inet_hosts) > 1
    if weapon:
        st = MindStage("Exploitation", "#b13b2a")
        seen: set[str] = set()
        for f in weapon:
            base = (f":{f.port}/{f.service}" if f.service else f":{f.port}") if f.port else (f.service or "service")
            label = f"{f.host} {base}" if (multi and f.host) else base
            if label in seen:
                continue
            seen.add(label)
            sub = f.cve_id or _techniques_for(f)[0].tid
            st.children.append(MindChild(label, sub, _v(f.deal_tier)))
            if len(st.children) >= 4:
                break
        stages.append(st)

    # Stage 3 — Lateral movement (internal hosts reachable post-foothold)
    if internal_hosts and inet_hosts:
        st = MindStage("Lateral movement", "#a16207")
        for host in internal_hosts[:4]:
            hf = [f for f in internal if f.host == host]
            worst = _worst([_v(x.deal_tier) for x in hf]) if hf else "unscored"
            st.children.append(MindChild(host, "pivot target", worst))
        stages.append(st)

    # Stage 4 — Impact (crown jewels, else the worst reachable assets), deduped by host
    impact_src = crown or sorted(findings, key=lambda f: f.risk_score, reverse=True)
    if impact_src:
        st = MindStage("Impact", "#7a1f12")
        seen_i: set[str] = set()
        for f in impact_src:
            label = f.host or (f.service or "asset")
            if label in seen_i:
                continue
            seen_i.add(label)
            sens = _v(f.data_sensitivity)
            sub = "crown jewel" if sens == "crown_jewel" else "regulated" if sens == "regulated" else "data target"
            st.children.append(MindChild(label, sub, _v(f.deal_tier)))
            if len(st.children) >= 4:
                break
        stages.append(st)

    # ── narrative steps for the single worst path ────────────────────────────
    steps: list[AttackStep] = []
    order = 1
    if entry:
        f0 = entry[0]
        t0 = _techniques_for(f0)[0]
        loc = (f"{f0.host}:{f0.port}" if f0.host and f0.port else (f0.host or f0.service or "the exposed service"))
        steps.append(AttackStep(
            order, "Initial access", f"Breach {loc}",
            f"{t0.how} The {f0.service or 'service'} is {_exploit_note(f0)}"
            + (f" ({f0.cve_id})." if f0.cve_id else "."),
            t0.name, t0.tid, t0.ref, _v(f0.deal_tier)))
        order += 1
        steps.append(AttackStep(
            order, "Execution & foothold", f"Establish a foothold on {f0.host or 'the host'}",
            "Run code / open a session on the compromised host and harvest local credentials "
            "to widen access.", "Valid Accounts", "T1078", _MITRE + "T1078/", _v(f0.deal_tier)))
        order += 1
    if internal_hosts and inet_hosts:
        tgts = ", ".join(internal_hosts[:3]) + ("…" if len(internal_hosts) > 3 else "")
        steps.append(AttackStep(
            order, "Lateral movement", f"Pivot to internal hosts ({tgts})",
            "Use the foothold and stolen credentials to reach internal-only systems over remote "
            "services — these are unreachable from the internet but trivial to hit from inside.",
            "Remote Services", "T1021", _MITRE + "T1021/", "critical"))
        order += 1
    if impact_src:
        f9 = impact_src[0]
        sens = _v(f9.data_sensitivity)
        what = ("crown-jewel data" if sens == "crown_jewel" else
                "regulated data" if sens == "regulated" else "high-value systems / data")
        steps.append(AttackStep(
            order, "Impact", f"Reach {what} on {f9.host or 'the target'}",
            "Collect and exfiltrate the data, or disrupt the asset — the objective an acquirer "
            "must price into the deal.", "Exfiltration / Impact", "T1567", _MITRE + "T1567/",
            _v(f9.deal_tier)))

    # ── summary ──────────────────────────────────────────────────────────────
    if inet_hosts:
        nh = len(inet_hosts)
        nw = len(weapon)
        summary = (f"{nh} internet-facing host" + ("" if nh == 1 else "s")
                   + (" gives" if nh == 1 else " give") + " an external attacker a way in; "
                   + f"{nw} weaponizable finding" + ("" if nw == 1 else "s") + " on the perimeter"
                   + (f", then {len(internal_hosts)} internal host"
                      + ("" if len(internal_hosts) == 1 else "s") + " reachable by pivoting"
                      if internal_hosts else "")
                   + ".")
    else:
        summary = ("No internet-facing exposure detected — an attacker needs insider access, "
                   "phishing, or supply-chain footing before any of these findings are reachable.")

    return AttackPlan(
        summary=summary, steps=steps, stages=stages,
        n_entry=len(inet_hosts), n_exploit=len(weapon), n_lateral=len(internal_hosts),
        has_paths=bool(stages),
    )


# ── radial mind-map → SVG string (rendered raw via rx.html) ──────────────────
def _node(cx: float, cy: float, w: float, h: float, fill: str, stroke: str,
          line1: str, line2: str, text_fill: str, fs1: float, fw: int, sub_fill: str) -> str:
    x, y = cx - w / 2, cy - h / 2
    rx = h / 2 if w <= h * 1.4 else 12
    if line2:
        t1y, t2y = cy - 4, cy + 13
        text = (f'<text x="{cx:.0f}" y="{t1y:.0f}" text-anchor="middle" '
                f'font-size="{fs1}" font-weight="{fw}" fill="{text_fill}" '
                f'font-family="Geist, sans-serif">{_esc(line1)}</text>'
                f'<text x="{cx:.0f}" y="{t2y:.0f}" text-anchor="middle" font-size="10.5" '
                f'fill="{sub_fill}" font-family="Geist Mono, monospace">{_esc(line2)}</text>')
    else:
        text = (f'<text x="{cx:.0f}" y="{cy + 4:.0f}" text-anchor="middle" '
                f'font-size="{fs1}" font-weight="{fw}" fill="{text_fill}" '
                f'font-family="Geist, sans-serif">{_esc(line1)}</text>')
    return (f'<rect x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" height="{h:.0f}" rx="{rx:.0f}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>' + text)


def _truncate(s: str, n: int) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def _edge(x1: float, y1: float, x2: float, y2: float, color: str, width: float) -> str:
    # gentle quadratic curve: pull the control point toward the canvas centre
    mx, my = (x1 + x2) / 2, (y1 + y2) / 2
    cxp, cyp = mx + (mx - x1) * 0.12, my + (my - y1) * 0.12
    return (f'<path d="M{x1:.0f},{y1:.0f} Q{cxp:.0f},{cyp:.0f} {x2:.0f},{y2:.0f}" '
            f'fill="none" stroke="{color}" stroke-width="{width}" stroke-linecap="round" '
            f'opacity="0.45"/>')


def build_mindmap_svg(plan: AttackPlan, target: str = "") -> str:
    W, H = 1000, 820
    CX, CY = 500, 400
    R1, R2 = 205, 322
    if not plan.stages:
        return (f'<svg viewBox="0 0 {W} 240" xmlns="http://www.w3.org/2000/svg" '
                f'style="width:100%;height:auto">'
                f'<text x="{CX}" y="120" text-anchor="middle" font-size="16" fill="#6b7785" '
                f'font-family="Geist, sans-serif">No external attack path — no reachable exposure.</text></svg>')

    edges: list[str] = []
    nodes: list[str] = []
    n = len(plan.stages)
    for i, stage in enumerate(plan.stages):
        theta = -pi / 2 + (2 * pi * i / n)
        sx, sy = CX + R1 * cos(theta), CY + R1 * sin(theta)
        edges.append(_edge(CX, CY, sx, sy, stage.accent, 3.2))
        # children fan around the stage angle, with a radial stagger so 132px-wide
        # nodes never collide even when the branch points straight up or down
        k = len(stage.children)
        for j, ch in enumerate(stage.children):
            spread = (j - (k - 1) / 2) * (20 * pi / 180)
            ct = theta + spread
            r = R2 + (j % 2) * 58          # alternate near / far ring
            chx, chy = CX + r * cos(ct), CY + r * sin(ct)
            col = _TIER_HEX.get(ch.tier, "#6b7785")
            edges.append(_edge(sx, sy, chx, chy, col, 1.8))
            nodes.append(_node(chx, chy, 132, 44, "#ffffff", col,
                               _truncate(ch.label, 16), _truncate(ch.sub, 15),
                               "#0f1419", 12, 600, "#6b7785"))
        nodes.append(_node(sx, sy, 156, 50, stage.accent, stage.accent,
                           stage.name, "", "#ffffff", 14, 700, "#dfeae6"))

    centre_label = _truncate(target or "Target", 22)
    centre = _node(CX, CY, 188, 78, "#0f5e3a", "#0f5e3a",
                   centre_label, "ATTACK SURFACE", "#ffffff", 17, 700, "#bfe0cf")

    return (f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" '
            f'style="width:100%;height:auto;max-height:680px">'
            + "".join(edges) + "".join(nodes) + centre + "</svg>")
