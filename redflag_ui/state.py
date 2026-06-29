"""
redflag_ui/state.py — Reflex State for the RedFlag UI.

This is the ONLY new logic layer. It calls the SAME engines the Streamlit app
uses (analysis.*, narrative.engine, cost.rollup, reports.*) and flattens their
output into typed view-models the presentation layer binds to. No scoring,
sequencing, scanning, or cost logic is reimplemented here.

The app starts EMPTY — there is no demo/sample data. Real data enters only via
`run_scan` (live pipeline) or `handle_upload` (OpenVAS/ZAP XML, Shodan JSON,
asset .xlsx). Raw engine objects are held in backend-only vars (underscore
prefix) so they can be re-fed to the Day-1 / cost / export engines on demand
without being serialised to the browser.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import reflex as rx

from analysis.triage import triage_all
from analysis.day1 import build_day1_blueprint
from analysis.attack_brain import analyze_attack_paths, build_mindmap_svg
from analysis.maturity import run_assessment
from analysis.standards_compare import compare_to_standard
from cost.rollup import run_cost_pipeline
from config.loader import get_maturity_questions
from narrative.engine import (
    build_day1_narrative, build_maturity_narrative, build_cost_narrative,
)


# ── lookup maps (presentation only) ──────────────────────────────────────────
TIER_CLASS = {
    "deal_killer": "dk", "critical": "cr", "moderate": "mo",
    "manageable": "ma", "unscored": "ma",
}
TIER_LABEL = {
    "deal_killer": "Deal killer", "critical": "Critical", "moderate": "Moderate",
    "manageable": "Manageable", "unscored": "Unscored",
}
EXPOSURE_LABEL = {
    "internet_facing": "Internet-facing", "partner": "Partner",
    "internal": "Internal", "unknown": "Unknown",
}
EXPOSURE_CLASS = {
    "internet_facing": "internet", "partner": "partner",
    "internal": "internal", "unknown": "internal",
}
RAG_CLASS = {"red": "rag red", "amber": "rag amber", "green": "rag green", "unknown": "rag unknown"}
MODEL_NAME = {"isolate": "Isolate", "broker": "Broker", "federate": "Federate", "integrate": "Integrate"}
MODEL_ORDER = ["isolate", "broker", "federate", "integrate"]
PHASE_TAG = {
    "p0_pre_connect": ("P0", "p0"), "p1_contain": ("P1", "p1"),
    "p2_stabilise": ("P2", "p2"), "p3_integrate_ready": ("P3", "p3"),
}
# maturity gap severity → (rag class, label, bar colour class)
SEVERITY_VIEW = {
    "deal_blocker": ("rag red", "Deal blocker", "dk"),
    "below_min":    ("rag amber", "Below minimum", "cr"),
    "acceptable":   ("rag amber", "Acceptable", "mo"),
    "at_target":    ("rag green", "At target", "ma"),
}


# ── view-models (dataclasses; Reflex serialises these to JS objects) ──────────
@dataclass
class FindingRow:
    title: str
    cve_line: str
    host_line: str
    service: str
    exposure_label: str
    tier_label: str
    tag_class: str
    risk: int
    risk_class: str


@dataclass
class LadderStep:
    num: str
    name: str
    desc: str
    status_label: str
    li_class: str


@dataclass
class PillarRow:
    name: str
    rag_class: str
    rag_label: str
    evidence: str
    recommendation: str


@dataclass
class CritRow:
    label: str
    detail: str
    ico: str
    row_class: str


@dataclass
class GateRow:
    name: str
    status_label: str
    status_class: str
    card_class: str
    criteria: list[CritRow] = field(default_factory=list)


@dataclass
class ModelCard:
    name: str
    summary: str
    card_class: str
    badge: str
    controls: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


@dataclass
class ActionRow:
    title: str
    meta: str
    risk: int
    risk_class: str
    rationale: str
    tag_label: str


@dataclass
class PhaseGroup:
    tag: str
    tag_class: str
    title: str
    count_label: str
    has_items: bool
    actions: list[ActionRow] = field(default_factory=list)


@dataclass
class DomainRow:
    name: str
    score: str
    score_w: str
    rag_class: str
    rag_label: str
    bar_class: str
    detail: str


@dataclass
class AttackService:
    label: str
    tier_label: str
    tier_class: str
    risk: int
    cve: str


@dataclass
class AttackHostVM:
    host: str
    exposure_label: str
    exposure_class: str
    internet_facing: bool
    worst_class: str
    count_label: str
    services: list[AttackService] = field(default_factory=list)


@dataclass
class CostScenarioRow:
    name: str
    total: str
    capex: str
    opex: str
    count_label: str
    active_class: str


@dataclass
class CostCatRow:
    name: str
    base: str
    bar_w: str


@dataclass
class CostItemRow:
    title: str
    category: str
    kind: str
    base: str
    confidence: str
    flag: str
    flag_class: str


@dataclass
class DonutSeg:
    label: str
    pct: str
    count: str
    color: str


@dataclass
class AttackStepVM:
    order: str
    stage: str
    title: str
    detail: str
    technique: str
    tid: str
    ref: str
    tier_class: str


@dataclass
class BrainInsightVM:
    label: str
    sub: str
    bar_w: str        # "" → no bar; else e.g. "60%"
    kind_class: str   # "bi-tech" | "bi-cve"


# tier → hex (matches assets/redflag.css: dk=clay, cr=ochre, mo=teal, ma=emerald)
TIER_HEX = {
    "deal_killer": "#b13b2a", "critical": "#a16207",
    "moderate": "#0e4f6b", "manageable": "#0f5e3a", "unscored": "#a3acb5",
}


# ── static maturity questionnaire (from YAML; structure never changes) ────────
def _build_maturity_form() -> list[dict]:
    mq = get_maturity_questions()
    form: list[dict] = []
    for key, dom in mq.get("domains", {}).items():
        form.append({
            "key": key,
            "label": dom.get("label", key),
            "description": dom.get("description", ""),
            "questions": [
                {"id": q["id"], "text": q["text"], "options": q.get("options", []) or []}
                for q in dom.get("questions", [])
            ],
        })
    return form


MATURITY_FORM = _build_maturity_form()


# ── helpers ───────────────────────────────────────────────────────────────────
def _v(x) -> str:
    """Normalise an enum-or-string field to its string value."""
    return str(getattr(x, "value", x))


def _cve_line(f) -> str:
    parts = [f.cve_id or "No CVE", f"CVSS {f.cvss_score:.1f}"]
    if _v(f.exploit_status) == "active_exploitation":
        parts.append("CISA KEV")
    elif _v(f.exploit_status) == "public_exploit":
        parts.append("public exploit")
    return "  ·  ".join(parts)


def _host_line(f) -> str:
    if f.host and f.port:
        return f"{f.host} : {f.port}"
    return f.host or "—"


def _money(x: float) -> str:
    x = float(x or 0)
    if x >= 1_000_000:
        return f"${x / 1_000_000:.2f}M"
    if x >= 1_000:
        return f"${x / 1_000:.0f}K"
    return f"${x:.0f}"


def _filesize(n: int) -> str:
    n = int(n or 0)
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


# Nmap must write its XML OUTSIDE the project tree. A write into the default
# data/results/ trips Reflex's dev file-watcher, which hot-reloads the app and
# resets backend state mid-scan — the scan completes but its findings are lost.
_SCAN_DIR = os.path.join(tempfile.gettempdir(), "redflag_scans")


def _worst_tier(tiers: list[str]) -> str:
    for t in ("deal_killer", "critical", "moderate", "manageable", "unscored"):
        if t in tiers:
            return t
    return "unscored"


def _empty_view() -> dict:
    """All display fields in their pre-scan empty state."""
    return {
        "scanned": False, "scan_date": "",
        "headline": "", "standfirst": "",
        "avg_score": 0, "verdict_label": "", "verdict_kicker_class": "c-ma", "verdict_msg": "",
        "n_total": 0, "n_dk": 0, "n_crit": 0, "n_mod": 0, "n_man": 0,
        "day1_narrative": "",
        "recommended_label": "", "posture_name": "", "posture_desc": "",
        "findings_rows": [], "ladder": [], "pillars": [], "gates": [],
        "models": [], "phases": [], "attack_hosts": [], "attack_internet_label": "",
        "donut_total": 0, "donut_gradient": "conic-gradient(#e8e8e2 0% 100%)", "donut_segs": [],
        "attack_inet_hosts": 0, "attack_total_hosts": 0, "attack_entry_services": 0,
        "attack_impact_label": "", "attack_impact_class": "mo",
        "mindmap_svg": "", "attack_summary": "", "attack_steps": [], "attack_has_paths": False,
    }


# ── pure builder: engines → dict of display-field values ──────────────────────
def build_view(findings: list, target: str, assessment=None, gap_report=None) -> dict:
    d: dict = _empty_view()
    if not findings and assessment is None:
        return d

    d["scanned"] = bool(findings)
    d["scan_date"] = datetime.now().strftime("%d %B %Y")

    n = len(findings)
    d["n_total"] = n
    n_dk = sum(1 for f in findings if _v(f.deal_tier) == "deal_killer")
    n_crit = sum(1 for f in findings if _v(f.deal_tier) == "critical")
    n_mod = sum(1 for f in findings if _v(f.deal_tier) == "moderate")
    n_man = sum(1 for f in findings if _v(f.deal_tier) == "manageable")
    d["n_dk"], d["n_crit"], d["n_mod"], d["n_man"] = n_dk, n_crit, n_mod, n_man
    avg = sum(f.risk_score for f in findings) / n if n else 0.0
    d["avg_score"] = int(round(avg))

    # risk-breakdown donut (conic-gradient segments + legend), severity order
    d["donut_total"] = n
    stops: list[str] = []
    segs: list[DonutSeg] = []
    cum = 0.0
    for key, label, cnt in (
        ("deal_killer", "Deal killer", n_dk), ("critical", "Critical", n_crit),
        ("moderate", "Moderate", n_mod), ("manageable", "Manageable", n_man),
    ):
        if cnt <= 0 or n == 0:
            continue
        frac = cnt / n * 100
        color = TIER_HEX[key]
        stops.append(f"{color} {cum:.3f}% {cum + frac:.3f}%")
        segs.append(DonutSeg(label=label, pct=f"{frac:.1f}%", count=str(cnt), color=color))
        cum += frac
    d["donut_gradient"] = ("conic-gradient(" + ", ".join(stops) + ")") if stops else "conic-gradient(#e8e8e2 0% 100%)"
    d["donut_segs"] = segs

    if n_dk:
        d["verdict_label"], d["verdict_kicker_class"] = "Deal Killer", "c-dk"
        d["verdict_msg"] = "Active blockers detected — escalate before any close."
    elif avg >= 75:
        d["verdict_label"], d["verdict_kicker_class"] = "Critical", "c-dk"
        d["verdict_msg"] = "Severe exposure — price protection and pre-close remediation required."
    elif avg >= 50:
        d["verdict_label"], d["verdict_kicker_class"] = "Moderate", "c-mo"
        d["verdict_msg"] = "Material gaps — negotiate remediation commitments into the deal."
    else:
        d["verdict_label"], d["verdict_kicker_class"] = "Manageable", "c-ma"
        d["verdict_msg"] = "Standard integration hygiene applies — no blockers to the close."

    if n_dk:
        d["headline"] = "Pre-connection blockers put the proposed acquisition at material risk."
    elif avg >= 75:
        d["headline"] = "Severe perimeter exposure demands price protection before close."
    elif avg >= 50:
        d["headline"] = "Material security gaps to negotiate into the deal terms."
    else:
        d["headline"] = "A manageable security posture with standard integration hygiene."

    parts = []
    if n_dk:
        parts.append(f"{n_dk} pre-connection blocker" + ("" if n_dk == 1 else "s"))
    if n_crit:
        parts.append(f"{n_crit} critical")
    if n_mod:
        parts.append(f"{n_mod} moderate finding" + ("" if n_mod == 1 else "s"))
    lead = ", ".join(parts) if parts else f"{n} findings"

    d["findings_rows"] = [
        FindingRow(
            title=f.title,
            cve_line=_cve_line(f),
            host_line=_host_line(f),
            service=f.service or "",
            exposure_label=EXPOSURE_LABEL.get(_v(f.exposure), "Unknown"),
            tier_label=TIER_LABEL.get(_v(f.deal_tier), "Unscored"),
            tag_class="tag " + TIER_CLASS.get(_v(f.deal_tier), "ma"),
            risk=int(round(f.risk_score)),
            risk_class="risk " + TIER_CLASS.get(_v(f.deal_tier), "ma"),
        )
        for f in findings
    ]

    bp = build_day1_blueprint(findings, assessment=assessment, gap_report=gap_report, target=target)
    d["recommended_label"] = bp.recommended_label
    d["standfirst"] = (
        f"{lead.capitalize()} shape the Day-1 plan. "
        f"Recommended connectivity posture: {bp.recommended_label}."
    )
    d["posture_name"] = MODEL_NAME.get(bp.recommended_model, bp.recommended_label)
    rec_entry = next((m for m in bp.model_catalog if m.get("recommended")), {})
    d["posture_desc"] = " ".join((rec_entry.get("summary") or bp.recommendation_rationale).split())
    d["day1_narrative"] = build_day1_narrative(bp)

    # ladder
    rec_idx = MODEL_ORDER.index(bp.recommended_model) if bp.recommended_model in MODEL_ORDER else 0
    catalog_by_key = {m["key"]: m for m in bp.model_catalog}
    ladder = []
    for i, key in enumerate(MODEL_ORDER):
        m = catalog_by_key.get(key, {})
        controls = m.get("controls", []) or []
        status = "Active" if i == rec_idx else ("Cleared" if i < rec_idx else "Locked")
        ladder.append(LadderStep(
            num=f"{i + 1:02d}",
            name=MODEL_NAME.get(key, key.title()),
            desc="  ·  ".join(controls[:3]) if controls else (m.get("label", "")),
            status_label=status,
            li_class="active" if i == rec_idx else "",
        ))
    d["ladder"] = ladder

    # pillars
    d["pillars"] = [
        PillarRow(
            name=p.label,
            rag_class=RAG_CLASS.get(p.status.value, "rag unknown"),
            rag_label=p.headline,
            evidence=p.evidence[0] if p.evidence else "",
            recommendation=p.recommendation,
        )
        for p in bp.pillars
    ]

    # gates
    d["gates"] = [
        GateRow(
            name=g.label,
            status_label="Pass" if g.passed else "Blocked",
            status_class="gate-status pass" if g.passed else "gate-status blocked",
            card_class="gate-card pass" if g.passed else "gate-card blocked",
            criteria=[
                CritRow(
                    label=c.label, detail=c.detail,
                    ico="✓" if c.passed else "✕",
                    row_class="gate-crit ok" if c.passed else "gate-crit no",
                )
                for c in g.criteria
            ],
        )
        for g in bp.gates
    ]

    # architecture catalog
    d["models"] = [
        ModelCard(
            name=m.get("label", ""),
            summary=" ".join((m.get("summary") or "").split()),
            card_class="model-card recommended" if m.get("recommended") else "model-card",
            badge="Recommended" if m.get("recommended") else "",
            controls=m.get("controls", []) or [],
            sources=m.get("sources", []) or [],
        )
        for m in bp.model_catalog
    ]

    # roadmap by phase
    phases = []
    for pm in bp.phase_meta:
        key = pm["key"]
        items = bp.roadmap.get(key, [])
        tag, cls = PHASE_TAG.get(key, ("", ""))
        actions = [
            ActionRow(
                title=it.title,
                meta=(f"{it.host or ''}" + (f" : {it.service}" if it.service else "")).strip(" :") or "—",
                risk=int(round(it.risk_score)),
                risk_class="action-risk " + TIER_CLASS.get(it.deal_tier, "ma"),
                rationale=it.rationale,
                tag_label=it.source.title(),
            )
            for it in items
        ]
        phases.append(PhaseGroup(
            tag=tag, tag_class="phase-tag " + cls,
            title=pm.get("label", key),
            count_label=f"{len(items)} item" + ("" if len(items) == 1 else "s"),
            has_items=len(items) > 0,
            actions=actions,
        ))
    d["phases"] = phases

    # attack chain (Internet → host → service → CVE), emerald palette
    by_host: dict[str, list] = {}
    for f in findings:
        by_host.setdefault(f.host or "unknown", []).append(f)
    hosts: list[AttackHostVM] = []
    inet_hosts = 0
    for host, fs in by_host.items():
        tiers = [_v(x.deal_tier) for x in fs]
        worst = _worst_tier(tiers)
        is_inet = any(_v(x.exposure) == "internet_facing" for x in fs)
        if is_inet:
            inet_hosts += 1
        exposure = "internet_facing" if is_inet else _v(fs[0].exposure)
        svcs = [
            AttackService(
                label=(f":{x.port}/{x.service}" if x.service else f":{x.port}") if x.port else (x.service or "service"),
                tier_label=TIER_LABEL.get(_v(x.deal_tier), "Unscored"),
                tier_class=TIER_CLASS.get(_v(x.deal_tier), "ma"),
                risk=int(round(x.risk_score)),
                cve=x.cve_id or "",
            )
            for x in sorted(fs, key=lambda z: z.risk_score, reverse=True)
        ]
        hosts.append(AttackHostVM(
            host=host,
            exposure_label=EXPOSURE_LABEL.get(exposure, "Unknown"),
            exposure_class=EXPOSURE_CLASS.get(exposure, "internal"),
            internet_facing=is_inet,
            worst_class=TIER_CLASS.get(worst, "ma"),
            count_label=f"{len(fs)} finding" + ("" if len(fs) == 1 else "s"),
            services=svcs,
        ))
    hosts.sort(key=lambda h: (not h.internet_facing, h.host))
    d["attack_hosts"] = hosts
    d["attack_internet_label"] = (
        f"{inet_hosts} internet-facing host" + ("" if inet_hosts == 1 else "s") + " reachable from the public internet"
        if inet_hosts else "No internet-facing hosts — no external entry point"
    )

    # attack kill-chain stage figures (Internet → exposed host → open service → impact)
    entry_services = sum(1 for f in findings
                         if _v(f.exposure) == "internet_facing" and _v(f.deal_tier) in ("deal_killer", "critical"))
    if entry_services == 0:
        entry_services = sum(1 for f in findings if _v(f.exposure) == "internet_facing")
    d["attack_inet_hosts"] = inet_hosts
    d["attack_total_hosts"] = len(by_host)
    d["attack_entry_services"] = entry_services
    d["attack_impact_label"] = (
        "Deal-killer impact" if n_dk else "Critical impact" if n_crit else
        "Material exposure" if n_mod else "Low residual risk"
    )
    d["attack_impact_class"] = "dk" if n_dk else "cr" if n_crit else "mo" if n_mod else "ma"

    # attacker-brain: knowledge-based (MITRE ATT&CK) attack-path mind-map + narrative
    plan = analyze_attack_paths(findings, target)
    d["mindmap_svg"] = build_mindmap_svg(plan, target)
    d["attack_summary"] = plan.summary
    d["attack_has_paths"] = plan.has_paths
    d["attack_steps"] = [
        AttackStepVM(
            order=f"{s.order:02d}",
            stage=s.stage,
            title=s.title,
            detail=s.detail,
            technique=s.technique,
            tid=s.tid,
            ref=s.ref,
            tier_class=TIER_CLASS.get(s.tier, "ma"),
        )
        for s in plan.steps
    ]
    return d


class RedFlagState(rx.State):
    # ── backend-only raw objects (not serialised to the browser) ─────────────
    _findings: list[Any] = []
    _assessment: Any = None
    _gap_report: Any = None
    _resolved_ip: str = ""
    # staged upload artefacts, consumed together with the live scan on Run scan.
    # kind ∈ {shodan, openvas, zap, asset} → {"name": str, "data": bytes}
    _staged: dict[str, Any] = {}

    # ── session / status ─────────────────────────────────────────────────────
    target: str = ""
    fast_mode: bool = False
    scanning: bool = False
    error: str = ""
    notice: str = ""
    scanner_count: int = 8
    scan_seconds: int = 47

    # ── staged-upload chips (filename · size shown next to each slot) ────────
    up_shodan_label: str = ""
    up_openvas_label: str = ""
    up_zap_label: str = ""
    up_asset_label: str = ""

    scanned: bool = False
    scan_date: str = ""

    # ── editorial framing ────────────────────────────────────────────────────
    headline: str = ""
    standfirst: str = ""

    # ── verdict + counts ─────────────────────────────────────────────────────
    avg_score: int = 0
    verdict_label: str = ""
    verdict_kicker_class: str = "c-ma"
    verdict_msg: str = ""
    n_total: int = 0
    n_dk: int = 0
    n_crit: int = 0
    n_mod: int = 0
    n_man: int = 0

    # ── day 1 ────────────────────────────────────────────────────────────────
    day1_narrative: str = ""
    recommended_label: str = ""
    posture_name: str = ""
    posture_desc: str = ""

    # ── collections ──────────────────────────────────────────────────────────
    findings_rows: list[FindingRow] = []
    ladder: list[LadderStep] = []
    pillars: list[PillarRow] = []
    gates: list[GateRow] = []
    models: list[ModelCard] = []
    phases: list[PhaseGroup] = []
    attack_hosts: list[AttackHostVM] = []
    attack_internet_label: str = ""

    # ── risk-breakdown donut + attack kill-chain figures ─────────────────────
    donut_total: int = 0
    donut_gradient: str = "conic-gradient(#e8e8e2 0% 100%)"
    donut_segs: list[DonutSeg] = []
    attack_inet_hosts: int = 0
    attack_total_hosts: int = 0
    attack_entry_services: int = 0
    attack_impact_label: str = ""
    attack_impact_class: str = "mo"

    # ── attacker-brain (attack-path mind-map + narrative) ────────────────────
    mindmap_svg: str = ""
    attack_summary: str = ""
    attack_steps: list[AttackStepVM] = []
    attack_has_paths: bool = False

    # ── self-improving brain memory (persists across scans, ~/RedFlag-Brain) ──
    brain_active: bool = False
    brain_stat_line: str = ""
    brain_recall_summary: str = ""
    brain_vault_path: str = ""
    brain_kev_known: int = 0
    brain_known: list[BrainInsightVM] = []
    brain_recall: list[BrainInsightVM] = []

    # ── maturity ─────────────────────────────────────────────────────────────
    mat_done: bool = False
    mat_overall: str = "0.0"
    mat_overall_pct: int = 0
    mat_overall_w: str = "0%"
    mat_blocker: bool = False
    mat_completion: int = 0
    mat_narrative: str = ""
    mat_domains: list[DomainRow] = []

    # ── cost ─────────────────────────────────────────────────────────────────
    cost_ready: bool = False
    cost_scenario: str = "base"
    cost_scope: str = "all"
    cost_include_maturity: bool = True
    cost_headline: str = "$0"
    cost_headline_label: str = "Base-case estimate"
    cost_low: str = "$0"
    cost_base: str = "$0"
    cost_high: str = "$0"
    cost_capex: str = "$0"
    cost_opex: str = "$0"
    cost_flagged_n: int = 0
    cost_narrative: str = ""
    cost_scenarios: list[CostScenarioRow] = []
    cost_categories: list[CostCatRow] = []
    cost_items: list[CostItemRow] = []

    # ── internal apply ───────────────────────────────────────────────────────
    def _apply(self, d: dict):
        for k, v in d.items():
            setattr(self, k, v)

    @property
    def has_data(self) -> bool:
        return bool(self._findings) or self._assessment is not None

    def ensure_loaded(self):
        """on_load — intentionally a no-op. The app holds no demo data."""
        return None

    def set_target(self, value: str):
        self.target = value

    def toggle_fast_mode(self, value: bool):
        self.fast_mode = bool(value)

    def clear_notice(self):
        self.notice = ""
        self.error = ""

    # ── manual file uploads — STAGE only; consumed by run_scan ────────────────
    # Mirrors the Streamlit sidebar: you pick the intelligence files, then a
    # single "Run scan" fuses the live scan AND every staged file into one
    # findings set (uploaded Shodan JSON replaces the live API; OpenVAS/ZAP are
    # correlation-merged against the Nmap layer; assets reclassify sensitivity).
    _UPLOAD_LABELS = {"shodan": "Shodan JSON", "openvas": "OpenVAS XML",
                      "zap": "OWASP ZAP XML", "asset": "Asset inventory"}

    async def upload_shodan(self, files: list[rx.UploadFile]):
        await self._stage(files, "shodan")

    async def upload_openvas(self, files: list[rx.UploadFile]):
        await self._stage(files, "openvas")

    async def upload_zap(self, files: list[rx.UploadFile]):
        await self._stage(files, "zap")

    async def upload_asset(self, files: list[rx.UploadFile]):
        await self._stage(files, "asset")

    async def _stage(self, files, kind: str):
        """Read one uploaded file into the staging buffer and show a chip.

        Nothing is parsed or scored here — staged bytes are held until the next
        Run scan, so the file always combines with (never overwrites) the scan.
        """
        if not files:
            return
        file = files[0]
        name = (getattr(file, "name", None) or getattr(file, "filename", "") or "upload")
        try:
            data = await file.read()
        except Exception as e:
            self.error = f"Could not read {name}: {e}"
            return
        self._staged = {**self._staged, kind: {"name": name, "data": data}}
        setattr(self, f"up_{kind}_label", f"{name}  ·  {_filesize(len(data))}")
        self.error = ""
        self.notice = f"{self._UPLOAD_LABELS.get(kind, kind)} staged: {name} — click Run scan to process."

    def clear_shodan(self):
        self._clear_staged("shodan")

    def clear_openvas(self):
        self._clear_staged("openvas")

    def clear_zap(self):
        self._clear_staged("zap")

    def clear_asset(self):
        self._clear_staged("asset")

    def _clear_staged(self, kind: str):
        self._staged = {k: v for k, v in self._staged.items() if k != kind}
        setattr(self, f"up_{kind}_label", "")
        self.notice = f"{self._UPLOAD_LABELS.get(kind, kind)} removed."

    # ── staged-file parsing helpers ──────────────────────────────────────────
    def _write_tmp(self, entry: dict, default_suffix: str) -> str:
        name = entry.get("name", "upload")
        suffix = os.path.splitext(name.lower())[1] or default_suffix
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(entry["data"])
            return tmp.name

    def _staged_shodan(self):
        """Parse staged Shodan JSON → (shodan_result, ip) or (None, "")."""
        entry = self._staged.get("shodan")
        if not entry:
            return None, ""
        from scanners.shodan_scan import parse_shodan_json
        try:
            data = json.loads(entry["data"].decode("utf-8", "ignore"))
            return parse_shodan_json(data), str(data.get("ip_str") or data.get("ip") or "")
        except Exception:
            return None, ""

    def _staged_xml(self, kind: str, parser) -> list:
        entry = self._staged.get(kind)
        if not entry:
            return []
        path = ""
        try:
            path = self._write_tmp(entry, ".xml")
            return parser(path)
        except Exception:
            return []
        finally:
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    def _staged_assets(self) -> dict:
        entry = self._staged.get("asset")
        if not entry:
            return {}
        from analysis.parsers.excel_assets import parse_asset_excel
        path = ""
        try:
            path = self._write_tmp(entry, ".xlsx")
            return parse_asset_excel(path)
        except Exception:
            return {}
        finally:
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    # ── comprehensive scan — live target + every staged file, one pipeline ────
    def run_scan(self):
        """Fuse the live scan and all staged uploads into one findings set.

        Faithful to the Streamlit "Run Comprehensive Scan": nmap (+ optional
        fast mode) → Vulners → Shodan (staged JSON beats live API) → OpenVAS /
        ZAP correlation-merge → DNS / TLS / Breach → asset sensitivity → triage.
        A target is optional: with only staged files, the live scanners are
        skipped and the uploads are processed on their own.
        """
        tgt = self.target.strip()
        has_uploads = bool(self._staged)
        if not tgt and not has_uploads:
            self.error = "Enter a target host or IP, or stage an intelligence file, first."
            return
        self.scanning = True
        self.error = ""
        self.notice = ""
        yield
        try:
            import socket
            from scanners.nmap_scan import run_nmap_scan
            from analysis.parser import analyze_nmap_file
            from scanners.vulners_parse import parse_vulners_from_nmap_xml, merge_vulners_with_nmap
            from scanners.shodan_scan import lookup_host, enrich_findings_with_shodan, create_shodan_findings
            from scanners.openvas_parse import parse_openvas_xml, merge_openvas_with_nmap
            from scanners.zap_scan import parse_zap_xml, merge_zap_with_nmap
            from analysis.parsers.excel_assets import apply_sensitivity_to_findings
            from scanners.dns_scan import run_dns_scan
            from scanners.tls_scan import run_tls_scan
            from scanners.breach_scan import run_breach_scan

            staged_shodan, staged_ip = self._staged_shodan()

            nmap_findings: list = []
            findings: list = []          # nmap layer (shodan-enriched, openvas/zap-merged)
            shodan_standalone: list = []
            all_findings: list = []
            resolved_ip = ""

            if tgt:
                os.makedirs(_SCAN_DIR, exist_ok=True)
                xml_file = run_nmap_scan(tgt, output_dir=_SCAN_DIR, fast_mode=self.fast_mode)
                nmap_findings = analyze_nmap_file(xml_file)
                vulners_raw = parse_vulners_from_nmap_xml(xml_file)
                if vulners_raw:
                    nmap_findings = merge_vulners_with_nmap(nmap_findings, vulners_raw)

                try:
                    resolved_ip = socket.gethostbyname(tgt)
                except Exception:
                    resolved_ip = ""

                # Shodan: staged JSON takes priority over the live API call
                if staged_shodan is not None:
                    shodan_result = staged_shodan
                    if not resolved_ip:
                        resolved_ip = staged_ip
                elif resolved_ip:
                    try:
                        shodan_result = lookup_host(resolved_ip)
                    except Exception:
                        shodan_result = None
                else:
                    shodan_result = None

                findings = (enrich_findings_with_shodan(nmap_findings, shodan_result)
                            if shodan_result else list(nmap_findings))
                if shodan_result and resolved_ip:
                    try:
                        shodan_standalone = create_shodan_findings(shodan_result, resolved_ip)
                    except Exception:
                        shodan_standalone = []
                all_findings = list(findings) + shodan_standalone
            else:
                # Upload-only: no live scanners. Standalone Shodan from staged JSON.
                if staged_shodan is not None:
                    resolved_ip = staged_ip
                    try:
                        shodan_standalone = create_shodan_findings(staged_shodan, resolved_ip)
                    except Exception:
                        shodan_standalone = []
                all_findings = list(shodan_standalone)

            self._resolved_ip = resolved_ip

            # ── OpenVAS — correlation-merge into the Nmap layer ──────────────
            openvas_findings = self._staged_xml("openvas", parse_openvas_xml)
            if openvas_findings:
                if tgt:
                    findings = merge_openvas_with_nmap(findings, openvas_findings)
                    all_findings = list(findings) + shodan_standalone
                else:
                    all_findings += openvas_findings

            # ── ZAP — correlation-merge into the Nmap layer ──────────────────
            zap_findings = self._staged_xml("zap", parse_zap_xml)
            if zap_findings:
                if tgt:
                    findings = merge_zap_with_nmap(findings, zap_findings)
                    all_findings = list(findings) + shodan_standalone
                else:
                    all_findings += zap_findings

            # ── DNS / TLS / Breach — only meaningful against a live target ────
            if tgt:
                try:
                    all_findings += run_dns_scan(tgt)
                except Exception:
                    pass
                try:
                    https_ports = list({f.port for f in nmap_findings
                                        if f.port and ((f.service or "").lower() in ("https", "ssl") or f.port == 443)})
                    tls_findings, _ = run_tls_scan(tgt, https_ports)
                    all_findings += tls_findings
                except Exception:
                    pass
                try:
                    breach_findings, _ = run_breach_scan(tgt, [resolved_ip] if resolved_ip else [])
                    all_findings += breach_findings
                except Exception:
                    pass

            # ── Asset inventory — reclassify data_sensitivity across the lot ──
            asset_map = self._staged_assets()
            if asset_map:
                all_findings = apply_sensitivity_to_findings(all_findings, asset_map)

            self._findings = triage_all(all_findings)
            self._refresh_all()
            self._learn_and_recall(tgt)

            # ── result notice — sources fused + deal-killer headline ─────────
            sources = []
            if tgt:
                sources.append("live scan")
            for k in ("shodan", "openvas", "zap", "asset"):
                if self._staged.get(k):
                    sources.append({"shodan": "Shodan", "openvas": "OpenVAS",
                                    "zap": "ZAP", "asset": "asset inventory"}[k])
            n = len(self._findings)
            n_dk = sum(1 for f in self._findings if _v(f.deal_tier) == "deal_killer")
            src_txt = (" · sources: " + ", ".join(sources)) if sources else ""
            if n_dk:
                self.notice = (f"Scan complete — {n_dk} deal-killer finding"
                               + ("" if n_dk == 1 else "s")
                               + f" across {n} total findings{src_txt}.")
            else:
                self.notice = f"Scan complete — {n} findings{src_txt}."
        except Exception as e:
            self.error = f"Scan failed: {e}"
        finally:
            self.scanning = False

    # ── self-improving brain memory (learn-by-remembering, no LLM) ───────────
    @staticmethod
    def _fmt_brain_stats(s) -> str:
        return (f"Learned from {s.scans} scan" + ("" if s.scans == 1 else "s")
                + f"  ·  {s.techniques} techniques  ·  {s.cves} CVEs tracked"
                + (f"  ·  {s.kev_known} known-exploited" if s.kev_known else ""))

    def _learn_and_recall(self, tgt: str):
        """Feed this scan into the persistent brain, then surface what it knows.

        Best-effort: the brain is long-term memory on disk (~/RedFlag-Brain) and
        must NEVER break a scan, so the whole thing is guarded. Recall reads the
        prior corpus first (so it reflects what we knew coming in), then we learn.
        """
        try:
            from analysis.brain_memory import BrainMemory
            brain = BrainMemory()
            plan = analyze_attack_paths(self._findings, tgt or "target")
            recall_summary, recall_items = brain.recall(self._findings, plan)
            brain.learn_from_scan(self._findings, plan, tgt or "target")
            s = brain.stats()
            self.brain_active = True
            self.brain_stat_line = self._fmt_brain_stats(s)
            self.brain_recall_summary = recall_summary
            self.brain_vault_path = s.vault_path
            self.brain_kev_known = s.kev_known
            techs = brain.top_techniques(6)
            maxw = max((t.weight for t in techs), default=1) or 1
            self.brain_known = [
                BrainInsightVM(label=t.label, sub=t.sub,
                               bar_w=f"{int(round(t.weight / maxw * 100))}%",
                               kind_class="bi-tech")
                for t in techs
            ]
            self.brain_recall = [
                BrainInsightVM(label=b.label, sub=b.sub, bar_w="", kind_class="bi-cve")
                for b in recall_items
            ]
        except Exception:
            # memory is a bonus layer; a failure here leaves the scan intact
            pass

    def refresh_threat_intel(self):
        """Pull the free CISA KEV feed into the brain (manual, best-effort)."""
        self.error = ""
        self.notice = "Fetching the latest CISA KEV feed…"
        yield
        try:
            from analysis.brain_memory import BrainMemory
            brain = BrainMemory()
            ok, msg, _n = brain.ingest_kev()
            if self.brain_active:
                s = brain.stats()
                self.brain_kev_known = s.kev_known
                self.brain_stat_line = self._fmt_brain_stats(s)
            if ok:
                self.notice = msg
            else:
                self.error = msg
        except Exception as e:
            self.error = f"Threat-intel refresh failed: {e}"

    # ── maturity questionnaire ───────────────────────────────────────────────
    def submit_maturity(self, form_data: dict):
        answers: dict[str, int] = {}
        for k, v in form_data.items():
            if v in ("", None):
                continue
            try:
                answers[k] = int(v)
            except (TypeError, ValueError):
                continue
        if not answers:
            self.error = "Answer at least one question before submitting."
            return
        assessment = run_assessment(answers, target=self.target or "target")
        self._assessment = assessment
        try:
            self._gap_report = compare_to_standard(assessment)
        except Exception:
            self._gap_report = None
        self._build_maturity_result()
        self._refresh_all()
        self.notice = f"Maturity assessment scored — overall {assessment.overall_score:.1f} / 5."

    def reset_maturity(self):
        self._assessment = None
        self._gap_report = None
        self.mat_done = False
        self.mat_domains = []
        self.mat_narrative = ""
        self.mat_overall = "0.0"
        self.mat_overall_pct = 0
        self.mat_overall_w = "0%"
        self.mat_blocker = False
        self.mat_completion = 0
        self._refresh_all()
        self.notice = "Maturity assessment cleared."

    def _build_maturity_result(self):
        a = self._assessment
        if a is None:
            return
        self.mat_done = True
        self.mat_overall = f"{a.overall_score:.1f}"
        self.mat_overall_pct = int(round(a.overall_score / 5 * 100))
        self.mat_overall_w = f"{int(round(a.overall_score / 5 * 100))}%"
        self.mat_blocker = bool(a.is_deal_blocker)
        self.mat_completion = int(round(a.completion_pct))
        self.mat_narrative = build_maturity_narrative(a)
        rows = []
        for ds in a.domain_scores:
            rag_class, rag_label, bar_class = SEVERITY_VIEW.get(
                _v(ds.gap_severity), ("rag unknown", "Not scored", "ma")
            )
            rows.append(DomainRow(
                name=ds.label,
                score=f"{ds.score:.1f}",
                score_w=f"{int(round(ds.score / 5 * 100))}%",
                rag_class=rag_class,
                rag_label=rag_label,
                bar_class=bar_class,
                detail=(
                    f"min {ds.acceptable_min}  ·  target {ds.recommended}  ·  "
                    f"{ds.answered}/{ds.total_questions} answered"
                ),
            ))
        self.mat_domains = rows

    # ── cost roll-up + What-If ───────────────────────────────────────────────
    def set_cost_scenario(self, scenario: str):
        self.cost_scenario = scenario
        self._build_cost()

    def set_cost_scope(self, scope: str):
        self.cost_scope = scope
        self._build_cost()

    def toggle_cost_maturity(self, value: bool):
        self.cost_include_maturity = value
        self._build_cost()

    def _scoped_findings(self) -> list:
        if self.cost_scope == "dk":
            return [f for f in self._findings if _v(f.deal_tier) == "deal_killer"]
        if self.cost_scope == "dk_cr":
            return [f for f in self._findings if _v(f.deal_tier) in ("deal_killer", "critical")]
        return list(self._findings)

    def _build_cost(self):
        findings = self._scoped_findings()
        if not findings:
            self.cost_ready = False
            self.cost_scenarios, self.cost_categories, self.cost_items = [], [], []
            self.cost_headline = "$0"
            self.cost_low = self.cost_base = self.cost_high = "$0"
            self.cost_capex = self.cost_opex = "$0"
            self.cost_flagged_n = 0
            self.cost_narrative = ""
            return
        gap = self._gap_report if self.cost_include_maturity else None
        rollup = run_cost_pipeline(
            findings, gap_report=gap, target=self.target or "target",
            include_maturity_gaps=self.cost_include_maturity,
        )
        self.cost_ready = True
        self.cost_low = _money(rollup.total.low)
        self.cost_base = _money(rollup.total.base)
        self.cost_high = _money(rollup.total.high)
        self.cost_capex = _money(rollup.capex_total.base)
        self.cost_opex = _money(rollup.opex_total.base)
        emphasis = {"low": rollup.total.low, "base": rollup.total.base, "high": rollup.total.high}[self.cost_scenario]
        label = {"low": "Best-case estimate", "base": "Most-likely estimate", "high": "Worst-case estimate"}[self.cost_scenario]
        self.cost_headline = _money(emphasis)
        self.cost_headline_label = label
        self.cost_flagged_n = len(rollup.flagged_items)
        self.cost_narrative = build_cost_narrative(rollup)

        self.cost_scenarios = [
            CostScenarioRow(
                name={"low": "Best case", "base": "Most likely", "high": "Worst case"}.get(_v(s.scenario_type), _v(s.scenario_type).title()),
                total=_money(s.total_usd),
                capex=_money(s.capex_usd),
                opex=_money(s.opex_usd),
                count_label=f"{s.line_count} line item" + ("" if s.line_count == 1 else "s"),
                active_class="cost-scn active" if _v(s.scenario_type) == self.cost_scenario else "cost-scn",
            )
            for s in rollup.scenarios
        ]

        max_base = max((v.get("base", 0.0) for v in rollup.by_category.values()), default=0.0) or 1.0
        self.cost_categories = [
            CostCatRow(
                name=cat.replace("_", " ").title(),
                base=_money(vals.get("base", 0.0)),
                bar_w=f"{int(round(vals.get('base', 0.0) / max_base * 100))}%",
            )
            for cat, vals in sorted(rollup.by_category.items(), key=lambda kv: kv[1].get("base", 0.0), reverse=True)
        ]

        self.cost_items = [
            CostItemRow(
                title=it.title,
                category=str(getattr(it.category, "value", it.category)).replace("_", " ").title(),
                kind=str(getattr(it.capex_opex, "value", it.capex_opex)).upper(),
                base=_money(it.cost.base),
                confidence=str(getattr(it.confidence, "value", it.confidence)).title(),
                flag="Review" if it.needs_review else "",
                flag_class="cost-flag on" if it.needs_review else "cost-flag",
            )
            for it in sorted(rollup.line_items, key=lambda z: z.cost.base, reverse=True)
        ]

    # ── shared refresh ───────────────────────────────────────────────────────
    def _refresh_all(self):
        self._apply(build_view(self._findings, self.target or "target",
                               assessment=self._assessment, gap_report=self._gap_report))
        self._build_cost()

    # ── exports ──────────────────────────────────────────────────────────────
    def download_csv(self):
        if not self._findings:
            self.error = "Nothing to export yet — run a scan or upload findings first."
            return
        from reports.generator import findings_to_dataframe
        csv = findings_to_dataframe(self._findings).to_csv(index=False)
        return rx.download(data=csv, filename=f"redflag_{self._slug()}.csv")

    def download_pdf(self):
        if not self._findings:
            self.error = "Nothing to export yet — run a scan or upload findings first."
            return
        from reports.pdf_report import generate_pdf_report
        path = generate_pdf_report(
            self._findings, self.target or "target", self._resolved_ip,
            output_dir=tempfile.gettempdir(),
        )
        return self._download_file(path, f"redflag_report_{self._slug()}.pdf")

    def download_day1_pdf(self):
        if not self._findings:
            self.error = "Nothing to export yet — run a scan or upload findings first."
            return
        from reports.pdf_report import generate_day1_section
        bp = build_day1_blueprint(self._findings, assessment=self._assessment,
                                  gap_report=self._gap_report, target=self.target or "target")
        synthetic = os.path.join(tempfile.gettempdir(), "report.pdf")
        path = generate_day1_section(synthetic, bp, build_day1_narrative(bp))
        return self._download_file(path, f"redflag_day1_{self._slug()}.pdf")

    def download_cost_pdf(self):
        if not self._findings:
            self.error = "Nothing to export yet — run a scan or upload findings first."
            return
        from reports.pdf_report import generate_cost_section
        rollup = run_cost_pipeline(self._findings, gap_report=self._gap_report,
                                   target=self.target or "target")
        synthetic = os.path.join(tempfile.gettempdir(), "report.pdf")
        path = generate_cost_section(synthetic, rollup, build_cost_narrative(rollup))
        return self._download_file(path, f"redflag_cost_{self._slug()}.pdf")

    def _slug(self) -> str:
        base = (self.target or "target").replace(":", "_").replace("/", "_").strip()
        return base or "target"

    def _download_file(self, path: str, filename: str):
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            return rx.download(data=data, filename=filename)
        except Exception as e:
            self.error = f"Export failed: {e}"
            return None
