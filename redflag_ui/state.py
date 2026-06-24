"""
redflag_ui/state.py — Reflex State for the RedFlag UI.

This is the ONLY new logic layer. It calls the SAME engines the Streamlit app
uses (analysis.triage, analysis.day1, narrative.engine) and flattens their
output into typed view-models the presentation layer binds to. No scoring,
sequencing, or scanning logic is reimplemented here.

`build_view()` is a pure engines→dict builder. It is used twice:
  • at import time to seed the demo data as the State's default values, so the
    server-rendered page is populated immediately (no websocket round-trip), and
  • inside the load_sample / run_scan event handlers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

import reflex as rx

from analysis.schema import (
    Finding, ExposureLevel, DataSensitivity, ExploitStatus,
    ScannerSource, EvidenceStrength,
)
from analysis.triage import triage_all
from analysis.day1 import build_day1_blueprint
from narrative.engine import build_executive_summary, build_day1_narrative


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
RAG_CLASS = {"red": "rag red", "amber": "rag amber", "green": "rag green", "unknown": "rag unknown"}
MODEL_NAME = {"isolate": "Isolate", "broker": "Broker", "federate": "Federate", "integrate": "Integrate"}
MODEL_ORDER = ["isolate", "broker", "federate", "integrate"]
PHASE_TAG = {
    "p0_pre_connect": ("P0", "p0"), "p1_contain": ("P1", "p1"),
    "p2_stabilise": ("P2", "p2"), "p3_integrate_ready": ("P3", "p3"),
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
    tag_class: str        # e.g. "tag dk"
    risk: int
    risk_class: str       # e.g. "risk dk"


@dataclass
class LadderStep:
    num: str
    name: str
    desc: str
    status_label: str
    li_class: str         # "active" | ""


@dataclass
class PillarRow:
    name: str
    rag_class: str        # "rag red"
    rag_label: str
    evidence: str
    recommendation: str


@dataclass
class CritRow:
    label: str
    detail: str
    ico: str
    row_class: str        # "gate-crit ok" | "gate-crit no"


@dataclass
class GateRow:
    name: str
    status_label: str
    status_class: str     # "gate-status pass"
    card_class: str       # "gate-card pass"
    criteria: list[CritRow] = field(default_factory=list)


@dataclass
class ModelCard:
    name: str
    summary: str
    card_class: str       # "model-card recommended"
    badge: str            # "Recommended" | ""
    controls: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


@dataclass
class ActionRow:
    title: str
    meta: str
    risk: int
    risk_class: str       # "action-risk dk"
    rationale: str
    tag_label: str


@dataclass
class PhaseGroup:
    tag: str
    tag_class: str        # "phase-tag p0"
    title: str
    count_label: str
    has_items: bool
    actions: list[ActionRow] = field(default_factory=list)


def _demo_findings() -> list:
    """The proven 4-finding fixture (mirrors tests/test_app_smoke.py)."""
    raw = [
        Finding(
            cve_id="CVE-2017-0144", title="SMB Remote Code Execution (EternalBlue)",
            host="10.0.0.5", port=445, service="microsoft-ds", cvss_score=9.8,
            description="MS17-010 SMBv1 RCE.", remediation="Patch MS17-010; disable SMBv1.",
            exposure=ExposureLevel.INTERNET_FACING, data_sensitivity=DataSensitivity.CROWN_JEWEL,
            exploit_status=ExploitStatus.ACTIVE_EXPLOITATION, scanner_source=ScannerSource.OPENVAS,
            evidence_strength=EvidenceStrength.CONFIRMED,
        ),
        Finding(
            cve_id="CVE-2021-44228", title="Log4Shell JNDI RCE",
            host="10.0.0.6", port=8080, service="http", cvss_score=10.0,
            description="Log4j2 JNDI lookup RCE.", remediation="Upgrade Log4j to 2.17+.",
            exposure=ExposureLevel.INTERNET_FACING, data_sensitivity=DataSensitivity.SENSITIVE,
            exploit_status=ExploitStatus.PUBLIC_EXPLOIT, scanner_source=ScannerSource.NMAP,
            evidence_strength=EvidenceStrength.CORRELATED,
        ),
        Finding(
            title="Open SSH service", host="10.0.0.7", port=22, service="ssh",
            cvss_score=5.0, description="SSH exposed.", remediation="Restrict by IP.",
            exposure=ExposureLevel.PARTNER, data_sensitivity=DataSensitivity.LOW,
            exploit_status=ExploitStatus.NO_EXPLOIT, scanner_source=ScannerSource.NMAP,
            evidence_strength=EvidenceStrength.UNKNOWN,
        ),
        Finding(
            title="HTTP service banner", host="10.0.0.8", port=80, service="http",
            cvss_score=2.5, description="Informational.", remediation="None.",
            exposure=ExposureLevel.INTERNAL, data_sensitivity=DataSensitivity.LOW,
            exploit_status=ExploitStatus.NO_EXPLOIT, scanner_source=ScannerSource.NMAP,
            evidence_strength=EvidenceStrength.INFERRED,
        ),
    ]
    return triage_all(raw)


def _v(x) -> str:
    """Normalise an enum-or-string field to its string value.

    triage_all assigns enum *objects* (the model has no validate_assignment), so
    a finding's deal_tier/exposure may be either a DealTier enum or its string
    value depending on code path — mirror app.py's getattr(..., 'value', ...).
    """
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


# ── pure builder: engines → dict of State field values ───────────────────────
def build_view(findings: list, target: str, demo: bool) -> dict:
    d: dict = {}
    d["is_demo"] = demo
    d["scanned"] = True
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

    bp = build_day1_blueprint(findings, target=target)
    d["recommended_label"] = bp.recommended_label
    d["standfirst"] = (
        f"{lead.capitalize()} shape the Day-1 plan. "
        f"Recommended connectivity posture: {bp.recommended_label}."
    )
    d["posture_name"] = MODEL_NAME.get(bp.recommended_model, bp.recommended_label)
    rec_entry = next((m for m in bp.model_catalog if m.get("recommended")), {})
    d["posture_desc"] = " ".join((rec_entry.get("summary") or bp.recommendation_rationale).split())
    d["pull_quote"] = bp.recommendation_rationale
    d["exec_summary"] = build_executive_summary(findings, target=target)
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
                    label=c.label,
                    detail=c.detail,
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
            tag=tag,
            tag_class="phase-tag " + cls,
            title=pm.get("label", key),
            count_label=f"{len(items)} item" + ("" if len(items) == 1 else "s"),
            has_items=len(items) > 0,
            actions=actions,
        ))
    d["phases"] = phases
    return d


# Computed once at import → seeds SSR-visible demo data (no socket needed).
_DEFAULTS = build_view(_demo_findings(), "target.example.com", True)


class RedFlagState(rx.State):
    # session / status
    target: str = "target.example.com"
    scanning: bool = False
    error: str = ""
    scanner_count: int = 8
    scan_seconds: int = 47

    scanned: bool = _DEFAULTS["scanned"]
    is_demo: bool = _DEFAULTS["is_demo"]
    scan_date: str = _DEFAULTS["scan_date"]

    # editorial framing
    headline: str = _DEFAULTS["headline"]
    standfirst: str = _DEFAULTS["standfirst"]

    # verdict + counts
    avg_score: int = _DEFAULTS["avg_score"]
    verdict_label: str = _DEFAULTS["verdict_label"]
    verdict_kicker_class: str = _DEFAULTS["verdict_kicker_class"]
    verdict_msg: str = _DEFAULTS["verdict_msg"]
    n_total: int = _DEFAULTS["n_total"]
    n_dk: int = _DEFAULTS["n_dk"]
    n_crit: int = _DEFAULTS["n_crit"]
    n_mod: int = _DEFAULTS["n_mod"]
    n_man: int = _DEFAULTS["n_man"]

    # narrative
    exec_summary: str = _DEFAULTS["exec_summary"]
    day1_narrative: str = _DEFAULTS["day1_narrative"]
    pull_quote: str = _DEFAULTS["pull_quote"]

    # day 1
    recommended_label: str = _DEFAULTS["recommended_label"]
    posture_name: str = _DEFAULTS["posture_name"]
    posture_desc: str = _DEFAULTS["posture_desc"]

    # collections
    findings_rows: list[FindingRow] = _DEFAULTS["findings_rows"]
    ladder: list[LadderStep] = _DEFAULTS["ladder"]
    pillars: list[PillarRow] = _DEFAULTS["pillars"]
    gates: list[GateRow] = _DEFAULTS["gates"]
    models: list[ModelCard] = _DEFAULTS["models"]
    phases: list[PhaseGroup] = _DEFAULTS["phases"]

    # ── handlers ─────────────────────────────────────────────────────────────
    def _apply(self, d: dict):
        for k, v in d.items():
            setattr(self, k, v)
        self.error = ""

    def ensure_loaded(self):
        """on_load — no-op once data exists (defaults already seed the demo)."""
        if not self.scanned:
            self._apply(build_view(_demo_findings(), self.target, True))

    def set_target(self, value: str):
        self.target = value

    def load_sample(self):
        self.target = "target.example.com"
        self._apply(build_view(_demo_findings(), "target.example.com", True))

    def run_scan(self):
        """Live scan — same core pipeline as app.py (nmap→shodan→dns→tls→breach→triage)."""
        tgt = self.target.strip()
        if not tgt:
            self.error = "Enter a target host or IP first."
            return
        self.scanning = True
        self.error = ""
        yield
        try:
            import socket
            from scanners.nmap_scan import run_nmap_scan
            from analysis.parser import analyze_nmap_file
            from scanners.vulners_parse import parse_vulners_from_nmap_xml, merge_vulners_with_nmap
            from scanners.shodan_scan import lookup_host, enrich_findings_with_shodan, create_shodan_findings
            from scanners.dns_scan import run_dns_scan
            from scanners.tls_scan import run_tls_scan
            from scanners.breach_scan import run_breach_scan

            xml_file = run_nmap_scan(tgt)
            nmap_findings = analyze_nmap_file(xml_file)
            vulners_raw = parse_vulners_from_nmap_xml(xml_file)
            if vulners_raw:
                nmap_findings = merge_vulners_with_nmap(nmap_findings, vulners_raw)

            resolved_ip = socket.gethostbyname(tgt)
            shodan_result = lookup_host(resolved_ip)
            findings = enrich_findings_with_shodan(nmap_findings, shodan_result)
            all_findings = findings + create_shodan_findings(shodan_result, resolved_ip)

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
                breach_findings, _ = run_breach_scan(tgt, [resolved_ip])
                all_findings += breach_findings
            except Exception:
                pass

            self._apply(build_view(triage_all(all_findings), tgt, demo=False))
        except Exception as e:
            self.error = f"Scan failed: {e}"
        finally:
            self.scanning = False
