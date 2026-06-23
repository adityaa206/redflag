"""
analysis/day1.py — "Day 1" Safe Harbor Blueprint engine.

Re-frames the findings + maturity data RedFlag already produces on a temporal
integration timeline, and recommends a Day-1 connectivity architecture that lets
the acquired business stay productive *without exposing the parent network*.

This module answers two questions the existing scoring does not:
  1. "What do we fix FIRST?"            -> build_roadmap (phase-sequenced)
  2. "How do we connect on Day 1?"      -> recommend_connectivity (architecture tier)

All computation is deterministic — no Streamlit, no external API calls — mirroring
analysis/triage.py and analysis/maturity.py. All thresholds live in
config/day1_blueprint.yaml.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from config.loader import get_day1_blueprint, get_domain_standard


# ── Enums ─────────────────────────────────────────────────────────────────────

class Day1Phase(str, Enum):
    P0_PRE_CONNECT     = "p0_pre_connect"      # Fix before any link
    P1_CONTAIN         = "p1_contain"          # At cutover
    P2_STABILISE       = "p2_stabilise"        # Day 1-30
    P3_INTEGRATE_READY = "p3_integrate_ready"  # Day 30-100


class ConnectivityModel(str, Enum):
    ISOLATE   = "isolate"
    BROKER    = "broker"
    FEDERATE  = "federate"
    INTEGRATE = "integrate"


class PillarStatus(str, Enum):
    GREEN   = "green"
    AMBER   = "amber"
    RED     = "red"
    UNKNOWN = "unknown"


# ── Value objects ─────────────────────────────────────────────────────────────

@dataclass
class Pillar:
    """One of the three 'Review' pillars (identity / network / remote access)."""
    key:             str
    label:           str
    status:          PillarStatus
    headline:        str
    evidence:        list[str]
    recommendation:  str


@dataclass
class CriterionResult:
    """Result of evaluating a single tier-gate entry criterion."""
    label:  str
    passed: bool
    detail: str = ""


@dataclass
class IntegrationGate:
    """Entry gate for one connectivity tier."""
    model:    str                       # ConnectivityModel value
    label:    str
    passed:   bool
    criteria: list[CriterionResult] = field(default_factory=list)

    @property
    def blocking(self) -> list[CriterionResult]:
        return [c for c in self.criteria if not c.passed]


@dataclass
class Day1ActionItem:
    """A single roadmap item (finding or maturity gap) assigned to a phase."""
    phase:       str                    # Day1Phase value
    title:       str
    source:      str                    # "finding" | "maturity"
    risk_score:  float
    deal_tier:   str
    rationale:   str
    host:        Optional[str] = None
    service:     Optional[str] = None
    remediation: str = ""


@dataclass
class Day1Blueprint:
    """Full Day-1 Safe Harbor Blueprint result."""
    target:                  str
    recommended_model:       str        # ConnectivityModel value
    recommended_label:       str
    recommendation_rationale: str
    model_catalog:           list[dict] = field(default_factory=list)   # connectivity_models + 'recommended' flag
    pillars:                 list[Pillar] = field(default_factory=list)
    gates:                   list[IntegrationGate] = field(default_factory=list)
    roadmap:                 dict = field(default_factory=dict)         # phase_value -> list[Day1ActionItem]
    phase_meta:              list[dict] = field(default_factory=list)   # ordered phase metadata
    has_maturity:            bool = False

    @property
    def phase_counts(self) -> dict:
        return {ph: len(items) for ph, items in self.roadmap.items()}

    @property
    def total_actions(self) -> int:
        return sum(len(items) for items in self.roadmap.values())

    @property
    def p0_count(self) -> int:
        return len(self.roadmap.get(Day1Phase.P0_PRE_CONNECT.value, []))


# ── Internal helpers ──────────────────────────────────────────────────────────

def _enum_val(v) -> str:
    return str(getattr(v, "value", v))


def is_remote_access(finding, cfg: Optional[dict] = None) -> bool:
    """True if a finding represents a remote-access pathway (RDP/VPN/SSH/SMB...)."""
    cfg = cfg or get_day1_blueprint()
    ra = cfg.get("remote_access_services", {})
    services = {str(s).lower() for s in ra.get("services", [])}
    ports    = {int(p) for p in ra.get("ports", [])}
    svc = (finding.service or "").lower()
    if svc and svc in services:
        return True
    if finding.port is not None and int(finding.port) in ports:
        return True
    return False


def _finding_context(finding, cfg: dict) -> dict:
    """Build the attribute dict used for rule / criterion matching."""
    return {
        "exposure":         _enum_val(finding.exposure),
        "exploit_status":   _enum_val(finding.exploit_status),
        "deal_tier":        _enum_val(finding.deal_tier),
        "data_sensitivity": _enum_val(finding.data_sensitivity),
        "service":          (finding.service or "").lower(),
        "remote_access":    is_remote_access(finding, cfg),
    }


def _matches(when: dict, ctx: dict) -> bool:
    """All keys in `when` must equal the context (bools and strings)."""
    for key, expected in when.items():
        actual = ctx.get(key)
        if isinstance(expected, bool):
            if bool(actual) != expected:
                return False
        else:
            if str(actual).lower() != str(expected).lower():
                return False
    return True


# ── Phase assignment + roadmap ────────────────────────────────────────────────

def assign_phase(finding, cfg: Optional[dict] = None) -> str:
    """Map a finding to a Day-1 phase using the ordered phase_rules (first match)."""
    cfg = cfg or get_day1_blueprint()
    ctx = _finding_context(finding, cfg)
    for rule in cfg.get("phase_rules", []):
        if _matches(rule.get("when", {}), ctx):
            return rule.get("phase", Day1Phase.P3_INTEGRATE_READY.value)
    return Day1Phase.P3_INTEGRATE_READY.value


def _phase_rationale(finding, cfg: dict) -> str:
    """Short explanation of why a finding landed in its phase."""
    ctx = _finding_context(finding, cfg)
    if ctx["exploit_status"] == "active_exploitation":
        return "Actively exploited in the wild — active-compromise risk before any link."
    if ctx["deal_tier"] == "deal_killer":
        return "Deal-killer finding — must be resolved or mitigated before connecting."
    if ctx["exposure"] == "internet_facing" and ctx["remote_access"]:
        return "Internet-facing remote access — the leading Day-1 ransomware entry vector."
    if ctx["exposure"] == "internet_facing" and ctx["exploit_status"] == "public_exploit":
        return "Public exploit on an internet-facing service — reachable and weaponised."
    if ctx["exposure"] == "internet_facing":
        return "Internet-facing exposure — firewall and inspect before trusting the perimeter."
    if ctx["exposure"] == "partner" and ctx["remote_access"]:
        return "Partner-exposed remote access — move behind ZTNA at cutover."
    if ctx["deal_tier"] == "critical":
        return "Critical-tier finding — stabilise within the first 30 days."
    if ctx["exposure"] == "partner":
        return "Partner-exposed service — review in the first 30 days."
    return "Internal hygiene — address while moving toward full integration."


def build_roadmap(findings: list, gap_report=None, cfg: Optional[dict] = None) -> dict:
    """
    Assign every finding and maturity gap to a phase. Returns
    {phase_value: [Day1ActionItem, ...]} with items sorted by risk_score desc
    within each phase — the literal 'fix-first' ordered list.
    """
    cfg = cfg or get_day1_blueprint()
    roadmap: dict[str, list[Day1ActionItem]] = {ph.value: [] for ph in Day1Phase}

    for f in findings:
        phase = assign_phase(f, cfg)
        roadmap[phase].append(Day1ActionItem(
            phase=phase,
            title=f.title,
            source="finding",
            risk_score=float(getattr(f, "risk_score", 0.0)),
            deal_tier=_enum_val(f.deal_tier),
            rationale=_phase_rationale(f, cfg),
            host=getattr(f, "host", None),
            service=getattr(f, "service", None),
            remediation=getattr(f, "remediation", "") or "",
        ))

    # Fold in maturity gaps
    if gap_report is not None:
        gap_phase_map = cfg.get("maturity_gap_phase", {})
        for gap in getattr(gap_report, "gaps", []):
            sev = _enum_val(gap.gap_severity)
            phase = gap_phase_map.get(sev, Day1Phase.P3_INTEGRATE_READY.value)
            roadmap[phase].append(Day1ActionItem(
                phase=phase,
                title=f"Maturity gap: {gap.label} (score {gap.current_score:.1f}/need {gap.acceptable_min})",
                source="maturity",
                # Scale 0-5 maturity gap onto the 0-100 risk axis for sorting
                risk_score=round(min(5.0, gap.gap_to_acceptable) / 5.0 * 100, 1),
                deal_tier="deal_killer" if gap.is_deal_blocker else "moderate",
                rationale=gap.rationale or "Below the corporate acquisition standard.",
                remediation=f"Raise {gap.label} maturity to at least level {gap.acceptable_min}.",
            ))

    for phase in roadmap:
        roadmap[phase].sort(key=lambda it: it.risk_score, reverse=True)

    return roadmap


# ── Pillars ───────────────────────────────────────────────────────────────────

_SEVERITY_TO_STATUS = {
    "deal_blocker": PillarStatus.RED,
    "below_min":    PillarStatus.AMBER,
    "acceptable":   PillarStatus.AMBER,
    "at_target":    PillarStatus.GREEN,
}


def _domain_score(assessment, domain_key: str):
    """Return the DomainScore for a domain, or None."""
    if assessment is None:
        return None
    for ds in getattr(assessment, "domain_scores", []):
        if ds.domain == domain_key and ds.answered > 0:
            return ds
    return None


def _worst_status(*statuses: PillarStatus) -> PillarStatus:
    order = [PillarStatus.RED, PillarStatus.AMBER, PillarStatus.GREEN, PillarStatus.UNKNOWN]
    known = [s for s in statuses if s != PillarStatus.UNKNOWN]
    if not known:
        return PillarStatus.UNKNOWN
    for s in order:
        if s in known:
            return s
    return PillarStatus.UNKNOWN


def build_pillars(findings: list, assessment=None, cfg: Optional[dict] = None) -> list[Pillar]:
    """Build the three Review pillars with RAG status + evidence + recommendation."""
    cfg = cfg or get_day1_blueprint()
    pillars: list[Pillar] = []

    # Pre-compute finding signals
    ra_findings   = [f for f in findings if is_remote_access(f, cfg)]
    inet_ra       = [f for f in ra_findings if _enum_val(f.exposure) == "internet_facing"]
    partner_ra    = [f for f in ra_findings if _enum_val(f.exposure) == "partner"]
    inet_findings = [f for f in findings if _enum_val(f.exposure) == "internet_facing"]

    for pcfg in cfg.get("pillars", []):
        key   = pcfg["key"]
        label = pcfg["label"]
        domain = pcfg.get("maturity_domain")
        evidence: list[str] = []

        # Maturity-derived status (identity / network pillars)
        mat_status = PillarStatus.UNKNOWN
        if domain:
            ds = _domain_score(assessment, domain)
            if ds is not None:
                mat_status = _SEVERITY_TO_STATUS.get(_enum_val(ds.gap_severity), PillarStatus.UNKNOWN)
                evidence.append(
                    f"{ds.label} maturity {ds.score:.1f}/5 "
                    f"(min {ds.acceptable_min}, target {ds.recommended})"
                )

        # Finding-derived status, per pillar
        find_status = PillarStatus.UNKNOWN
        if key == "remote_access_pathways":
            if inet_ra:
                find_status = PillarStatus.RED
                evidence.append(
                    f"{len(inet_ra)} internet-facing remote-access pathway(s): "
                    + ", ".join(sorted({f"{(f.service or 'svc')}:{f.port}" for f in inet_ra}))
                )
            elif partner_ra:
                find_status = PillarStatus.AMBER
                evidence.append(f"{len(partner_ra)} partner-exposed remote-access pathway(s)")
            elif findings:
                find_status = PillarStatus.GREEN
                evidence.append("No internet-facing remote-access services detected")
        elif key == "network_boundaries":
            dk_inet = [f for f in inet_findings
                       if _enum_val(f.deal_tier) == "deal_killer"
                       or _enum_val(f.exploit_status) == "active_exploitation"]
            if dk_inet:
                find_status = PillarStatus.RED
                evidence.append(f"{len(dk_inet)} internet-facing deal-killer / actively-exploited finding(s)")
            elif inet_findings:
                find_status = PillarStatus.AMBER
                evidence.append(f"{len(inet_findings)} internet-facing service(s) on the perimeter")
            elif findings:
                find_status = PillarStatus.GREEN
                evidence.append("No internet-facing services detected")

        status = _worst_status(mat_status, find_status)

        # Recommendation keyed off the final status
        rec_key = {
            PillarStatus.GREEN:   "recommendation_green",
            PillarStatus.AMBER:   "recommendation_amber",
            PillarStatus.RED:     "recommendation_red",
            PillarStatus.UNKNOWN: "recommendation_unknown",
        }[status]
        recommendation = pcfg.get(rec_key, "")

        headline = {
            PillarStatus.GREEN:   "Ready",
            PillarStatus.AMBER:   "Needs work",
            PillarStatus.RED:     "Blocker",
            PillarStatus.UNKNOWN: "Not assessed",
        }[status]

        if not evidence:
            evidence.append("No data — run a scan and the Maturity Assessment.")

        pillars.append(Pillar(
            key=key, label=label, status=status,
            headline=headline, evidence=evidence, recommendation=recommendation,
        ))

    return pillars


# ── Tier gates ────────────────────────────────────────────────────────────────

_LEVEL_KEYS = {"acceptable_min", "recommended", "deal_blocker"}


def _eval_criterion(crit: dict, findings: list, assessment, cfg: dict) -> CriterionResult:
    label = crit.get("label", "")
    ctype = crit.get("type")

    if ctype == "no_finding":
        when = crit.get("when", {})
        matched = [f for f in findings if _matches(when, _finding_context(f, cfg))]
        if matched:
            sample = ", ".join(sorted({
                f"{f.title[:40]}" for f in matched[:3]
            }))
            return CriterionResult(label=label, passed=False,
                                   detail=f"{len(matched)} finding(s): {sample}")
        return CriterionResult(label=label, passed=True, detail="None present")

    if ctype == "maturity_min":
        domain = crit.get("domain")
        level_key = crit.get("level", "acceptable_min")
        ds = _domain_score(assessment, domain)
        if ds is None:
            return CriterionResult(label=label, passed=False, detail="Not assessed")
        std = get_domain_standard(domain)
        threshold = float(std.get(level_key, 2))
        if ds.score >= threshold:
            return CriterionResult(label=label, passed=True,
                                   detail=f"{ds.score:.1f} >= {threshold:.0f}")
        return CriterionResult(label=label, passed=False,
                               detail=f"{ds.score:.1f} < {threshold:.0f}")

    # Unknown criterion type — treat as informational pass
    return CriterionResult(label=label, passed=True, detail="")


def build_gates(findings: list, assessment=None, cfg: Optional[dict] = None) -> list[IntegrationGate]:
    """Evaluate the entry gate for each connectivity tier."""
    cfg = cfg or get_day1_blueprint()
    gates_cfg = cfg.get("tier_gates", {})
    model_labels = {m["key"]: m["label"] for m in cfg.get("connectivity_models", [])}

    gates: list[IntegrationGate] = []
    for model_key in ["isolate", "broker", "federate", "integrate"]:
        crits_cfg = gates_cfg.get(model_key, {}).get("criteria", [])
        results = [_eval_criterion(c, findings, assessment, cfg) for c in crits_cfg]
        passed = all(r.passed for r in results)
        gates.append(IntegrationGate(
            model=model_key,
            label=model_labels.get(model_key, model_key.title()),
            passed=passed,
            criteria=results,
        ))
    return gates


# ── Connectivity recommendation ───────────────────────────────────────────────

def recommend_connectivity(
    findings: list,
    assessment=None,
    gates: Optional[list[IntegrationGate]] = None,
    cfg: Optional[dict] = None,
) -> tuple[str, str, str]:
    """
    Recommend the HIGHEST connectivity tier whose entry gate passes — the most
    integrated posture the target's current state safely justifies.

    Returns (model_value, model_label, rationale).
    """
    cfg = cfg or get_day1_blueprint()
    gates = gates if gates is not None else build_gates(findings, assessment, cfg)
    models = {m["key"]: m for m in cfg.get("connectivity_models", [])}
    gate_by_model = {g.model: g for g in gates}

    # No scan data at all -> stay isolated.
    if not findings:
        m = models.get("isolate", {})
        return (
            ConnectivityModel.ISOLATE.value,
            m.get("label", "Isolate"),
            "No scan data available — remain fully isolated until the target is "
            "scanned and assessed.",
        )

    order = ["integrate", "federate", "broker", "isolate"]
    chosen = "isolate"
    for model_key in order:
        g = gate_by_model.get(model_key)
        if model_key == "isolate" or (g is not None and g.passed):
            chosen = model_key
            break

    m = models.get(chosen, {})
    label = m.get("label", chosen.title())
    summary = " ".join((m.get("summary") or "").split())

    # Explain how to advance to the next tier up (if any).
    next_up = {"isolate": "broker", "broker": "federate", "federate": "integrate"}.get(chosen)
    advance = ""
    if next_up:
        ng = gate_by_model.get(next_up)
        if ng is not None and ng.blocking:
            blockers = "; ".join(c.label for c in ng.blocking)
            advance = f" To advance to {models.get(next_up, {}).get('label', next_up)}: {blockers}."

    rationale = f"{summary}{advance}"
    return chosen, label, rationale


# ── Orchestrator ──────────────────────────────────────────────────────────────

def build_day1_blueprint(
    findings: list,
    assessment=None,
    gap_report=None,
    target: str = "",
) -> Day1Blueprint:
    """
    Top-level orchestrator. Degrades gracefully: with findings only (no maturity
    questionnaire filled) it still produces posture + roadmap + the remote-access
    pillar, marking identity/network pillars 'not assessed'.
    """
    cfg = get_day1_blueprint()

    pillars  = build_pillars(findings, assessment, cfg)
    gates    = build_gates(findings, assessment, cfg)
    model, label, rationale = recommend_connectivity(findings, assessment, gates, cfg)
    roadmap  = build_roadmap(findings, gap_report, cfg)

    # Annotate the catalog with the recommended flag for display.
    catalog = []
    for m in cfg.get("connectivity_models", []):
        entry = dict(m)
        entry["recommended"] = (m["key"] == model)
        catalog.append(entry)

    return Day1Blueprint(
        target=target,
        recommended_model=model,
        recommended_label=label,
        recommendation_rationale=rationale,
        model_catalog=catalog,
        pillars=pillars,
        gates=gates,
        roadmap=roadmap,
        phase_meta=cfg.get("phases", []),
        has_maturity=assessment is not None,
    )
