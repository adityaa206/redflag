"""
cost/schema.py — Pydantic models and enums for the cost & debt modelling engine.

All monetary values are in USD.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


# ── Enums ─────────────────────────────────────────────────────────────────────

class RemediationCategory(str, Enum):
    """High-level category of the remediation work."""
    PATCHING          = "patching"           # OS / software updates
    CONFIGURATION     = "configuration"      # Hardening, firewall, ACL changes
    ARCHITECTURE      = "architecture"       # Network re-segmentation, redesign
    TOOLING           = "tooling"            # Deploy / licence a security tool
    PROCESS           = "process"            # Policy, training, procedure
    INCIDENT_RESPONSE = "incident_response"  # IR retainer / tabletop exercises
    COMPLIANCE        = "compliance"         # Audit, certification, pen-test
    CREDENTIAL        = "credential"         # Password rotation, MFA rollout
    DATA_PROTECTION   = "data_protection"    # Encryption, DLP, backup
    MONITORING        = "monitoring"         # SIEM, logging, alerting
    INTEGRATION       = "integration"        # Day-1 connectivity / integration standup


class CapexOpex(str, Enum):
    """Capital expenditure vs operating expenditure classification."""
    CAPEX = "capex"  # One-time investment (tools, infrastructure, architecture)
    OPEX  = "opex"   # Recurring cost (labour, subscriptions, retainers)
    MIXED = "mixed"  # Combination — split defined per line item


class CostConfidence(str, Enum):
    """Confidence level of the cost estimate."""
    HIGH   = "high"    # Based on vendor quotes or known fixed pricing
    MEDIUM = "medium"  # Based on industry benchmarks (default)
    LOW    = "low"     # Rough order-of-magnitude only


class ScenarioType(str, Enum):
    """Scenario variant for sensitivity analysis."""
    LOW  = "low"   # Best-case: minimal scope, in-house labour
    BASE = "base"  # Most-likely: benchmark rates, standard scope
    HIGH = "high"  # Worst-case: consultant rates, full scope, overtime


class ReviewFlag(str, Enum):
    """Reason an item was flagged for human review before export."""
    HIGH_VARIANCE     = "high_variance"      # high/low spread > 3× base
    ZERO_ESTIMATE     = "zero_estimate"      # Could not find catalog match
    DUPLICATE         = "duplicate"          # Merged from multiple findings
    DEAL_KILLER_ITEM  = "deal_killer_item"   # Linked to a deal-killer finding
    MANUAL_REQUIRED   = "manual_required"    # Requires human judgement


# ── Core value objects ────────────────────────────────────────────────────────

class CostTriple(BaseModel):
    """Low / base / high cost triple (always shown together, never a single number)."""
    low:  float = Field(ge=0.0, description="Best-case cost in USD")
    base: float = Field(ge=0.0, description="Most-likely cost in USD")
    high: float = Field(ge=0.0, description="Worst-case cost in USD")

    model_config = ConfigDict(frozen=True)

    def total(self, scenario: ScenarioType = ScenarioType.BASE) -> float:
        return {"low": self.low, "base": self.base, "high": self.high}[scenario]

    def spread_ratio(self) -> float:
        """high/low ratio; used to detect high-variance estimates."""
        return (self.high / self.low) if self.low > 0 else float("inf")

    def __add__(self, other: "CostTriple") -> "CostTriple":
        return CostTriple(
            low=self.low   + other.low,
            base=self.base + other.base,
            high=self.high + other.high,
        )

    @classmethod
    def zero(cls) -> "CostTriple":
        return cls(low=0.0, base=0.0, high=0.0)

    def to_dict(self) -> dict:
        return {"low": self.low, "base": self.base, "high": self.high}


# ── Line items ────────────────────────────────────────────────────────────────

class CostLineItem(BaseModel):
    """A single remediation cost line item linked to one or more findings."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    # What it is
    title:       str
    description: str = ""
    category:    RemediationCategory
    capex_opex:  CapexOpex

    # Which budget this rolls into: "remediation" (fix findings/gaps) or
    # "integration" (Day-1 connectivity standup).
    bucket:      str = "remediation"

    # Linked findings (UUIDs from Finding.id)
    finding_ids: list[str] = Field(default_factory=list)

    # Cost
    cost:       CostTriple
    confidence: CostConfidence = CostConfidence.MEDIUM

    # Deduplication
    is_merged:   bool = False
    merged_from: list[str] = Field(default_factory=list)  # original line item IDs

    # Review gate
    review_flags: list[ReviewFlag] = Field(default_factory=list)

    # Metadata
    catalog_key:  Optional[str] = None   # key from remediation_catalog.yaml
    notes:        Optional[str] = None
    created_at:   datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(use_enum_values=True)

    @property
    def needs_review(self) -> bool:
        return len(self.review_flags) > 0


# ── Scenario ─────────────────────────────────────────────────────────────────

class CostScenario(BaseModel):
    """A named cost scenario (low / base / high) with line item totals."""
    scenario_type: ScenarioType
    total_usd:     float
    capex_usd:     float
    opex_usd:      float
    line_count:    int

    model_config = ConfigDict(use_enum_values=True)


# ── Rollup ────────────────────────────────────────────────────────────────────

class CostRollup(BaseModel):
    """Aggregated cost picture across all line items."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    target:      Optional[str] = None  # scan target for labelling
    line_items:  list[CostLineItem] = Field(default_factory=list)

    # Aggregated triples
    total:       CostTriple = Field(default_factory=CostTriple.zero)
    capex_total: CostTriple = Field(default_factory=CostTriple.zero)
    opex_total:  CostTriple = Field(default_factory=CostTriple.zero)

    # Bucket split: remediation (fix findings/gaps) vs integration (Day-1 standup)
    remediation_total: CostTriple = Field(default_factory=CostTriple.zero)
    integration_total: CostTriple = Field(default_factory=CostTriple.zero)

    # Estimate accuracy readout (surfaced in the UI). accuracy_band_pct is the ±%
    # around the base case; accuracy_pct = 100 - band (a confidence percentage).
    accuracy_band_pct: float = 0.0
    accuracy_pct:      float = 0.0

    # Per-scenario totals (populated by rollup engine)
    scenarios:   list[CostScenario] = Field(default_factory=list)

    # Per-category breakdown {category_value: CostTriple}
    by_category: dict[str, dict] = Field(default_factory=dict)

    # Review gate — must be acknowledged before export
    flagged_items:    list[str] = Field(default_factory=list)  # line item IDs
    review_acknowledged: bool   = False

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(use_enum_values=True)

    @property
    def has_flagged_items(self) -> bool:
        return len(self.flagged_items) > 0

    @property
    def export_blocked(self) -> bool:
        return self.has_flagged_items and not self.review_acknowledged
