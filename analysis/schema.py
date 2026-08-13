"""
analysis/schema.py — the Finding model and every enum. Single source of truth.

Everything in RedFlag is an operation on a Finding: created by a scanner,
improved by a correlation merge, scored by triage, sequenced by the Day-1
engine, priced by the cost engine, narrated, exported, and remembered by the
brain. This module is the vocabulary the whole codebase shares.

CAREFUL — `use_enum_values=True` means an enum-typed field on a Finding INSTANCE
holds the plain string ("internet_facing"), not the enum member. But
analysis/triage.py assigns enum OBJECTS to deal_tier. The codebase therefore
normalises everywhere with:

    def _v(x) -> str:
        return str(getattr(x, "value", x))

Never use str(x) — on an enum member it yields "DealTier.CRITICAL", which
silently fails every comparison and dict lookup.
"""
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional
from enum import Enum
from datetime import datetime, timezone
import uuid


class ExposureLevel(str, Enum):
    INTERNET_FACING = "internet_facing"
    PARTNER = "partner"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


class DataSensitivity(str, Enum):
    CROWN_JEWEL = "crown_jewel"
    REGULATED = "regulated"
    SENSITIVE = "sensitive"
    LOW = "low"
    UNKNOWN = "unknown"


class ExploitStatus(str, Enum):
    ACTIVE_EXPLOITATION = "active_exploitation"
    PUBLIC_EXPLOIT = "public_exploit"
    NO_EXPLOIT = "no_exploit"
    UNKNOWN = "unknown"


class DealTier(str, Enum):
    DEAL_KILLER = "deal_killer"
    CRITICAL = "critical"
    MODERATE = "moderate"
    MANAGEABLE = "manageable"
    UNSCORED = "unscored"


class ScannerSource(str, Enum):
    NMAP = "nmap"
    SHODAN = "shodan"
    OPENVAS = "openvas"
    ZAP = "zap"
    NUCLEI = "nuclei"
    VULNERS = "vulners"
    DNS = "dns"
    TLS = "tls"
    BREACH = "breach"
    PDF = "pdf_upload"
    EXCEL = "excel_upload"
    EMAIL = "email_attachment"
    MANUAL = "manual"


class EvidenceStrength(str, Enum):
    CONFIRMED = "confirmed"
    CORRELATED = "correlated"
    INFERRED = "inferred"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    cve_id: Optional[str] = None
    title: str

    host: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    # EPSS (FIRST.org Exploit Prediction Scoring System), 0.0–1.0 when known.
    epss_score: Optional[float] = None       # probability of exploitation in next 30 days
    epss_percentile: Optional[float] = None  # rank vs all CVEs (0.0–1.0)
    description: str = ""
    remediation: str = ""

    exposure: ExposureLevel = ExposureLevel.UNKNOWN
    data_sensitivity: DataSensitivity = DataSensitivity.UNKNOWN
    exploit_status: ExploitStatus = ExploitStatus.UNKNOWN

    scanner_source: ScannerSource = ScannerSource.MANUAL
    evidence_strength: EvidenceStrength = EvidenceStrength.UNKNOWN
    raw_data: Optional[dict] = None

    risk_score: float = 0.0
    deal_tier: DealTier = DealTier.UNSCORED
    override_reason: Optional[str] = None

    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(use_enum_values=True)