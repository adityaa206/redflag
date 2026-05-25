from pydantic import BaseModel, Field
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
    VULNERS = "vulners"
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

    class Config:
        use_enum_values = True