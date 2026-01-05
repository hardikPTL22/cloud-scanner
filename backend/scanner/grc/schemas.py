from pydantic import BaseModel
from typing import Dict, List
from enum import Enum
from datetime import datetime


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class RiskScore(BaseModel):
    score: float  # 0-10 scale
    level: RiskLevel
    cvss_base: float
    impact_factor: float
    exploitability_factor: float


class FrameworkScore(BaseModel):
    total_controls: int
    compliant: int
    non_compliant: int
    compliance_percent: float


class ComplianceSummary(BaseModel):
    overall_compliance: float
    frameworks: Dict[str, FrameworkScore]
    control_status: Dict[str, int]


class NonCompliantControl(BaseModel):
    control_id: str
    title: str
    service: str
    severity: str
    frameworks: Dict[str, List[str]]
    risk_score: RiskScore
    resource_id: str
    finding_count: int = 1


class ControlEffectivenessMetrics(BaseModel):
    control_effectiveness_rating: float
    improvement_rate: float
    total_controls: int
    effective_controls: int
    failed_controls: int


class ComplianceEvidence(BaseModel):
    control_id: str
    scan_id: str
    status: str
    evidence_artifacts: List[Dict]
    collected_at: datetime
    auditor_notes: str
    attestation_required: bool
