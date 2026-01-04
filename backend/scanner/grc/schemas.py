from pydantic import BaseModel
from typing import Dict, List


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
