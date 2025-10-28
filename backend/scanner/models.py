from pydantic import BaseModel, Field, ConfigDict
from typing import Any
import boto3
from enum import StrEnum
from datetime import datetime, timezone
from scanner.mitre_map import Vulnerability


class VulnerabilityFinding(BaseModel):
    type: Vulnerability
    name: str
    severity: str
    details: str


class ScanRequest(BaseModel):
    bucket: str = None
    file: str = None
    services: dict[str, list[str]] = {}


class ReportFormat(StrEnum):
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"


class GenerateReportRequest(BaseModel):
    scan_id: str
    format: ReportFormat = ReportFormat.PDF


class GenerateReportResponse(BaseModel):
    report_url: str


class ValidateRequest(BaseModel):
    access_key: str
    secret_key: str
    region: str


class ValidateResponse(BaseModel):
    valid: bool


class AwsCredentials(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    access_key: str
    secret_key: str
    region: str = "us-east-1"
    session: boto3.Session


class GetScanResponse(BaseModel):
    findings: list[VulnerabilityFinding] = Field(default_factory=list)


class ScanResponse(BaseModel):
    scan_id: str
    findings: list[VulnerabilityFinding] = Field(default_factory=list)


class ScanItem(BaseModel):
    scan_id: str
    access_key: str
    selected_scans: list[list[str]]
    findings: list[dict[str, Any]] = Field(default_factory=list)
    completed_at: datetime | None = None
    created_at: datetime


class ListScansResponse(BaseModel):
    scans: list[ScanItem]


class BucketsResponse(BaseModel):
    buckets: list[str]


class FilesResponse(BaseModel):
    files: list[str]
