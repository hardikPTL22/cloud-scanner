from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Any
from typing import Union, List
import boto3
from enum import StrEnum
from datetime import datetime


class VulnerabilityFinding(BaseModel):
    type: str
    name: str
    severity: str
    details: str = ""
    service: str = "unknown"
    mitre_id: str = ""
    mitre_name: str = ""
    description: str = ""
    remediation: str = ""


class FileScanFinding(BaseModel):
    file_key: str
    file_name: str
    severity: str
    status: str
    malicious_count: int
    suspicious_count: int
    undetected_count: int
    harmless_count: int
    total_vendors: int
    scan_date: str
    permalink: str
    file_size: int
    file_type: str
    md5: str
    sha256: str
    detected_engines: Optional[List[str]] = []
    details: str = ""


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
    findings: List[Union[VulnerabilityFinding, FileScanFinding]] = Field(
        default_factory=list
    )


class ScanResponse(BaseModel):
    scan_id: str
    findings: list[VulnerabilityFinding] = Field(default_factory=list)


class ScanItem(BaseModel):
    scan_id: str
    access_key: str
    scan_type: str = "service"
    selected_scans: Optional[list[str]] = None
    bucket: Optional[str] = None
    findings: Optional[list[dict[str, Any]]] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    metadata: Optional[dict[str, Any]] = None

    @property
    def is_service_scan(self) -> bool:
        return self.scan_type == "service"

    @property
    def is_file_scan(self) -> bool:
        return self.scan_type == "file"

    @property
    def scan_label(self) -> str:
        if self.is_service_scan:
            service_count = len(self.selected_scans) if self.selected_scans else 0
            return f"☁️ Cloud Service ({service_count} services)"
        else:
            file_count = self.metadata.get("file_count", 0) if self.metadata else 0
            return f"📁 File Scan ({file_count} files)"


class ListScansResponse(BaseModel):
    scans: list[ScanItem]


class BucketsResponse(BaseModel):
    buckets: list[str]


class FilesResponse(BaseModel):
    files: list[str]


class FileItem(BaseModel):
    key: str
    name: str
    type: str
    size: Optional[int] = None
    lastModified: Optional[str] = None
    children: Optional[list["FileItem"]] = None
    isExpanded: Optional[bool] = False


class ListFilesRequest(BaseModel):
    service: str
    location: str


class ListFilesResponse(BaseModel):
    files: list[FileItem]


class ScanFilesRequest(BaseModel):
    service: str
    location: str
    files: list[str]


class ScanFilesResponse(BaseModel):
    scan_id: str
    findings: list[FileScanFinding]
