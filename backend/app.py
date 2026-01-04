from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from scanner.grc.trend import build_grc_trend
import boto3
import os
import logging

from scanner.file_scanner import scan_s3_files, build_file_tree
from scanner.grc.compliance_engine import build_compliance
from scanner import run_scans
from scanner.db import create_scan, update_scan, list_scans, get_scan
from scanner.models import (
    ScanRequest,
    ScanResponse,
    ListScansResponse,
    AwsCredentials,
    BucketsResponse,
    ListFilesRequest,
    ListFilesResponse,
    ScanFilesRequest,
    ScanFilesResponse,
    FileScanFinding,
    ValidateRequest,
    ValidateResponse,
    ReportFormat,
    GetScanResponse,
)

from scanner.reports.service_scan.report import (
    generate_report_url as generate_service_report_url,
    get_report_details as get_service_report_details,
)
from scanner.reports.service_scan.report_generator import (
    generate_pdf_report as generate_service_pdf,
    write_json as write_service_json,
    write_csv as write_service_csv,
)

from scanner.reports.file_scan.report import (
    generate_report_url as generate_file_report_url,
    get_report_details as get_file_report_details,
)
from scanner.reports.file_scan.report_generator import (
    generate_pdf_report as generate_file_pdf,
    write_json as write_file_json,
    write_csv as write_file_csv,
)

logger = logging.getLogger(__name__)

app = FastAPI(docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def validate_aws_credentials(request: Request) -> AwsCredentials:
    if request.method == "OPTIONS":
        return

    access_key = request.headers.get("X-AWS-Access-Key")
    secret_key = request.headers.get("X-AWS-Secret-Key")
    region = request.headers.get("X-AWS-Region", "us-east-1")

    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )
        session.client("sts").get_caller_identity()
        return AwsCredentials(
            access_key=access_key,
            secret_key=secret_key,
            region=region,
            session=session,
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid AWS credentials")


@app.post("/api/scan", response_model=ScanResponse)
async def scan(
    data: ScanRequest,
    creds: AwsCredentials = Depends(validate_aws_credentials),
):
    selected_services = list(data.services.keys())
    total_checks = sum(len(v) for v in data.services.values())

    scan_id = create_scan(
        aws_access_key=creds.access_key,
        scans=selected_services,
        scan_type="service",
        metadata={
            "service_count": len(selected_services),
            "total_checks": total_checks,
            "services": selected_services,
        },
    )

    findings = run_scans(
        data.services,
        access_key=creds.access_key,
        secret_key=creds.secret_key,
        region=creds.region,
    )

    update_scan(scan_id, findings, completed=True)
    return ScanResponse(scan_id=scan_id, findings=findings)


@app.get("/api/scans", response_model=ListScansResponse)
async def get_scans(creds: AwsCredentials = Depends(validate_aws_credentials)):
    return ListScansResponse(scans=list_scans(creds.access_key))


@app.get("/api/scans/{scan_id}")
async def get_scan_details(
    scan_id: str,
    creds: AwsCredentials = Depends(validate_aws_credentials),
):
    scan = get_scan(scan_id)

    if not scan or scan["aws_access_key"] != creds.access_key:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.get("scan_type") == "file":
        return ScanFilesResponse(scan_id=scan_id, findings=scan.get("findings", []))

    return GetScanResponse(findings=scan.get("findings", []))


@app.get("/api/grc/{scan_id}")
async def get_grc_dashboard(
    scan_id: str,
    creds: AwsCredentials = Depends(validate_aws_credentials),
):
    scan = get_scan(scan_id)

    if not scan or scan["aws_access_key"] != creds.access_key:
        raise HTTPException(status_code=404, detail="Scan not found")

    compliance = build_compliance(scan.get("findings", []))

    return compliance


@app.get("/api/grc/trend")
async def get_grc_trend(
    creds: AwsCredentials = Depends(validate_aws_credentials),
):
    scans = list_scans(creds.access_key)

    trend = []

    for scan in scans:
        if scan.get("scan_type") != "service":
            continue

        findings = scan.get("findings") or []
        if not findings:
            continue

        compliant = len([f for f in findings if f.get("severity") in ("low", "medium")])
        total = len(findings)

        compliance_percentage = round((compliant / total) * 100) if total else 100

        trend.append(
            {
                "scan_id": scan["scan_id"],
                "date": scan["created_at"],
                "compliance_percentage": compliance_percentage,
            }
        )

    return {"trend": trend}


@app.get("/api/reports/service/{token}", include_in_schema=False)
async def generate_service_report(token: str):
    scan_id, fmt = get_service_report_details(token) or (None, None)
    if not scan_id:
        raise HTTPException(status_code=404)

    findings = get_scan(scan_id)["findings"]
    fmt = ReportFormat(fmt)

    if fmt == ReportFormat.PDF:
        path = generate_service_pdf(findings)
    elif fmt == ReportFormat.JSON:
        path = write_service_json(findings)
    else:
        path = write_service_csv(findings)

    return FileResponse(path, filename=os.path.basename(path))


@app.get("/api/reports/file/{token}", include_in_schema=False)
async def generate_file_report(token: str):
    scan_id, fmt = get_file_report_details(token) or (None, None)
    if not scan_id:
        raise HTTPException(status_code=404)

    findings = get_scan(scan_id)["findings"]
    fmt = ReportFormat(fmt)

    if fmt == ReportFormat.PDF:
        path = generate_file_pdf(findings)
    elif fmt == ReportFormat.JSON:
        path = write_file_json(findings)
    else:
        path = write_file_csv(findings)

    return FileResponse(path, filename=os.path.basename(path))


@app.get("/api/buckets", response_model=BucketsResponse)
async def list_buckets(creds: AwsCredentials = Depends(validate_aws_credentials)):
    s3 = creds.session.client("s3")
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    return BucketsResponse(buckets=buckets)


@app.post("/api/files/list", response_model=ListFilesResponse)
async def list_files_hierarchical(
    data: ListFilesRequest,
    creds: AwsCredentials = Depends(validate_aws_credentials),
):
    if data.service != "s3":
        raise HTTPException(status_code=501)

    s3 = creds.session.client("s3")
    paginator = s3.get_paginator("list_objects_v2")

    objects = []
    for page in paginator.paginate(Bucket=data.location):
        objects.extend(page.get("Contents", []))

    return ListFilesResponse(files=build_file_tree(objects))


@app.post("/api/files/scan", response_model=ScanFilesResponse)
async def scan_files_endpoint(
    data: ScanFilesRequest,
    creds: AwsCredentials = Depends(validate_aws_credentials),
):
    scan_id = create_scan(
        aws_access_key=creds.access_key,
        scan_type="file",
        bucket=data.location,
        metadata={"file_count": len(data.files)},
    )

    results = await scan_s3_files(creds.session, data.location, data.files)

    findings = [
        FileScanFinding(**r)
        for r in results
        if r.get("status") not in ["error", "timeout"]
    ]

    update_scan(scan_id, findings, completed=True)
    return ScanFilesResponse(scan_id=scan_id, findings=findings)


@app.post("/api/validate", response_model=ValidateResponse)
async def validate_credentials(data: ValidateRequest):
    try:
        boto3.Session(
            aws_access_key_id=data.access_key,
            aws_secret_access_key=data.secret_key,
            region_name=data.region,
        ).client("sts").get_caller_identity()
        return ValidateResponse(valid=True)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid AWS credentials")
