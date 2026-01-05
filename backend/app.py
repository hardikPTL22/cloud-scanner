from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from scanner.grc.trend import build_grc_trend
import boto3
import os
import logging

from scanner.file_scanner import scan_s3_files, build_file_tree
from scanner.grc.compliance_engine import build_compliance
from scanner.grc.control_mapper import map_control
from scanner.grc.risk_scoring import calculate_risk_score
from scanner.grc.control_effectiveness import calculate_control_effectiveness
from scanner.grc.evidence_collector import collect_evidence
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
    """Enhanced GRC dashboard with risk scoring, control effectiveness, and evidence collection"""
    scan = get_scan(scan_id)

    if not scan or scan["aws_access_key"] != creds.access_key:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = scan.get("findings", [])

    logger.info(f"Total findings: {len(findings)}")
    if findings:
        finding_types = [f.get("type") for f in findings[:5]]
        logger.info(f"Sample finding types: {finding_types}")

    enhanced_findings = []
    unmapped_count = 0

    for finding in findings:
        try:
            risk_score = calculate_risk_score(finding)
            enhanced_finding = {**finding, "risk_score": risk_score.model_dump()}
            enhanced_findings.append(enhanced_finding)
        except Exception as e:
            logger.warning(f"Failed to calculate risk score for finding: {e}")
            enhanced_findings.append(finding)

    compliance = build_compliance(enhanced_findings)

    try:
        effectiveness = calculate_control_effectiveness(creds.access_key, days=30)
    except Exception as e:
        logger.warning(f"Failed to calculate control effectiveness: {e}")
        effectiveness = None

    non_compliant_controls = []
    control_findings_map = {}

    for finding in enhanced_findings:
        finding_type = finding.get("type")

        if not finding_type:
            continue

        mapping = map_control(finding_type.upper())

        if not mapping:
            unmapped_count += 1
            logger.warning(f"No mapping found for: {finding_type}")
            continue

        severity = finding.get("severity", "unknown").lower()

        if severity not in ["high", "critical"]:
            continue

        for fw, controls in mapping.items():
            for ctrl in controls:
                control_key = f"{fw}:{ctrl}"

                if control_key not in control_findings_map:
                    control_findings_map[control_key] = {
                        "control_id": ctrl,
                        "framework": fw,
                        "title": finding.get("name", "Unknown"),
                        "service": finding.get("service", "unknown"),
                        "severity": severity,
                        "risk_score": finding.get("risk_score"),
                        "resource_ids": [],
                        "finding_types": set(),
                        "finding_count": 0,
                    }

                control_findings_map[control_key]["finding_count"] += 1
                control_findings_map[control_key]["finding_types"].add(finding_type)

                resource_id = finding.get("resource_id") or finding.get(
                    "details", "N/A"
                )
                if resource_id not in control_findings_map[control_key]["resource_ids"]:
                    control_findings_map[control_key]["resource_ids"].append(
                        resource_id
                    )

                severities = ["critical", "high", "medium", "low", "informational"]
                current_severity = control_findings_map[control_key]["severity"]
                if severities.index(severity) < severities.index(current_severity):
                    control_findings_map[control_key]["severity"] = severity
                    control_findings_map[control_key]["risk_score"] = finding.get(
                        "risk_score"
                    )

    for control_data in control_findings_map.values():
        control_data["finding_types"] = list(control_data["finding_types"])
        non_compliant_controls.append(control_data)

    non_compliant_controls.sort(
        key=lambda x: (
            x.get("risk_score", {}).get("score", 0) if x.get("risk_score") else 0
        ),
        reverse=True,
    )

    logger.info(f"Unmapped findings: {unmapped_count}/{len(findings)}")
    logger.info(f"Non-compliant controls found: {len(non_compliant_controls)}")
    if non_compliant_controls:
        logger.info(f"Sample control: {non_compliant_controls[0]['control_id']}")

    risk_distribution = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }

    for finding in enhanced_findings:
        risk_level = (
            finding.get("risk_score", {}).get("level", "low")
            if finding.get("risk_score")
            else finding.get("severity", "low")
        )
        if risk_level in risk_distribution:
            risk_distribution[risk_level] += 1

    total_risk_score = sum(
        f.get("risk_score", {}).get("score", 0)
        for f in enhanced_findings
        if f.get("risk_score")
    )

    return {
        "compliance_summary": compliance.model_dump(),
        "control_effectiveness": effectiveness,
        "non_compliant_controls": non_compliant_controls,
        "risk_distribution": risk_distribution,
        "total_risk_score": round(total_risk_score, 2),
        "average_risk_score": (
            round(total_risk_score / len(enhanced_findings), 2)
            if enhanced_findings
            else 0
        ),
        "findings_count": len(enhanced_findings),
        "controls_failed": len(non_compliant_controls),
    }


@app.get("/api/grc/trend")
async def get_grc_trend(
    creds: AwsCredentials = Depends(validate_aws_credentials), limit: int = 10
):
    """Fixed GRC trend analysis using proper compliance calculation"""
    try:
        trend_data = build_grc_trend(creds.access_key, limit=limit)
        return {"trend": trend_data}
    except Exception as e:
        logger.error(f"Failed to build GRC trend: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to generate compliance trend"
        )


@app.get("/api/grc/{scan_id}/evidence/{control_id}")
async def get_control_evidence(
    scan_id: str,
    control_id: str,
    creds: AwsCredentials = Depends(validate_aws_credentials),
):
    """Get automated evidence collection for a specific control"""
    scan = get_scan(scan_id)

    if not scan or scan["aws_access_key"] != creds.access_key:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        evidence = collect_evidence(scan_id, control_id)
        return evidence.model_dump()
    except Exception as e:
        logger.error(f"Failed to collect evidence for control {control_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to collect evidence")


@app.get("/api/grc/control-effectiveness")
async def get_control_effectiveness_metrics(
    creds: AwsCredentials = Depends(validate_aws_credentials), days: int = 30
):
    """Get control effectiveness KPIs over specified time period"""
    try:
        metrics = calculate_control_effectiveness(creds.access_key, days=days)
        if not metrics:
            return {
                "message": "Insufficient data for control effectiveness analysis",
                "metrics": None,
            }
        return {"metrics": metrics, "period_days": days}
    except Exception as e:
        logger.error(f"Failed to calculate control effectiveness: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to calculate control effectiveness"
        )


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
