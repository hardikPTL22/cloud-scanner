from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import boto3
import os
import logging

logger = logging.getLogger(__name__)
from scanner.file_scanner import scan_s3_files, build_file_tree
from scanner import run_scans, generate_pdf_report, write_json, write_csv
from scanner.db import create_scan, update_scan, list_scans, get_scan
from scanner.models import (
    ScanRequest,
    ScanResponse,
    ListScansResponse,
    GenerateReportRequest,
    GenerateReportResponse,
    AwsCredentials,
    BucketsResponse,
    FilesResponse,
    ValidateResponse,
    ValidateRequest,
    ReportFormat,
    GetScanResponse,
    ListFilesRequest,
    ListFilesResponse,
    ScanFilesRequest,
    ScanFilesResponse,
    FileScanFinding,
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


app = FastAPI(
    docs_url=None,
    redoc_url=None,
)


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
        sts_client = session.client("sts")
        sts_client.get_caller_identity()
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
    data: ScanRequest, creds: AwsCredentials = Depends(validate_aws_credentials)
):
    selected_services = list(data.services.keys())
    selected_scans = data.services

    total_checks = sum(len(checks) for checks in data.services.values())

    print(f"Selected services: {selected_services}")
    print(f"Total services: {len(selected_services)}")
    print(f"Total checks: {total_checks}")

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
        selected_scans,
        access_key=creds.access_key,
        secret_key=creds.secret_key,
        region=creds.region,
    )

    update_scan(scan_id, findings, True)

    return ScanResponse(scan_id=scan_id, findings=findings)


@app.get("/api/scans", response_model=ListScansResponse)
async def get_scans(creds: AwsCredentials = Depends(validate_aws_credentials)):
    scans = list_scans(creds.access_key)
    return ListScansResponse(scans=scans)


@app.get("/api/scans/{scan_id}", response_model=GetScanResponse)
async def get_scan_details(
    scan_id: str, creds: AwsCredentials = Depends(validate_aws_credentials)
):
    scan = get_scan(scan_id)

    if not scan or scan["aws_access_key"] != creds.access_key:
        raise HTTPException(status_code=404, detail="Scan not found")
    return GetScanResponse(findings=scan.get("findings", []))


@app.get("/api/reports/service/{token}", include_in_schema=False)
async def generate_service_report(token: str):
    scan_id, format_str = get_service_report_details(token) or (None, None)

    if not scan_id or not format_str:
        raise HTTPException(status_code=404, detail="Report not found or expired")

    findings = get_scan(scan_id).get("findings", [])
    format_type = ReportFormat(format_str)

    try:
        if format_type == ReportFormat.PDF:
            filepath = generate_service_pdf(findings)
        elif format_type == ReportFormat.JSON:
            filepath = write_service_json(findings)
        elif format_type == ReportFormat.CSV:
            filepath = write_service_csv(findings)
        else:
            raise HTTPException(status_code=400, detail="Unsupported format")

        return FileResponse(
            filepath,
            filename=os.path.basename(filepath),
            media_type="application/octet-stream",
        )
    except Exception as e:
        logger.error(f"Error generating service report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/reports/file/{token}", include_in_schema=False)
async def generate_file_report(token: str):
    scan_id, format_str = get_file_report_details(token) or (None, None)

    if not scan_id or not format_str:
        raise HTTPException(status_code=404, detail="Report not found or expired")

    findings = get_scan(scan_id).get("findings", [])
    format_type = ReportFormat(format_str)

    try:
        if format_type == ReportFormat.PDF:
            filepath = generate_file_pdf(findings)
        elif format_type == ReportFormat.JSON:
            filepath = write_file_json(findings)
        elif format_type == ReportFormat.CSV:
            filepath = write_file_csv(findings)
        else:
            raise HTTPException(status_code=400, detail="Unsupported format")

        return FileResponse(
            filepath,
            filename=os.path.basename(filepath),
            media_type="application/octet-stream",
        )
    except Exception as e:
        logger.error(f"Error generating file report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/generate-report", response_model=GenerateReportResponse)
async def generate_report(
    data: GenerateReportRequest,
    creds: AwsCredentials = Depends(validate_aws_credentials),
):
    report_url = generate_service_report_url(data.scan_id, data.format.value)
    return GenerateReportResponse(report_url=report_url)


@app.post("/api/generate-file-report", response_model=GenerateReportResponse)
async def generate_file_report_endpoint(
    data: GenerateReportRequest,
    creds: AwsCredentials = Depends(validate_aws_credentials),
):
    report_url = generate_file_report_url(data.scan_id, data.format.value)
    return GenerateReportResponse(report_url=report_url)


@app.get("/api/buckets", response_model=BucketsResponse)
async def list_buckets(creds: AwsCredentials = Depends(validate_aws_credentials)):
    try:
        s3_client = creds.session.client("s3")
        response = s3_client.list_buckets()
        bucket_names = [b["Name"] for b in response.get("Buckets", [])]
        return BucketsResponse(buckets=bucket_names)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/files", response_model=FilesResponse)
async def list_files(
    bucket: str = None, creds: AwsCredentials = Depends(validate_aws_credentials)
):
    if not bucket:
        raise HTTPException(status_code=400, detail="Bucket name is required")
    try:
        s3_client = creds.session.client("s3")
        response = s3_client.list_objects_v2(Bucket=bucket)
        file_names = [b["Key"] for b in response.get("Contents", [])]
        return FilesResponse(files=file_names)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/files/list", response_model=ListFilesResponse)
async def list_files_hierarchical(
    data: ListFilesRequest, creds: AwsCredentials = Depends(validate_aws_credentials)
):
    try:
        if data.service == "s3":
            s3_client = creds.session.client("s3")
            paginator = s3_client.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=data.location)

            all_objects = []
            for page in pages:
                if "Contents" in page:
                    all_objects.extend(page["Contents"])
            file_tree = build_file_tree(all_objects)

            return ListFilesResponse(files=file_tree)
        elif data.service == "efs":
            raise HTTPException(
                status_code=501, detail="EFS scanning not implemented yet"
            )
        elif data.service == "fsx":
            raise HTTPException(
                status_code=501, detail="FSx scanning not implemented yet"
            )
        else:
            raise HTTPException(
                status_code=400, detail=f"Unsupported service: {data.service}"
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/files/scan", response_model=ScanFilesResponse)
async def scan_files_endpoint(
    data: ScanFilesRequest, creds: AwsCredentials = Depends(validate_aws_credentials)
):
    try:
        if data.service == "s3":
            scan_id = create_scan(
                aws_access_key=creds.access_key,
                scan_type="file",
                bucket=data.location,
                metadata={
                    "file_count": len(data.files),
                    "service": data.service,
                },
            )

            try:
                scan_results = await scan_s3_files(
                    creds.session, data.location, data.files
                )

                findings = []
                for result in scan_results:
                    if result.get("status") not in ["error", "timeout"]:
                        finding = FileScanFinding(**result)
                        findings.append(finding)

                update_scan(scan_id, findings, completed=True)

                logger.info(
                    f"File scan {scan_id} completed with {len(findings)} findings"
                )

                return ScanFilesResponse(scan_id=scan_id, findings=findings)

            except Exception as e:
                logger.error(f"Error during file scan {scan_id}: {str(e)}")
                update_scan(scan_id, [], completed=True)
                raise HTTPException(status_code=500, detail=str(e))
        else:
            raise HTTPException(
                status_code=400,
                detail=f"File scanning not supported for {data.service}",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File scan endpoint error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/validate", response_model=ValidateResponse)
async def validate_credentials(data: ValidateRequest):
    try:
        session = boto3.Session(
            aws_access_key_id=data.access_key,
            aws_secret_access_key=data.secret_key,
            region_name=data.region,
        )
        sts_client = session.client("sts")
        sts_client.get_caller_identity()
        return ValidateResponse(valid=True)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid AWS credentials")


if __name__ == "__main__":
    import json, sys

    open(sys.argv[1], "w").write(json.dumps(app.openapi()))
