from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
import boto3
import os
from scanner import run_scans, generate_pdf_report, write_json, write_csv
from scanner.db import create_scan, update_scan, list_scans, get_scan

# from fastapi import Query, UploadFile, File
# import asyncio


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    bucket: str = None
    file: str = None
    services: dict[str, list[str]] = {}


async def validate_aws_credentials(request: Request):
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
        return {
            "access_key": access_key,
            "secret_key": secret_key,
            "region": region,
            "session": session,
        }
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid AWS credentials")


@app.post("/api/scan")
async def scan(data: ScanRequest, creds: dict = Depends(validate_aws_credentials)):
    selected_scans = list(data.services.values())
    scan_id = create_scan(
        creds["access_key"],
        selected_scans,
    )

    findings = run_scans(
        data.services,
        access_key=creds["access_key"],
        secret_key=creds["secret_key"],
        region=creds["region"],
    )

    update_scan(scan_id, findings=findings, completed=True)

    return JSONResponse(content={"scan_id": scan_id, "findings": findings})


@app.get("/api/scans")
async def get_scans(creds: dict = Depends(validate_aws_credentials)):
    scans = list_scans(creds["access_key"])
    return {"scans": scans}


@app.post("/api/report")
async def generate_report(data: dict):
    scan_id = data.get("scan_id")
    format_type = data.get("format", "pdf").lower()
    findings = get_scan(scan_id).get("findings", [])

    if format_type == "pdf":
        filepath = generate_pdf_report(findings)
    elif format_type == "json":
        filepath = write_json(findings)
    elif format_type == "csv":
        filepath = write_csv(findings)
    else:
        raise HTTPException(status_code=400, detail="Unsupported format")

    return FileResponse(
        filepath,
        filename=os.path.basename(filepath),
        media_type="application/octet-stream",
    )


@app.get("/api/buckets")
async def list_buckets(creds: dict = Depends(validate_aws_credentials)):
    try:
        s3_client = creds["session"].client("s3")
        response = s3_client.list_buckets()
        bucket_names = [b["Name"] for b in response.get("Buckets", [])]
        return JSONResponse(content={"buckets": bucket_names})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/files")
async def list_files(
    bucket: str = None, creds: dict = Depends(validate_aws_credentials)
):
    if not bucket:
        raise HTTPException(status_code=400, detail="Bucket name is required")
    try:
        s3_client = creds["session"].client("s3")
        response = s3_client.list_objects_v2(Bucket=bucket)
        file_names = [b["Key"] for b in response.get("Contents", [])]
        return JSONResponse(content={"files": file_names})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# @app.get("/api/folders")
# async def list_folders(
#     bucket: str = Query(...), creds: dict = Depends(validate_aws_credentials)
# ):
#     s3 = creds["session"].client("s3")
#     paginator = s3.get_paginator("list_objects_v2")
#     result = paginator.paginate(Bucket=bucket, Delimiter="/")
#     folders = []
#     async for page in result:
#         if "CommonPrefixes" in page:
#             folders.extend([prefix["Prefix"] for prefix in page["CommonPrefixes"]])
#     return {"folders": folders}


# class S3FilesToScan(BaseModel):
#     bucket: str
#     keys: list[str]


# @app.post("/api/scan-files")
# async def scan_s3_files(
#     data: S3FilesToScan, creds: dict = Depends(validate_aws_credentials)
# ):
#     results = []
#     for key in data.keys:
#         local_path = f"/tmp/{os.path.basename(key)}"
#         download_file_from_s3(creds["session"], data.bucket, key, local_path)
#         vt_result = await scan_file_with_virustotal(local_path, os.path.basename(key))
#         os.remove(local_path)
#         results.append({"file": key, "scan_result": vt_result})
#     return {"results": results}


@app.get("/api/validate")
async def validate_credentials():
    return JSONResponse(content={"valid": True})


if __name__ == "__main__":
    app.run
