from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
import boto3
import tempfile
import os
from scanner import run_scans, generate_pdf_report, write_json, write_csv

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
    file_path = None
    selected_bucket = data.bucket
    if data.file is not None and selected_bucket is not None:
        file_key = data.file
        bucket = data.bucket
        temp_file = tempfile.NamedTemporaryFile("wb", delete=False)
        try:
            s3_client = creds["session"].client("s3")
            obj = s3_client.get_object(Bucket=bucket, Key=file_key)
            temp_file.write(obj["Body"].read())
            temp_file.close()
            file_path = temp_file.name
        except Exception:
            file_path = None

    selected_services = data.services

    findings = run_scans(
        selected_services,
        access_key=creds["access_key"],
        secret_key=creds["secret_key"],
        region=creds["region"],
    )

    if file_path:
        try:
            os.remove(file_path)
        except Exception:
            pass

    return JSONResponse(content={"findings": findings})


@app.post("/api/report")
async def generate_report(data: dict):
    findings = data.get("findings", [])
    format_type = data.get("format", "pdf").lower()

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


@app.get("/api/validate")
async def validate_credentials():
    return JSONResponse(content={"valid": True})


if __name__ == "__main__":
    app.run
