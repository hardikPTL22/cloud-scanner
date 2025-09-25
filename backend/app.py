import os
import tempfile
from flask import Flask, request, g, jsonify, send_file
from flask_cors import CORS
import boto3
import sys

sys.dont_write_bytecode = True

from scanner import (
    find_public_s3_buckets,
    find_unencrypted_s3_buckets,
    find_over_permissive_iam_policies,
    find_open_security_groups,
    find_cloudtrail_not_logging,
    scan_file,
    generate_pdf_report,
    write_json,
    write_csv,
)

app = Flask(__name__)
CORS(app)

SEVERITY = {
    "public_s3_bucket": "High",
    "over_permissive_iam": "High",
    "open_security_group": "Medium",
    "unencrypted_s3_bucket": "Medium",
    "cloudtrail_not_logging": "High",
    "file_scan": "High",
}


def run_scans(file_path=None):
    findings = []

    public_buckets = find_public_s3_buckets()
    for b in public_buckets:
        findings.append(
            {
                "type": "public_s3_bucket",
                "name": b,
                "severity": SEVERITY["public_s3_bucket"],
                "details": "Bucket has public ACL or bucket policy allowing public read.",
            }
        )

    unenc = find_unencrypted_s3_buckets()
    for b in unenc:
        findings.append(
            {
                "type": "unencrypted_s3_bucket",
                "name": b,
                "severity": SEVERITY["unencrypted_s3_bucket"],
                "details": "Bucket does not have default server-side encryption configured.",
            }
        )

    permissive_policies = find_over_permissive_iam_policies()
    for p in permissive_policies:
        findings.append(
            {
                "type": "over_permissive_iam",
                "name": p,
                "severity": SEVERITY["over_permissive_iam"],
                "details": "IAM policy contains '*' in Action or Resource.",
            }
        )

    open_groups = find_open_security_groups()
    for g in open_groups:
        findings.append(
            {
                "type": "open_security_group",
                "name": g,
                "severity": SEVERITY["open_security_group"],
                "details": "Security group has rules that allow ingress from 0.0.0.0/0 or ::/0.",
            }
        )

    ct_not_logging = find_cloudtrail_not_logging()
    for t in ct_not_logging:
        findings.append(
            {
                "type": "cloudtrail_not_logging",
                "name": t,
                "severity": SEVERITY["cloudtrail_not_logging"],
                "details": "CloudTrail exists but is not currently logging events.",
            }
        )

    if file_path:
        result = scan_file(file_path)
        if result["infected"]:
            findings.append(
                {
                    "type": "file_scan",
                    "name": os.path.basename(file_path),
                    "severity": SEVERITY["file_scan"],
                    "details": f"Infected with {result['malware']}",
                }
            )
        else:
            findings.append(
                {
                    "type": "file_scan",
                    "name": os.path.basename(file_path),
                    "severity": "Low",
                    "details": "File scanned clean.",
                }
            )

    print(f"Scan complete. Findings: {len(findings)}")  # Debug print
    return findings


@app.before_request
def middleware():
    try:
        access_key = request.headers.get("X-AWS-Access-Key")
        secret_key = request.headers.get("X-AWS-Secret-Key")
        region = request.headers.get("X-AWS-Region", "us-east-1")

        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )
        sts_client = session.client("sts")
        sts_client.get_caller_identity()  # Validate credentials
        g.s3_client = session.client("s3")
    except Exception as e:
        print(f"Error in middleware: {e}")  # Debug print
        return jsonify({"error": f"Invalid AWS credentials"}), 401


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.json
    if data.get("file", None) is not None and data.get("bucket", None) is not None:
        file = data.get("file")
        bucket = data.get("bucket")
        file = tempfile.NamedTemporaryFile("wb")
        obj = g.s3_client.get_object(Bucket=bucket, Key=file).get("Body")
        file.write(obj.read())
        file.close()
        filepath = file.name
        print(f"Received file for scanning: {filepath}")  # Debug print
    else:
        filepath = None
        print("No file uploaded, running cloud scans only.")  # Debug print

    findings = run_scans(file_path=filepath)
    print(f"Returning findings: {findings}")  # Debug print

    return jsonify({"findings": findings})


@app.route("/api/report", methods=["POST"])
def generate_report():
    data = request.json
    findings = data.get("findings", [])
    format_type = data.get("format", "pdf").lower()

    if format_type == "pdf":
        filepath = generate_pdf_report(findings)
    elif format_type == "json":
        filepath = write_json(findings)
    elif format_type == "csv":
        filepath = write_csv(findings)
    else:
        return jsonify({"error": "Unsupported format"}), 400

    return send_file(filepath, as_attachment=True)


@app.route("/api/buckets", methods=["GET"])
def list_buckets():
    try:
        response = g.s3_client.list_buckets()
        bucket_names = [b["Name"] for b in response.get("Buckets", [])]
        return jsonify({"buckets": bucket_names})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/files", methods=["GET"])
def list_files():
    try:
        data = request.args
        if "bucket" not in data:
            return jsonify({"error": "Bucket name is required"}), 400
        response = g.s3_client.list_objects_v2(Bucket=data.get("bucket"))
        file_names = [b["Key"] for b in response.get("Contents", [])]
        return jsonify({"files": file_names})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/validate", methods=["GET"])
def validate_credentials():
    return jsonify({"valid": True})


if __name__ == "__main__":
    app.run(debug=True)
