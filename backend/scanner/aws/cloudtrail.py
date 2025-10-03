from botocore.exceptions import ClientError
from scanner.mitre_map import Vulnerability, new_vulnerability


def find_cloudtrail_not_logging(cloudtrail_client, findings):
    trails_resp = cloudtrail_client.describe_trails(includeShadowTrails=False)
    for t in trails_resp.get("trailList", []):
        name = t.get("Name") or t.get("TrailARN")
        try:
            status = cloudtrail_client.get_trail_status(Name=name)
            if not status.get("IsLogging"):
                findings.append(
                    new_vulnerability(
                        Vulnerability.cloudtrail_not_logging,
                        name,
                    )
                )
        except ClientError:
            continue


def find_cloudtrail_not_multi_region(cloudtrail_client, findings):
    trails_resp = cloudtrail_client.describe_trails(includeShadowTrails=False)
    for t in trails_resp.get("trailList", []):
        if not t.get("IsMultiRegionTrail", False):
            name = t.get("Name") or t.get("TrailARN")
            findings.append(
                new_vulnerability(
                    Vulnerability.cloudtrail_not_multi_region,
                    name,
                )
            )


def find_cloudtrail_no_log_file_validation(cloudtrail_client, findings):
    trails_resp = cloudtrail_client.describe_trails(includeShadowTrails=False)
    for t in trails_resp.get("trailList", []):
        if not t.get("LogFileValidationEnabled", False):
            name = t.get("Name") or t.get("TrailARN")
            findings.append(
                new_vulnerability(
                    Vulnerability.cloudtrail_no_log_file_validation,
                    name,
                )
            )


def find_cloudtrail_bucket_public(s3_client, cloudtrail_client, findings):
    trails_resp = cloudtrail_client.describe_trails(includeShadowTrails=False)
    for t in trails_resp.get("trailList", []):
        bucket_name = t.get("S3BucketName")
        if bucket_name:
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if (
                        grantee.get("URI")
                        == "http://acs.amazonaws.com/groups/global/AllUsers"
                    ):
                        findings.append(
                            new_vulnerability(
                                Vulnerability.cloudtrail_bucket_public,
                                bucket_name,
                            )
                        )
                        break
            except ClientError:
                continue


def find_cloudtrail_encryption_disabled(cloudtrail_client, s3_client, findings):
    trails = cloudtrail_client.describe_trails(includeShadowTrails=False).get(
        "trailList", []
    )
    for trail in trails:
        s3_bucket = trail.get("S3BucketName")
        if s3_bucket:
            try:
                s3_client.get_bucket_encryption(Bucket=s3_bucket)
            except ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    == "ServerSideEncryptionConfigurationNotFoundError"
                ):
                    findings.append(
                        new_vulnerability(
                            Vulnerability.cloudtrail_bucket_encryption_disabled,
                            s3_bucket,
                        )
                    )
