from botocore.exceptions import ClientError
from scanner.mitre_map import Vulnerability, new_vulnerability


def find_cloudtrail_not_logging(cloudtrail_client, findings):
    not_logging = []
    trails_resp = cloudtrail_client.describe_trails(includeShadowTrails=False)

    for t in trails_resp.get("trailList", []):
        name = t.get("Name") or t.get("TrailARN")
        try:
            status = (
                cloudtrail_client.get_trail_status(Name=t.get("Name"))
                if t.get("Name")
                else cloudtrail_client.get_trail_status(
                    TrailNameList=[t.get("TrailARN")]
                )
            )

            is_logging = status.get("IsLogging")
            if is_logging is False:
                not_logging.append(name)
        except ClientError:
            continue
        except Exception:
            continue
    for t in not_logging:
        findings.append(
            new_vulnerability(
                Vulnerability.cloudtrail_not_logging,
                t,
            )
        )


def find_cloudtrail_not_multi_region(cloudtrail_client, findings):
    not_multi_region = []
    trails_resp = cloudtrail_client.describe_trails(includeShadowTrails=False)
    for t in trails_resp.get("trailList", []):
        if not t.get("IsMultiRegionTrail", False):
            name = t.get("Name") or t.get("TrailARN")
            not_multi_region.append(name)
    for t in not_multi_region:
        findings.append(
            new_vulnerability(
                Vulnerability.cloudtrail_not_multi_region,
                t,
            )
        )


def find_cloudtrail_no_log_file_validation(cloudtrail_client, findings):
    no_validation = []
    trails_resp = cloudtrail_client.describe_trails(includeShadowTrails=False)
    for t in trails_resp.get("trailList", []):
        try:
            if not t.get("LogFileValidationEnabled", False):
                name = t.get("Name") or t.get("TrailARN")
                no_validation.append(name)
        except Exception:
            continue
    for t in no_validation:
        findings.append(
            new_vulnerability(
                Vulnerability.cloudtrail_no_log_file_validation,
                t,
            )
        )


def find_cloudtrail_bucket_public(s3_client, cloudtrail_client, findings):
    pub_buckets = []
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
                        pub_buckets.append(bucket_name)
                        break
            except Exception:
                continue
    for b in pub_buckets:
        findings.append(
            new_vulnerability(
                Vulnerability.cloudtrail_bucket_public,
                b,
            )
        )
