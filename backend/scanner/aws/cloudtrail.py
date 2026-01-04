from botocore.exceptions import ClientError
from scanner.mitre_maps.cloudtrail_mitre_map import CloudTrailVulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients
import json
from concurrent.futures import ThreadPoolExecutor
import logging

logger = logging.getLogger(__name__)


def fetch_trails(cloudtrail_client, include_shadow=False):
    """Fetch all CloudTrail trails once for reuse across checks"""
    try:
        return cloudtrail_client.describe_trails(
            includeShadowTrails=include_shadow
        ).get("trailList", [])
    except Exception as e:
        logger.error(f"Error fetching trails: {e}")
        return []


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_not_logging(cloudtrail_client, findings, trails=None):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_logging(trail):
        name = trail.get("Name") or trail.get("TrailARN")
        try:
            status = cloudtrail_client.get_trail_status(Name=name)
            if not status.get("IsLogging"):
                findings.append(
                    new_vulnerability(
                        CloudTrailVulnerability.cloudtrail_not_logging,
                        name,
                        "cloudtrail",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_logging, trails)


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_not_multi_region(cloudtrail_client, findings, trails=None):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_multi_region(trail):
        if not trail.get("IsMultiRegionTrail", False):
            name = trail.get("Name") or trail.get("TrailARN")
            findings.append(
                new_vulnerability(
                    CloudTrailVulnerability.cloudtrail_not_multi_region,
                    name,
                    "cloudtrail",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_multi_region, trails)


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_no_log_file_validation(cloudtrail_client, findings, trails=None):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_validation(trail):
        if not trail.get("LogFileValidationEnabled", False):
            name = trail.get("Name") or trail.get("TrailARN")
            findings.append(
                new_vulnerability(
                    CloudTrailVulnerability.cloudtrail_no_log_file_validation,
                    name,
                    "cloudtrail",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_validation, trails)


@inject_clients(clients=["cloudtrail", "s3"])
def find_cloudtrail_bucket_public(cloudtrail_client, s3_client, findings, trails=None):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_bucket_public(trail):
        bucket_name = trail.get("S3BucketName")
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
                                CloudTrailVulnerability.cloudtrail_bucket_public,
                                bucket_name,
                                "cloudtrail",
                            )
                        )
                        break
            except ClientError:
                pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_bucket_public, trails)


@inject_clients(clients=["cloudtrail", "s3"])
def find_cloudtrail_encryption_disabled(
    cloudtrail_client, s3_client, findings, trails=None
):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_encryption(trail):
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
                            CloudTrailVulnerability.cloudtrail_bucket_encryption_disabled,
                            s3_bucket,
                            "cloudtrail",
                        )
                    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_encryption, trails)


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_no_kms_encryption(cloudtrail_client, findings, trails=None):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_kms(trail):
        if not trail.get("KmsKeyId"):
            name = trail.get("Name") or trail.get("TrailARN")
            findings.append(
                new_vulnerability(
                    CloudTrailVulnerability.cloudtrail_no_kms,
                    name,
                    "cloudtrail",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_kms, trails)


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_not_recording(cloudtrail_client, findings, trails=None):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_recording(trail):
        name = trail.get("Name") or trail.get("TrailARN")
        try:
            status = cloudtrail_client.get_trail_status(Name=name)
            if not status.get("IsRecording", False):
                findings.append(
                    new_vulnerability(
                        CloudTrailVulnerability.cloudtrail_not_recording,
                        name,
                        "cloudtrail",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_recording, trails)


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_no_organization_trail(cloudtrail_client, findings, trails=None):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_org_trail(trail):
        if not trail.get("IsOrganizationTrail", False):
            name = trail.get("Name") or trail.get("TrailARN")
            findings.append(
                new_vulnerability(
                    CloudTrailVulnerability.cloudtrail_no_org_trail,
                    name,
                    "cloudtrail",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_org_trail, trails)


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_event_selectors_not_configured(
    cloudtrail_client, findings, trails=None
):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_event_selectors(trail):
        try:
            trail_name = trail.get("Name") or trail.get("TrailARN")
            event_selectors = cloudtrail_client.get_event_selectors(
                TrailName=trail_name
            )
            if not event_selectors.get("EventSelectors"):
                findings.append(
                    new_vulnerability(
                        CloudTrailVulnerability.cloudtrail_no_event_selectors,
                        trail_name,
                        "cloudtrail",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_event_selectors, trails)


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_management_events_disabled(
    cloudtrail_client, findings, trails=None
):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_mgmt_events(trail):
        try:
            trail_name = trail.get("Name") or trail.get("TrailARN")
            event_selectors = cloudtrail_client.get_event_selectors(
                TrailName=trail_name
            )
            for selector in event_selectors.get("EventSelectors", []):
                if not selector.get("IncludeManagementEvents", True):
                    findings.append(
                        new_vulnerability(
                            CloudTrailVulnerability.cloudtrail_mgmt_events_disabled,
                            trail_name,
                            "cloudtrail",
                        )
                    )
                    break
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_mgmt_events, trails)


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_data_events_disabled(cloudtrail_client, findings, trails=None):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_data_events(trail):
        try:
            trail_name = trail.get("Name") or trail.get("TrailARN")
            event_selectors = cloudtrail_client.get_event_selectors(
                TrailName=trail_name
            )
            has_data_events = False
            for selector in event_selectors.get("EventSelectors", []):
                if selector.get("DataResources"):
                    has_data_events = True
                    break
            if not has_data_events:
                findings.append(
                    new_vulnerability(
                        CloudTrailVulnerability.cloudtrail_no_data_events,
                        trail_name,
                        "cloudtrail",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_data_events, trails)


@inject_clients(clients=["cloudtrail", "cloudwatch"])
def find_cloudtrail_no_cloudwatch_logs(
    cloudtrail_client, cloudwatch_client, findings, trails=None
):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_cloudwatch(trail):
        if not trail.get("CloudWatchLogsLogGroupArn"):
            name = trail.get("Name") or trail.get("TrailARN")
            findings.append(
                new_vulnerability(
                    CloudTrailVulnerability.cloudtrail_no_cloudwatch,
                    name,
                    "cloudtrail",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_cloudwatch, trails)


@inject_clients(clients=["cloudtrail", "s3"])
def find_cloudtrail_bucket_versioning_disabled(
    cloudtrail_client, s3_client, findings, trails=None
):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_versioning(trail):
        bucket_name = trail.get("S3BucketName")
        if bucket_name:
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get("Status") != "Enabled":
                    findings.append(
                        new_vulnerability(
                            CloudTrailVulnerability.cloudtrail_bucket_versioning_disabled,
                            bucket_name,
                            "cloudtrail",
                        )
                    )
            except ClientError:
                pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_versioning, trails)


@inject_clients(clients=["cloudtrail", "s3"])
def find_cloudtrail_bucket_no_mfa_delete(
    cloudtrail_client, s3_client, findings, trails=None
):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_mfa_delete(trail):
        bucket_name = trail.get("S3BucketName")
        if bucket_name:
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get("MFADelete") != "Enabled":
                    findings.append(
                        new_vulnerability(
                            CloudTrailVulnerability.cloudtrail_bucket_no_mfa_delete,
                            bucket_name,
                            "cloudtrail",
                        )
                    )
            except ClientError:
                pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_mfa_delete, trails)


@inject_clients(clients=["cloudtrail", "s3"])
def find_cloudtrail_bucket_no_access_logging(
    cloudtrail_client, s3_client, findings, trails=None
):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_access_logging(trail):
        bucket_name = trail.get("S3BucketName")
        if bucket_name:
            try:
                logging = s3_client.get_bucket_logging(Bucket=bucket_name)
                if not logging.get("LoggingEnabled"):
                    findings.append(
                        new_vulnerability(
                            CloudTrailVulnerability.cloudtrail_bucket_no_logging,
                            bucket_name,
                            "cloudtrail",
                        )
                    )
            except ClientError:
                pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_access_logging, trails)


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_shadow_trails(cloudtrail_client, findings):
    trails = fetch_trails(cloudtrail_client, include_shadow=True)

    def check_shadow(trail):
        if trail.get("HasShadowTrails", False):
            name = trail.get("Name") or trail.get("TrailARN")
            findings.append(
                new_vulnerability(
                    CloudTrailVulnerability.cloudtrail_shadow_trails,
                    name,
                    "cloudtrail",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_shadow, trails)


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_no_sns_notification(cloudtrail_client, findings, trails=None):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_sns(trail):
        if not trail.get("SNSTopicName"):
            name = trail.get("Name") or trail.get("TrailARN")
            findings.append(
                new_vulnerability(
                    CloudTrailVulnerability.cloudtrail_no_sns,
                    name,
                    "cloudtrail",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_sns, trails)


@inject_clients(clients=["cloudtrail", "s3"])
def find_cloudtrail_bucket_public_policy(
    cloudtrail_client, s3_client, findings, trails=None
):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_public_policy(trail):
        bucket_name = trail.get("S3BucketName")
        if bucket_name:
            try:
                policy = s3_client.get_bucket_policy(Bucket=bucket_name)
                if policy.get("Policy"):
                    policy_doc = json.loads(policy["Policy"])
                    for stmt in policy_doc.get("Statement", []):
                        if (
                            stmt.get("Effect") == "Allow"
                            and stmt.get("Principal") == "*"
                        ):
                            findings.append(
                                new_vulnerability(
                                    CloudTrailVulnerability.cloudtrail_bucket_public_policy,
                                    bucket_name,
                                    "cloudtrail",
                                )
                            )
                            break
            except ClientError:
                pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_public_policy, trails)


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_enable_log_file_digest(cloudtrail_client, findings, trails=None):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_digest(trail):
        if not trail.get("HasCustomEventSelectors", False) or not trail.get(
            "LogFileValidationEnabled", False
        ):
            name = trail.get("Name") or trail.get("TrailARN")
            findings.append(
                new_vulnerability(
                    CloudTrailVulnerability.cloudtrail_no_log_digest,
                    name,
                    "cloudtrail",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_digest, trails)


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_no_tags(cloudtrail_client, findings, trails=None):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_tags(trail):
        trail_arn = trail.get("TrailARN")
        if trail_arn:
            try:
                tags = cloudtrail_client.list_tags(ResourceIdList=[trail_arn])
                if not tags.get("ResourceTagList", [{}])[0].get("TagsList"):
                    name = trail.get("Name") or trail_arn
                    findings.append(
                        new_vulnerability(
                            CloudTrailVulnerability.cloudtrail_no_tags,
                            name,
                            "cloudtrail",
                        )
                    )
            except ClientError:
                pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_tags, trails)


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_too_many_trails(cloudtrail_client, findings):
    try:
        trails = fetch_trails(cloudtrail_client)
        trail_count = len(trails)
        if trail_count > 5:
            findings.append(
                new_vulnerability(
                    CloudTrailVulnerability.cloudtrail_too_many_trails,
                    f"Found {trail_count} trails",
                    "cloudtrail",
                )
            )
    except ClientError:
        pass


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_no_read_events(cloudtrail_client, findings, trails=None):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_read_events(trail):
        try:
            trail_name = trail.get("Name") or trail.get("TrailARN")
            event_selectors = cloudtrail_client.get_event_selectors(
                TrailName=trail_name
            )
            for selector in event_selectors.get("EventSelectors", []):
                if selector.get("ReadWriteType") == "WriteOnly":
                    findings.append(
                        new_vulnerability(
                            CloudTrailVulnerability.cloudtrail_no_read_events,
                            trail_name,
                            "cloudtrail",
                        )
                    )
                    break
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_read_events, trails)


@inject_clients(clients=["cloudtrail", "s3"])
def find_cloudtrail_bucket_no_lifecycle(
    cloudtrail_client, s3_client, findings, trails=None
):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_lifecycle(trail):
        bucket_name = trail.get("S3BucketName")
        if bucket_name:
            try:
                s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
                    findings.append(
                        new_vulnerability(
                            CloudTrailVulnerability.cloudtrail_bucket_no_lifecycle,
                            bucket_name,
                            "cloudtrail",
                        )
                    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_lifecycle, trails)


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_no_advanced_event_selectors(
    cloudtrail_client, findings, trails=None
):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_advanced_selectors(trail):
        try:
            trail_name = trail.get("Name") or trail.get("TrailARN")
            advanced = cloudtrail_client.get_event_selectors(TrailName=trail_name)
            if not advanced.get("AdvancedEventSelectors"):
                findings.append(
                    new_vulnerability(
                        CloudTrailVulnerability.cloudtrail_no_advanced_selectors,
                        trail_name,
                        "cloudtrail",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_advanced_selectors, trails)


@inject_clients(clients=["cloudtrail"])
def find_cloudtrail_name_invalid(cloudtrail_client, findings, trails=None):
    if trails is None:
        trails = fetch_trails(cloudtrail_client)

    def check_name(trail):
        name = trail.get("Name", "")
        if (
            not name
            or " " in name
            or not name.replace("-", "").replace("_", "").isalnum()
        ):
            arn = trail.get("TrailARN", "unknown")
            findings.append(
                new_vulnerability(
                    CloudTrailVulnerability.cloudtrail_invalid_name,
                    arn,
                    "cloudtrail",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_name, trails)
