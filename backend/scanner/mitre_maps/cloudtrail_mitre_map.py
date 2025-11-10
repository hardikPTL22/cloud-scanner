from enum import Enum


class CloudTrailVulnerability(str, Enum):
    cloudtrail_not_logging = "cloudtrail_not_logging"
    cloudtrail_not_multi_region = "cloudtrail_not_multi_region"
    cloudtrail_no_log_file_validation = "cloudtrail_no_log_file_validation"
    cloudtrail_bucket_public = "cloudtrail_bucket_public"
    cloudtrail_bucket_encryption_disabled = "cloudtrail_bucket_encryption_disabled"
    cloudtrail_no_kms = "cloudtrail_no_kms"
    cloudtrail_not_recording = "cloudtrail_not_recording"
    cloudtrail_no_org_trail = "cloudtrail_no_org_trail"
    cloudtrail_no_event_selectors = "cloudtrail_no_event_selectors"
    cloudtrail_mgmt_events_disabled = "cloudtrail_mgmt_events_disabled"
    cloudtrail_no_data_events = "cloudtrail_no_data_events"
    cloudtrail_no_cloudwatch = "cloudtrail_no_cloudwatch"
    cloudtrail_bucket_versioning_disabled = "cloudtrail_bucket_versioning_disabled"
    cloudtrail_bucket_no_mfa_delete = "cloudtrail_bucket_no_mfa_delete"
    cloudtrail_bucket_no_logging = "cloudtrail_bucket_no_logging"
    cloudtrail_shadow_trails = "cloudtrail_shadow_trails"
    cloudtrail_no_sns = "cloudtrail_no_sns"
    cloudtrail_bucket_public_policy = "cloudtrail_bucket_public_policy"
    cloudtrail_no_log_digest = "cloudtrail_no_log_digest"
    cloudtrail_no_tags = "cloudtrail_no_tags"
    cloudtrail_too_many_trails = "cloudtrail_too_many_trails"
    cloudtrail_no_read_events = "cloudtrail_no_read_events"
    cloudtrail_bucket_no_lifecycle = "cloudtrail_bucket_no_lifecycle"
    cloudtrail_no_advanced_selectors = "cloudtrail_no_advanced_selectors"
    cloudtrail_invalid_name = "cloudtrail_invalid_name"


CLOUDTRAIL_SEVERITY = {
    "cloudtrail_not_logging": "Critical",
    "cloudtrail_not_recording": "Critical",
    "cloudtrail_not_multi_region": "Medium",
    "cloudtrail_no_log_file_validation": "Medium",
    "cloudtrail_bucket_public": "Critical",
    "cloudtrail_bucket_encryption_disabled": "High",
    "cloudtrail_no_kms": "High",
    "cloudtrail_no_org_trail": "Medium",
    "cloudtrail_no_event_selectors": "Medium",
    "cloudtrail_mgmt_events_disabled": "High",
    "cloudtrail_no_data_events": "Medium",
    "cloudtrail_no_cloudwatch": "Medium",
    "cloudtrail_bucket_versioning_disabled": "Medium",
    "cloudtrail_bucket_no_mfa_delete": "Medium",
    "cloudtrail_bucket_no_logging": "Medium",
    "cloudtrail_shadow_trails": "Medium",
    "cloudtrail_no_sns": "Low",
    "cloudtrail_bucket_public_policy": "High",
    "cloudtrail_no_log_digest": "Medium",
    "cloudtrail_no_tags": "Low",
    "cloudtrail_too_many_trails": "Low",
    "cloudtrail_no_read_events": "Medium",
    "cloudtrail_bucket_no_lifecycle": "Low",
    "cloudtrail_no_advanced_selectors": "Medium",
    "cloudtrail_invalid_name": "Low",
}


CLOUDTRAIL_MITRE_MAP = {
    "cloudtrail_not_logging": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "CloudTrail logging is disabled or not logging API activities",
        "remediation": "Enable CloudTrail detector and ensure logging is active across regions",
    },
    "cloudtrail_not_recording": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "CloudTrail trail exists but is not recording events",
        "remediation": "Enable recording for the trail to capture API calls",
    },
    "cloudtrail_bucket_public": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "CloudTrail log bucket is publicly accessible",
        "remediation": "Restrict S3 bucket ACLs and enable Block Public Access",
    },
    "cloudtrail_bucket_encryption_disabled": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "CloudTrail S3 bucket does not have encryption enabled",
        "remediation": "Enable default S3 encryption (SSE-S3 or SSE-KMS)",
    },
    "cloudtrail_no_kms": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "CloudTrail not configured to use KMS key",
        "remediation": "Configure CloudTrail to use customer-managed KMS key",
    },
    "cloudtrail_bucket_public_policy": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "CloudTrail bucket has public policy allowing unauthorized access",
        "remediation": "Remove public principals from bucket policy",
    },
    "cloudtrail_not_multi_region": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "CloudTrail is configured for single region only",
        "remediation": "Enable multi-region CloudTrail to capture all API activities",
    },
    "cloudtrail_no_log_file_validation": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "CloudTrail log file validation is not enabled",
        "remediation": "Enable log file validation for integrity checks",
    },
    "cloudtrail_mgmt_events_disabled": {
        "mitre_id": "T1078.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "description": "CloudTrail not logging management events",
        "remediation": "Enable management events for all API calls tracking",
    },
    "cloudtrail_no_data_events": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "CloudTrail not configured to log data events",
        "remediation": "Configure event selectors to log data events",
    },
    "cloudtrail_no_cloudwatch": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "CloudTrail not configured to log to CloudWatch",
        "remediation": "Configure CloudTrail to deliver logs to CloudWatch Logs",
    },
    "cloudtrail_no_event_selectors": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "CloudTrail event selectors not configured",
        "remediation": "Configure event selectors for management and data events",
    },
    "cloudtrail_no_org_trail": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "Organization CloudTrail not configured",
        "remediation": "Create organization CloudTrail in management account",
    },
    "cloudtrail_bucket_versioning_disabled": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "CloudTrail S3 bucket versioning disabled",
        "remediation": "Enable S3 versioning on CloudTrail bucket",
    },
    "cloudtrail_bucket_no_mfa_delete": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "CloudTrail bucket MFA delete not enabled",
        "remediation": "Enable MFA delete on CloudTrail bucket",
    },
    "cloudtrail_bucket_no_logging": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "CloudTrail S3 bucket access logging disabled",
        "remediation": "Enable S3 server access logging on CloudTrail bucket",
    },
    "cloudtrail_shadow_trails": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "Shadow CloudTrail trails detected",
        "remediation": "Use single CloudTrail per account, avoid shadow trails",
    },
    "cloudtrail_no_sns": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "CloudTrail not configured with SNS notifications",
        "remediation": "Configure SNS notifications for CloudTrail logs",
    },
    "cloudtrail_no_log_digest": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "CloudTrail log file digest not enabled",
        "remediation": "Enable CloudTrail log file digest for integrity verification",
    },
    "cloudtrail_no_tags": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "CloudTrail trail not tagged",
        "remediation": "Add tags to all CloudTrail trails for organization",
    },
    "cloudtrail_too_many_trails": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "More than 5 CloudTrail trails detected",
        "remediation": "Consolidate trails, avoid redundant configurations",
    },
    "cloudtrail_no_read_events": {
        "mitre_id": "T1526",
        "mitre_name": "Enumerate Cloud Resources",
        "description": "CloudTrail not logging read events",
        "remediation": "Enable logging of read events",
    },
    "cloudtrail_bucket_no_lifecycle": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "CloudTrail bucket has no lifecycle policy",
        "remediation": "Configure S3 lifecycle policy for retention",
    },
    "cloudtrail_no_advanced_selectors": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "CloudTrail not using advanced event selectors",
        "remediation": "Enable advanced event selectors for detailed logging control",
    },
    "cloudtrail_invalid_name": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "CloudTrail trail has invalid or unclear name",
        "remediation": "Use descriptive, consistent naming convention",
    },
}
