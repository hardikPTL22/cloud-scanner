from enum import Enum


class S3Vulnerability(str, Enum):
    public_s3_bucket = "public_s3_bucket"
    unencrypted_s3_bucket = "unencrypted_s3_bucket"
    s3_bucket_versioning_disabled = "s3_bucket_versioning_disabled"
    s3_bucket_logging_disabled = "s3_bucket_logging_disabled"
    s3_bucket_block_public_access_disabled = "s3_bucket_block_public_access_disabled"
    s3_mfa_delete_disabled = "s3_mfa_delete_disabled"
    s3_no_lifecycle = "s3_no_lifecycle"
    s3_cors_all_origins = "s3_cors_all_origins"
    s3_bucket_no_tags = "s3_bucket_no_tags"
    s3_website_enabled = "s3_website_enabled"
    s3_no_object_lock = "s3_no_object_lock"
    s3_requester_pays = "s3_requester_pays"
    s3_acl_public = "s3_acl_public"
    s3_unencrypted_upload_allowed = "s3_unencrypted_upload_allowed"
    s3_no_replication = "s3_no_replication"
    s3_no_server_access_logging = "s3_no_server_access_logging"
    s3_no_cloudtrail_logging = "s3_no_cloudtrail_logging"
    s3_no_intelligent_tiering = "s3_no_intelligent_tiering"
    s3_object_lock_no_retention = "s3_object_lock_no_retention"
    s3_public_read_access = "s3_public_read_access"
    s3_public_write_access = "s3_public_write_access"
    s3_non_standard_encryption = "s3_non_standard_encryption"
    s3_bucket_key_disabled = "s3_bucket_key_disabled"
    s3_user_versioning_disabled = "s3_user_versioning_disabled"
    s3_unrestricted_policy = "s3_unrestricted_policy"
    s3_no_kms_encryption = "s3_no_kms_encryption"
    s3_no_access_point = "s3_no_access_point"


S3_SEVERITY = {
    "public_s3_bucket": "High",
    "s3_bucket_block_public_access_disabled": "High",
    "s3_acl_public": "High",
    "s3_unrestricted_policy": "High",
    "s3_public_read_access": "High",
    "s3_public_write_access": "High",
    "unencrypted_s3_bucket": "Medium",
    "s3_bucket_versioning_disabled": "Medium",
    "s3_bucket_logging_disabled": "Medium",
    "s3_mfa_delete_disabled": "Medium",
    "s3_no_lifecycle": "Medium",
    "s3_no_replication": "Medium",
    "s3_no_server_access_logging": "Medium",
    "s3_bucket_key_disabled": "Medium",
    "s3_no_intelligent_tiering": "Medium",
    "s3_unencrypted_upload_allowed": "High",
    "s3_bucket_no_tags": "Low",
    "s3_website_enabled": "Low",
    "s3_cors_all_origins": "Medium",
    "s3_no_object_lock": "Medium",
    "s3_requester_pays": "Low",
    "s3_non_standard_encryption": "Medium",
    "s3_user_versioning_disabled": "Medium",
    "s3_no_cloudtrail_logging": "High",
    "s3_object_lock_no_retention": "Medium",
    "s3_no_kms_encryption": "High",
    "s3_no_access_point": "Low",
}


S3_MITRE_MAP = {
    "public_s3_bucket": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "S3 bucket has public ACL or bucket policy",
        "remediation": "Disable public ACLs, enable Block Public Access, use restrictive policies",
    },
    "s3_bucket_block_public_access_disabled": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "S3 Block Public Access settings not fully enabled",
        "remediation": "Enable all four Block Public Access settings",
    },
    "s3_acl_public": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "S3 bucket ACL allows public access",
        "remediation": "Set ACL to private or log-delivery-write only",
    },
    "s3_unrestricted_policy": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "S3 bucket policy unrestricted or too permissive",
        "remediation": "Use principal restrictions, specific resources, limited actions",
    },
    "s3_public_read_access": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "S3 bucket allows public read",
        "remediation": "Restrict read access to authenticated principals",
    },
    "s3_public_write_access": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "S3 bucket allows public write",
        "remediation": "Restrict write access to authenticated principals",
    },
    "s3_unencrypted_upload_allowed": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "S3 bucket allows unencrypted uploads",
        "remediation": "Enforce bucket policy requiring encryption on upload",
    },
    "s3_no_cloudtrail_logging": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "S3 bucket CloudTrail logging not enabled",
        "remediation": "Enable CloudTrail data events for S3 objects",
    },
    "s3_no_kms_encryption": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "S3 bucket not using KMS encryption",
        "remediation": "Enable KMS encryption with customer-managed keys",
    },
    "unencrypted_s3_bucket": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "S3 bucket default encryption not enabled",
        "remediation": "Enable default bucket encryption (SSE-S3 or SSE-KMS)",
    },
    "s3_bucket_versioning_disabled": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "S3 bucket versioning not enabled",
        "remediation": "Enable bucket versioning for all objects",
    },
    "s3_bucket_logging_disabled": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "S3 bucket access logging not enabled",
        "remediation": "Enable S3 access logging to another bucket",
    },
    "s3_mfa_delete_disabled": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "S3 bucket MFA delete not enabled",
        "remediation": "Enable MFA delete with versioning",
    },
    "s3_no_lifecycle": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "S3 bucket has no lifecycle policy",
        "remediation": "Configure lifecycle policy for retention/archival",
    },
    "s3_cors_all_origins": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "S3 bucket CORS allows all origins",
        "remediation": "Restrict CORS to trusted origins only",
    },
    "s3_no_object_lock": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "S3 bucket Object Lock not enabled",
        "remediation": "Enable Object Lock for WORM protection",
    },
    "s3_object_lock_no_retention": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "S3 Object Lock has no default retention",
        "remediation": "Configure default retention policy",
    },
    "s3_no_server_access_logging": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "S3 bucket server access logging not enabled",
        "remediation": "Enable S3 server access logging",
    },
    "s3_no_replication": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "S3 bucket replication not configured",
        "remediation": "Enable cross-region replication for DR",
    },
    "s3_no_intelligent_tiering": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "S3 Intelligent-Tiering not enabled",
        "remediation": "Enable Intelligent-Tiering for cost optimization",
    },
    "s3_non_standard_encryption": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "S3 bucket using non-standard encryption",
        "remediation": "Use AES-256 or KMS encryption",
    },
    "s3_bucket_key_disabled": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "S3 bucket key not enabled for KMS",
        "remediation": "Enable S3 bucket keys for KMS objects",
    },
    "s3_user_versioning_disabled": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "S3 bucket versioning disabled",
        "remediation": "Enable versioning for all production buckets",
    },
    "s3_website_enabled": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "S3 bucket website hosting enabled",
        "remediation": "Use CloudFront for website hosting instead",
    },
    "s3_requester_pays": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "S3 bucket requester pays enabled",
        "remediation": "Disable requester pays unless intentional",
    },
    "s3_bucket_no_tags": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "S3 bucket not tagged",
        "remediation": "Add tags to all S3 buckets",
    },
    "s3_no_access_point": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "S3 bucket has no access points",
        "remediation": "Use S3 access points for access management",
    },
}
