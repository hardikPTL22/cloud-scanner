from enum import Enum


class RDSVulnerability(str, Enum):
    rds_instance_unencrypted = "rds_instance_unencrypted"
    rds_instance_public_access = "rds_instance_public_access"
    rds_no_backup = "rds_no_backup"
    rds_low_backup_retention = "rds_low_backup_retention"
    rds_no_multi_az = "rds_no_multi_az"
    rds_no_enhanced_monitoring = "rds_no_enhanced_monitoring"
    rds_no_deletion_protection = "rds_no_deletion_protection"
    rds_no_copy_snapshots = "rds_no_copy_snapshots"
    rds_auto_minor_upgrade = "rds_auto_minor_upgrade"
    rds_no_performance_insights = "rds_no_performance_insights"
    rds_iam_auth_disabled = "rds_iam_auth_disabled"
    rds_default_port = "rds_default_port"
    rds_default_param_group = "rds_default_param_group"
    rds_cluster_unencrypted = "rds_cluster_unencrypted"
    rds_cluster_public = "rds_cluster_public"
    rds_no_automated_backup = "rds_no_automated_backup"
    rds_snapshot_public = "rds_snapshot_public"
    rds_no_tags = "rds_no_tags"
    rds_storage_not_encrypted = "rds_storage_not_encrypted"
    rds_no_option_group = "rds_no_option_group"
    rds_no_vpc = "rds_no_vpc"
    rds_no_cloudtrail = "rds_no_cloudtrail"
    rds_cluster_low_retention = "rds_cluster_low_retention"
    rds_default_sg = "rds_default_sg"
    rds_no_kms_key = "rds_no_kms_key"
    rds_unsupported_engine = "rds_unsupported_engine"
    rds_no_audit_logs = "rds_no_audit_logs"


RDS_SEVERITY = {
    "rds_instance_unencrypted": "High",
    "rds_instance_public_access": "High",
    "rds_cluster_unencrypted": "High",
    "rds_cluster_public": "High",
    "rds_no_kms_key": "High",
    "rds_snapshot_public": "High",
    "rds_no_backup": "High",
    "rds_no_automated_backup": "High",
    "rds_no_vpc": "High",
    "rds_default_sg": "High",
    "rds_storage_not_encrypted": "High",
    "rds_low_backup_retention": "Medium",
    "rds_no_multi_az": "Medium",
    "rds_no_enhanced_monitoring": "Low",
    "rds_no_deletion_protection": "Medium",
    "rds_no_copy_snapshots": "Low",
    "rds_auto_minor_upgrade": "Low",
    "rds_no_performance_insights": "Low",
    "rds_iam_auth_disabled": "Medium",
    "rds_default_port": "Medium",
    "rds_default_param_group": "Medium",
    "rds_no_option_group": "Low",
    "rds_no_cloudtrail": "Medium",
    "rds_cluster_low_retention": "Medium",
    "rds_no_tags": "Low",
    "rds_unsupported_engine": "Medium",
    "rds_no_audit_logs": "Medium",
}


RDS_MITRE_MAP = {
    "rds_instance_unencrypted": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "RDS instance storage encryption disabled",
        "remediation": "Enable encryption for all RDS instances at rest",
    },
    "rds_instance_public_access": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "RDS instance PubliclyAccessible setting enabled",
        "remediation": "Disable public access; use VPC and security groups only",
    },
    "rds_no_backup": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "RDS backup retention set to 0 days",
        "remediation": "Enable automated backups with appropriate retention",
    },
    "rds_no_automated_backup": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "RDS automated backup disabled",
        "remediation": "Enable automated backups for data protection",
    },
    "rds_snapshot_public": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "RDS snapshot is publicly accessible",
        "remediation": "Make snapshots private; restrict sharing to specific accounts",
    },
    "rds_cluster_unencrypted": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "RDS cluster storage encryption disabled",
        "remediation": "Enable encryption for Aurora cluster storage",
    },
    "rds_cluster_public": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "RDS cluster members have public access enabled",
        "remediation": "Disable public access for cluster members",
    },
    "rds_no_vpc": {
        "mitre_id": "T1570",
        "mitre_name": "Lateral Tool Transfer",
        "description": "RDS instance not in VPC",
        "remediation": "Deploy RDS in VPC for network isolation",
    },
    "rds_default_sg": {
        "mitre_id": "T1570",
        "mitre_name": "Lateral Tool Transfer",
        "description": "RDS using default security group",
        "remediation": "Use custom security groups with explicit rules",
    },
    "rds_storage_not_encrypted": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "RDS storage encryption not enabled",
        "remediation": "Enable storage encryption for database",
    },
    "rds_no_kms_key": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "RDS not using customer-managed KMS key",
        "remediation": "Use customer-managed KMS key for encryption",
    },
    "rds_low_backup_retention": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "RDS backup retention less than 7 days",
        "remediation": "Set backup retention to at least 7 days",
    },
    "rds_cluster_low_retention": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "RDS cluster backup retention less than 7 days",
        "remediation": "Increase cluster backup retention to at least 7 days",
    },
    "rds_no_multi_az": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "RDS instance not configured for Multi-AZ",
        "remediation": "Enable Multi-AZ for high availability",
    },
    "rds_no_deletion_protection": {
        "mitre_id": "T1485",
        "mitre_name": "Data Destruction",
        "description": "RDS deletion protection not enabled",
        "remediation": "Enable deletion protection for critical databases",
    },
    "rds_iam_auth_disabled": {
        "mitre_id": "T1078.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "description": "RDS IAM database authentication disabled",
        "remediation": "Enable IAM database authentication",
    },
    "rds_default_port": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "RDS using default database port",
        "remediation": "Change to non-standard port if security policy requires",
    },
    "rds_default_param_group": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "RDS using default parameter group",
        "remediation": "Use custom parameter group with hardened settings",
    },
    "rds_no_enhanced_monitoring": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "RDS enhanced monitoring not enabled",
        "remediation": "Enable enhanced monitoring for database metrics",
    },
    "rds_no_performance_insights": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "RDS Performance Insights not enabled",
        "remediation": "Enable Performance Insights for optimization",
    },
    "rds_auto_minor_upgrade": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "RDS auto minor version upgrade enabled",
        "remediation": "Disable auto minor version upgrade; schedule upgrades manually",
    },
    "rds_no_copy_snapshots": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "RDS copy snapshots to another region disabled",
        "remediation": "Enable copy of snapshots to another region",
    },
    "rds_no_option_group": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "RDS not using custom option group",
        "remediation": "Use custom option group for database configuration",
    },
    "rds_no_cloudtrail": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "RDS activities not logged to CloudTrail",
        "remediation": "Enable CloudTrail for database management audit",
    },
    "rds_unsupported_engine": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "RDS using unsupported engine version",
        "remediation": "Upgrade to supported database engine version",
    },
    "rds_no_audit_logs": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "RDS database audit logging not enabled",
        "remediation": "Enable database audit logging",
    },
    "rds_no_tags": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "RDS instance not tagged",
        "remediation": "Add tags to all RDS instances",
    },
}
