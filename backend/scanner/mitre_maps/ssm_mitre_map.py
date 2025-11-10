from enum import Enum


class SSMVulnerability(str, Enum):
    ssm_parameter_unencrypted = "ssm_parameter_unencrypted"
    ssm_param_public_tier = "ssm_param_public_tier"
    ssm_document_public = "ssm_document_public"
    ssm_no_session_logging = "ssm_no_session_logging"
    ssm_param_no_tags = "ssm_param_no_tags"
    ssm_doc_no_description = "ssm_doc_no_description"
    ssm_patch_manager_disabled = "ssm_patch_manager_disabled"
    ssm_maintenance_window_no_logging = "ssm_maintenance_window_no_logging"
    ssm_no_host_mgmt_role = "ssm_no_host_mgmt_role"
    ssm_no_ops_center = "ssm_no_ops_center"
    ssm_automation_no_logging = "ssm_automation_no_logging"
    ssm_command_no_logging = "ssm_command_no_logging"
    ssm_doc_no_versioning = "ssm_doc_no_versioning"
    ssm_param_permissive = "ssm_param_permissive"
    ssm_param_stale = "ssm_param_stale"
    ssm_doc_stale = "ssm_doc_stale"
    ssm_no_inventory = "ssm_no_inventory"
    ssm_compliance_disabled = "ssm_compliance_disabled"
    ssm_state_manager_disabled = "ssm_state_manager_disabled"
    ssm_param_limit_high = "ssm_param_limit_high"
    ssm_default_kms_key = "ssm_default_kms_key"
    ssm_doc_hardcoded_creds = "ssm_doc_hardcoded_creds"
    ssm_param_no_policy = "ssm_param_no_policy"
    ssm_automation_no_role = "ssm_automation_no_role"
    ssm_no_change_calendar = "ssm_no_change_calendar"


SSM_SEVERITY = {
    "ssm_parameter_unencrypted": "High",
    "ssm_document_public": "High",
    "ssm_patch_manager_disabled": "High",
    "ssm_default_kms_key": "High",
    "ssm_doc_hardcoded_creds": "Critical",
    "ssm_param_public_tier": "Medium",
    "ssm_no_session_logging": "Medium",
    "ssm_maintenance_window_no_logging": "Medium",
    "ssm_no_host_mgmt_role": "Medium",
    "ssm_automation_no_logging": "Medium",
    "ssm_command_no_logging": "Medium",
    "ssm_param_permissive": "Medium",
    "ssm_compliance_disabled": "Medium",
    "ssm_state_manager_disabled": "Medium",
    "ssm_param_no_policy": "Medium",
    "ssm_automation_no_role": "Medium",
    "ssm_param_no_tags": "Low",
    "ssm_doc_no_description": "Low",
    "ssm_no_ops_center": "Low",
    "ssm_doc_no_versioning": "Low",
    "ssm_param_stale": "Low",
    "ssm_doc_stale": "Low",
    "ssm_no_inventory": "Low",
    "ssm_param_limit_high": "Low",
    "ssm_no_change_calendar": "Low",
}


SSM_MITRE_MAP = {
    "ssm_doc_hardcoded_creds": {
        "mitre_id": "T1552.004",
        "mitre_name": "Unsecured Credentials: Private Keys",
        "description": "SSM document contains hardcoded credentials",
        "remediation": "Remove credentials from documents; use IAM roles or Secrets Manager",
    },
    "ssm_parameter_unencrypted": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "SSM parameter stored as plaintext",
        "remediation": "Use SecureString for sensitive parameters with KMS",
    },
    "ssm_document_public": {
        "mitre_id": "T1526",
        "mitre_name": "Enumerate Cloud Resources",
        "description": "SSM document is publicly accessible",
        "remediation": "Set document to private; restrict sharing by account",
    },
    "ssm_patch_manager_disabled": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "SSM Patch Manager not configured",
        "remediation": "Enable Patch Manager for automated patching",
    },
    "ssm_default_kms_key": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "SSM using default AWS KMS key",
        "remediation": "Use customer-managed KMS key for parameters",
    },
    "ssm_param_public_tier": {
        "mitre_id": "T1526",
        "mitre_name": "Enumerate Cloud Resources",
        "description": "SSM parameter using Standard tier",
        "remediation": "Use Advanced tier for sensitive parameters",
    },
    "ssm_no_session_logging": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "SSM Session Manager logging not configured",
        "remediation": "Enable Session Manager CloudWatch logging",
    },
    "ssm_maintenance_window_no_logging": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "SSM maintenance window logging not configured",
        "remediation": "Enable logging for maintenance windows",
    },
    "ssm_no_host_mgmt_role": {
        "mitre_id": "T1078.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "description": "No host management role configured",
        "remediation": "Create IAM role for EC2 instance SSM access",
    },
    "ssm_automation_no_logging": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "SSM automation document logging not configured",
        "remediation": "Enable CloudWatch logging for automation documents",
    },
    "ssm_command_no_logging": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "SSM Run Command logging not configured",
        "remediation": "Enable CloudWatch logging for Run Command",
    },
    "ssm_param_permissive": {
        "mitre_id": "T1526",
        "mitre_name": "Enumerate Cloud Resources",
        "description": "SSM parameter has permissive access policy",
        "remediation": "Restrict parameter policy to least-privilege access",
    },
    "ssm_compliance_disabled": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "SSM Compliance Manager not configured",
        "remediation": "Enable SSM Compliance Manager",
    },
    "ssm_state_manager_disabled": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "SSM State Manager not configured",
        "remediation": "Configure State Manager for automated remediation",
    },
    "ssm_param_no_policy": {
        "mitre_id": "T1526",
        "mitre_name": "Enumerate Cloud Resources",
        "description": "SSM parameter has no resource policy",
        "remediation": "Define explicit parameter resource policy",
    },
    "ssm_automation_no_role": {
        "mitre_id": "T1078.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "description": "SSM automation document has no IAM role",
        "remediation": "Assign IAM role to automation document",
    },
    "ssm_param_no_tags": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "SSM parameter not tagged",
        "remediation": "Add tags to all SSM parameters",
    },
    "ssm_doc_no_description": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "SSM document lacks description",
        "remediation": "Add descriptive name and description to documents",
    },
    "ssm_no_ops_center": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "SSM OpsCenter not configured",
        "remediation": "Enable OpsCenter for centralized operations",
    },
    "ssm_doc_no_versioning": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "SSM document versioning not enabled",
        "remediation": "Enable document versioning for change control",
    },
    "ssm_param_stale": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "SSM parameter unchanged for 90+ days",
        "remediation": "Review and remove stale parameters",
    },
    "ssm_doc_stale": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "SSM document unchanged for 90+ days",
        "remediation": "Review and remove stale documents",
    },
    "ssm_no_inventory": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "SSM Inventory not enabled",
        "remediation": "Enable SSM Inventory for asset tracking",
    },
    "ssm_param_limit_high": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "SSM parameter count exceeds 10,000",
        "remediation": "Audit parameters; consolidate where possible",
    },
    "ssm_no_change_calendar": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "SSM Change Calendar not configured",
        "remediation": "Configure Change Calendar for scheduled changes",
    },
}
