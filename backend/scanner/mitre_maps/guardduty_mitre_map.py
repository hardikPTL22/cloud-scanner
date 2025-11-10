from enum import Enum


class GuardDutyVulnerability(str, Enum):
    guardduty_disabled = "guardduty_disabled"
    guardduty_finding_freq_not_optimal = "guardduty_finding_freq_not_optimal"
    guardduty_no_s3_protection = "guardduty_no_s3_protection"
    guardduty_no_eks_protection = "guardduty_no_eks_protection"
    guardduty_no_lambda_protection = "guardduty_no_lambda_protection"
    guardduty_no_rds_protection = "guardduty_no_rds_protection"
    guardduty_no_cloudwatch_logs = "guardduty_no_cloudwatch_logs"
    guardduty_no_threat_intel = "guardduty_no_threat_intel"
    guardduty_findings_not_archived = "guardduty_findings_not_archived"
    guardduty_no_ip_set = "guardduty_no_ip_set"
    guardduty_no_member_accounts = "guardduty_no_member_accounts"
    guardduty_high_severity_findings = "guardduty_high_severity_findings"
    guardduty_detector_no_tags = "guardduty_detector_no_tags"
    guardduty_no_member_invitations = "guardduty_no_member_invitations"
    guardduty_no_master_account = "guardduty_no_master_account"
    guardduty_no_vpc_flow_logs = "guardduty_no_vpc_flow_logs"
    guardduty_no_cloudtrail = "guardduty_no_cloudtrail"
    guardduty_no_findings_export = "guardduty_no_findings_export"
    guardduty_no_sns_notification = "guardduty_no_sns_notification"
    guardduty_orphaned_detector = "guardduty_orphaned_detector"
    guardduty_no_custom_ip_set = "guardduty_no_custom_ip_set"
    guardduty_no_custom_threat_intel = "guardduty_no_custom_threat_intel"
    guardduty_malware_protection_disabled = "guardduty_malware_protection_disabled"
    guardduty_runtime_monitoring_disabled = "guardduty_runtime_monitoring_disabled"


GUARDDUTY_SEVERITY = {
    "guardduty_disabled": "Critical",
    "guardduty_no_s3_protection": "High",
    "guardduty_no_eks_protection": "High",
    "guardduty_no_lambda_protection": "High",
    "guardduty_no_rds_protection": "High",
    "guardduty_malware_protection_disabled": "High",
    "guardduty_runtime_monitoring_disabled": "High",
    "guardduty_high_severity_findings": "High",
    "guardduty_finding_freq_not_optimal": "Medium",
    "guardduty_no_cloudwatch_logs": "Medium",
    "guardduty_no_ip_set": "Medium",
    "guardduty_no_master_account": "Medium",
    "guardduty_no_vpc_flow_logs": "Medium",
    "guardduty_no_cloudtrail": "Medium",
    "guardduty_no_findings_export": "Medium",
    "guardduty_no_sns_notification": "Medium",
    "guardduty_no_threat_intel": "Low",
    "guardduty_findings_not_archived": "Low",
    "guardduty_no_member_accounts": "Low",
    "guardduty_detector_no_tags": "Low",
    "guardduty_no_member_invitations": "Low",
    "guardduty_orphaned_detector": "Low",
    "guardduty_no_custom_ip_set": "Low",
    "guardduty_no_custom_threat_intel": "Low",
}


GUARDDUTY_MITRE_MAP = {
    "guardduty_disabled": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "GuardDuty detector is not enabled",
        "remediation": "Enable GuardDuty on all supported regions and accounts",
    },
    "guardduty_no_s3_protection": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "GuardDuty S3 protection not enabled",
        "remediation": "Enable S3 protection in GuardDuty",
    },
    "guardduty_no_eks_protection": {
        "mitre_id": "T1610",
        "mitre_name": "Deploy Containers",
        "description": "GuardDuty EKS protection not enabled",
        "remediation": "Enable EKS protection in GuardDuty",
    },
    "guardduty_no_lambda_protection": {
        "mitre_id": "T1648",
        "mitre_name": "Serverless Execution",
        "description": "GuardDuty Lambda protection not enabled",
        "remediation": "Enable Lambda protection in GuardDuty",
    },
    "guardduty_no_rds_protection": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "GuardDuty RDS protection not enabled",
        "remediation": "Enable RDS protection in GuardDuty",
    },
    "guardduty_malware_protection_disabled": {
        "mitre_id": "T1204",
        "mitre_name": "User Execution",
        "description": "GuardDuty malware protection not enabled",
        "remediation": "Enable malware protection in GuardDuty",
    },
    "guardduty_runtime_monitoring_disabled": {
        "mitre_id": "T1204",
        "mitre_name": "User Execution",
        "description": "GuardDuty runtime monitoring not enabled",
        "remediation": "Enable runtime monitoring in GuardDuty",
    },
    "guardduty_finding_freq_not_optimal": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "GuardDuty finding frequency not set to 15 minutes",
        "remediation": "Set finding frequency to 15 minutes for real-time alerts",
    },
    "guardduty_no_cloudwatch_logs": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "GuardDuty findings not exported to CloudWatch",
        "remediation": "Export GuardDuty findings to CloudWatch Logs",
    },
    "guardduty_high_severity_findings": {
        "mitre_id": "T1021",
        "mitre_name": "Remote Services",
        "description": "GuardDuty has unaddressed high-severity findings",
        "remediation": "Investigate and remediate all high-severity findings immediately",
    },
    "guardduty_no_threat_intel": {
        "mitre_id": "T1595",
        "mitre_name": "Active Scanning",
        "description": "GuardDuty not using threat intelligence feeds",
        "remediation": "Enable threat intelligence feeds in GuardDuty",
    },
    "guardduty_findings_not_archived": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "GuardDuty findings not properly archived",
        "remediation": "Archive resolved findings to keep console clear",
    },
    "guardduty_no_ip_set": {
        "mitre_id": "T1598",
        "mitre_name": "Phishing for Information",
        "description": "GuardDuty IP sets not configured",
        "remediation": "Create IP sets for trusted and known-bad IPs",
    },
    "guardduty_no_member_accounts": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "GuardDuty member accounts not configured",
        "remediation": "Invite member accounts to GuardDuty organization",
    },
    "guardduty_no_master_account": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "GuardDuty master account not configured",
        "remediation": "Designate a master account for organization GuardDuty",
    },
    "guardduty_no_vpc_flow_logs": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "VPC Flow Logs not enabled for GuardDuty",
        "remediation": "Enable VPC Flow Logs for GuardDuty analysis",
    },
    "guardduty_no_cloudtrail": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "CloudTrail not enabled for GuardDuty",
        "remediation": "Enable CloudTrail for GuardDuty analysis",
    },
    "guardduty_no_findings_export": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "GuardDuty findings not exported",
        "remediation": "Export findings to S3 or CloudWatch for analysis",
    },
    "guardduty_no_sns_notification": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "GuardDuty SNS notifications not configured",
        "remediation": "Configure SNS notifications for GuardDuty findings",
    },
    "guardduty_orphaned_detector": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "GuardDuty detector not updated in 90+ days",
        "remediation": "Delete orphaned detectors or ensure they are active",
    },
    "guardduty_detector_no_tags": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "GuardDuty detector not tagged",
        "remediation": "Tag all GuardDuty detectors for organization",
    },
    "guardduty_no_member_invitations": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "No member account invitations sent",
        "remediation": "Send invitations to member accounts",
    },
    "guardduty_no_custom_ip_set": {
        "mitre_id": "T1598",
        "mitre_name": "Phishing for Information",
        "description": "GuardDuty custom IP sets not configured",
        "remediation": "Create custom IP sets for threat intelligence",
    },
    "guardduty_no_custom_threat_intel": {
        "mitre_id": "T1598",
        "mitre_name": "Phishing for Information",
        "description": "GuardDuty custom threat intelligence not configured",
        "remediation": "Configure custom threat intelligence feeds",
    },
}
