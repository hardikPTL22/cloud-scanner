from enum import Enum


class IAMVulnerability(str, Enum):
    over_permissive_iam = "over_permissive_iam"
    iam_user_no_mfa = "iam_user_no_mfa"
    iam_unused_access_key = "iam_unused_access_key"
    iam_inline_policy = "iam_inline_policy"
    iam_root_access_key = "iam_root_access_key"
    iam_root_mfa_disabled = "iam_root_mfa_disabled"
    iam_old_access_key = "iam_old_access_key"
    iam_no_password_policy = "iam_no_password_policy"
    iam_weak_password_policy = "iam_weak_password_policy"
    iam_user_direct_policy = "iam_user_direct_policy"
    iam_role_direct_policy = "iam_role_direct_policy"
    iam_empty_group = "iam_empty_group"
    iam_user_no_access_key = "iam_user_no_access_key"
    iam_no_saml_provider = "iam_no_saml_provider"
    iam_role_trusts_all = "iam_role_trusts_all"
    iam_role_admin_access = "iam_role_admin_access"
    iam_multiple_access_keys = "iam_multiple_access_keys"
    iam_no_credential_report = "iam_no_credential_report"
    iam_no_ssh_key = "iam_no_ssh_key"
    iam_user_no_tags = "iam_user_no_tags"
    iam_role_no_tags = "iam_role_no_tags"
    iam_policy_no_tags = "iam_policy_no_tags"
    iam_unused_policy = "iam_unused_policy"
    iam_user_with_console_access = "iam_user_with_console_access"
    iam_policy_wildcard = "iam_policy_wildcard"
    iam_inactive_user = "iam_inactive_user"


IAM_SEVERITY = {
    "iam_root_access_key": "Critical",
    "iam_root_mfa_disabled": "Critical",
    "over_permissive_iam": "High",
    "iam_user_no_mfa": "High",
    "iam_no_password_policy": "High",
    "iam_role_trusts_all": "High",
    "iam_role_admin_access": "High",
    "iam_policy_wildcard": "High",
    "iam_weak_password_policy": "Medium",
    "iam_unused_access_key": "Medium",
    "iam_inline_policy": "Medium",
    "iam_old_access_key": "Medium",
    "iam_user_direct_policy": "Medium",
    "iam_role_direct_policy": "Medium",
    "iam_empty_group": "Medium",
    "iam_no_saml_provider": "Medium",
    "iam_multiple_access_keys": "Medium",
    "iam_inactive_user": "Medium",
    "iam_user_with_console_access": "Low",
    "iam_no_credential_report": "Low",
    "iam_user_no_access_key": "Low",
    "iam_no_ssh_key": "Low",
    "iam_user_no_tags": "Low",
    "iam_role_no_tags": "Low",
    "iam_policy_no_tags": "Low",
    "iam_unused_policy": "Low",
}


IAM_MITRE_MAP = {
    "iam_root_access_key": {
        "mitre_id": "T1098",
        "mitre_name": "Account Manipulation",
        "description": "Root account has active access keys",
        "remediation": "Delete root access keys; use IAM users with temporary credentials",
    },
    "iam_root_mfa_disabled": {
        "mitre_id": "T1098.003",
        "mitre_name": "Account Manipulation: Cloud Account",
        "description": "Root account MFA not enabled",
        "remediation": "Enable MFA on root account immediately",
    },
    "over_permissive_iam": {
        "mitre_id": "T1098.003",
        "mitre_name": "Account Manipulation: Cloud Roles/Permissions",
        "description": "IAM policy contains wildcard permissions",
        "remediation": "Review and remove wildcard permissions; enforce least privilege",
    },
    "iam_user_no_mfa": {
        "mitre_id": "T1098.003",
        "mitre_name": "Account Manipulation",
        "description": "IAM user does not have MFA enabled",
        "remediation": "Enable MFA for all IAM users, especially privileged ones",
    },
    "iam_no_password_policy": {
        "mitre_id": "T1098.003",
        "mitre_name": "Account Manipulation",
        "description": "No password policy configured for account",
        "remediation": "Enforce strong password policy requiring complexity, length, rotation",
    },
    "iam_role_trusts_all": {
        "mitre_id": "T1098.003",
        "mitre_name": "Account Manipulation",
        "description": "IAM role trust policy allows all principals",
        "remediation": "Restrict role trust policy to specific AWS accounts/services",
    },
    "iam_role_admin_access": {
        "mitre_id": "T1098.003",
        "mitre_name": "Account Manipulation: Cloud Roles/Permissions",
        "description": "IAM role has AdministratorAccess policy",
        "remediation": "Replace admin access with specific least-privilege permissions",
    },
    "iam_policy_wildcard": {
        "mitre_id": "T1098.003",
        "mitre_name": "Account Manipulation: Cloud Roles/Permissions",
        "description": "IAM policy contains wildcard in actions or resources",
        "remediation": "Replace wildcards with specific actions and resource ARNs",
    },
    "iam_weak_password_policy": {
        "mitre_id": "T1098.003",
        "mitre_name": "Account Manipulation",
        "description": "Password policy requirements too weak",
        "remediation": "Enforce strong password requirements (length, complexity, expiry)",
    },
    "iam_unused_access_key": {
        "mitre_id": "T1078.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "description": "Access key unused for 90+ days",
        "remediation": "Rotate or delete unused access keys regularly",
    },
    "iam_inline_policy": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "IAM inline policy attached to user/role",
        "remediation": "Use managed policies for better visibility and control",
    },
    "iam_old_access_key": {
        "mitre_id": "T1078.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "description": "Access key created 90+ days ago",
        "remediation": "Rotate access keys at least annually",
    },
    "iam_user_direct_policy": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "IAM user has directly attached policies",
        "remediation": "Use groups and roles for policy management",
    },
    "iam_role_direct_policy": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "IAM role has directly attached policies",
        "remediation": "Use managed policies for better control",
    },
    "iam_empty_group": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "IAM group has no members",
        "remediation": "Remove empty groups or add members",
    },
    "iam_no_saml_provider": {
        "mitre_id": "T1078.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "description": "No SAML provider configured",
        "remediation": "Configure SAML provider for federated authentication",
    },
    "iam_multiple_access_keys": {
        "mitre_id": "T1078.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "description": "IAM user has multiple active access keys",
        "remediation": "Limit users to one active access key",
    },
    "iam_inactive_user": {
        "mitre_id": "T1078.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "description": "IAM user inactive for 90+ days",
        "remediation": "Remove or disable inactive users",
    },
    "iam_user_with_console_access": {
        "mitre_id": "T1078.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "description": "IAM user has console login enabled",
        "remediation": "Limit console access to necessary users only",
    },
    "iam_no_credential_report": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "IAM credential report not generated",
        "remediation": "Generate credential report regularly",
    },
    "iam_no_ssh_key": {
        "mitre_id": "T1021.006",
        "mitre_name": "Remote Services: OpenSSH",
        "description": "IAM user has no SSH public key",
        "remediation": "Generate SSH keys for users who need SSH access",
    },
    "iam_user_no_tags": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "IAM user not tagged",
        "remediation": "Add tags to all IAM users for organization",
    },
    "iam_role_no_tags": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "IAM role not tagged",
        "remediation": "Add tags to all IAM roles for organization",
    },
    "iam_policy_no_tags": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "IAM managed policy not tagged",
        "remediation": "Add tags to managed policies for organization",
    },
    "iam_unused_policy": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "IAM managed policy is not in use",
        "remediation": "Delete or archive unused managed policies",
    },
}
