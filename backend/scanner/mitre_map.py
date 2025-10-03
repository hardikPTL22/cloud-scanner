from enum import Enum


class Vulnerability(str, Enum):
    public_s3_bucket = "public_s3_bucket"
    unencrypted_s3_bucket = "unencrypted_s3_bucket"
    s3_bucket_versioning_disabled = "s3_bucket_versioning_disabled"
    s3_bucket_logging_disabled = "s3_bucket_logging_disabled"
    s3_bucket_block_public_access_disabled = "s3_bucket_block_public_access_disabled"
    over_permissive_iam = "over_permissive_iam"
    iam_user_no_mfa = "iam_user_no_mfa"
    iam_unused_access_key = "iam_unused_access_key"
    iam_inline_policy = "iam_inline_policy"
    iam_root_access_key = "iam_root_access_key"
    open_security_group_ingress = "open_security_group_ingress"
    open_security_group_egress = "open_security_group_egress"
    unused_security_group = "unused_security_group"
    cloudtrail_not_logging = "cloudtrail_not_logging"
    cloudtrail_not_multi_region = "cloudtrail_not_multi_region"
    cloudtrail_no_log_file_validation = "cloudtrail_no_log_file_validation"
    cloudtrail_bucket_public = "cloudtrail_bucket_public"
    cloudtrail_bucket_encryption_disabled = "cloudtrail_bucket_encryption_disabled"
    guardduty_disabled = "guardduty_disabled"
    vpc_flow_logs_disabled = "vpc_flow_logs_disabled"
    ebs_volume_unencrypted = "ebs_volume_unencrypted"
    rds_instance_unencrypted = "rds_instance_unencrypted"
    rds_instance_public_access = "rds_instance_public_access"
    ssm_parameter_unencrypted = "ssm_parameter_unencrypted"
    lambda_overpermissive_role = "lambda_overpermissive_role"
    lambda_public_access = "lambda_public_access"
    apigateway_open_resource = "apigateway_open_resource"
    iam_user_with_console_access = "iam_user_with_console_access"
    ec2_instance_public_ip = "ec2_instance_public_ip"


SEVERITY = {
    Vulnerability.public_s3_bucket: "High",
    Vulnerability.over_permissive_iam: "High",
    Vulnerability.unencrypted_s3_bucket: "Medium",
    Vulnerability.cloudtrail_not_logging: "High",
    Vulnerability.s3_bucket_versioning_disabled: "Medium",
    Vulnerability.s3_bucket_logging_disabled: "Medium",
    Vulnerability.s3_bucket_block_public_access_disabled: "High",
    Vulnerability.iam_user_no_mfa: "High",
    Vulnerability.iam_unused_access_key: "Medium",
    Vulnerability.iam_inline_policy: "Medium",
    Vulnerability.iam_root_access_key: "High",
    Vulnerability.open_security_group_ingress: "High",
    Vulnerability.open_security_group_egress: "Medium",
    Vulnerability.unused_security_group: "Low",
    Vulnerability.cloudtrail_not_multi_region: "Medium",
    Vulnerability.cloudtrail_no_log_file_validation: "Medium",
    Vulnerability.cloudtrail_bucket_public: "High",
    Vulnerability.cloudtrail_bucket_encryption_disabled: "High",
    Vulnerability.guardduty_disabled: "High",
    Vulnerability.vpc_flow_logs_disabled: "Medium",
    Vulnerability.ebs_volume_unencrypted: "High",
    Vulnerability.rds_instance_unencrypted: "High",
    Vulnerability.rds_instance_public_access: "High",
    Vulnerability.ssm_parameter_unencrypted: "High",
    Vulnerability.lambda_overpermissive_role: "High",
    Vulnerability.lambda_public_access: "High",
    Vulnerability.apigateway_open_resource: "High",
    Vulnerability.iam_user_with_console_access: "Medium",
    Vulnerability.ec2_instance_public_ip: "Medium",
}


MITRE_MAP = {
    Vulnerability.public_s3_bucket: {
        "techniques": [
            {
                "id": "T1530",
                "name": "Data from Cloud Storage",
                "desc": "Adversaries may access or exfiltrate data from cloud storage (e.g., S3) if buckets or objects are publicly accessible.",
                "remediation": "Disable public ACLs/policies, enable S3 Block Public Access, apply least-privilege bucket policies, enable logging and encryption.",
            }
        ],
        "note": "Public S3 buckets may allow anyone to list or download objects.",
        "details": "Bucket has public ACL or bucket policy allowing public read.",
    },
    Vulnerability.s3_bucket_versioning_disabled: {
        "techniques": [
            {
                "id": "T1530",
                "name": "Data from Cloud Storage",
                "desc": "Lack of versioning might result in data loss or inability to recover from accidental deletion or ransomware.",
                "remediation": "Enable bucket versioning to preserve, retrieve, and restore every version of every object in a bucket.",
            }
        ],
        "note": "Versioning improves data durability and recovery options.",
        "details": "Bucket versioning is not enabled.",
    },
    Vulnerability.unencrypted_s3_bucket: {
        "techniques": [
            {
                "id": "T1530",
                "name": "Data from Cloud Storage",
                "desc": (
                    "Adversaries may access or exfiltrate data from cloud storage if "
                    "S3 buckets or objects are not encrypted at rest. Lack of "
                    "server-side encryption increases the risk of data exposure if "
                    "credentials are compromised or the storage is accessed "
                    "without authorization."
                ),
                "remediation": (
                    "Enable default bucket encryption (SSE-S3 or SSE-KMS) for all "
                    "S3 buckets, enforce TLS for data in transit, and restrict "
                    "access with IAM and bucket policies."
                ),
            }
        ],
        "note": "Encryption at rest protects S3 data from unauthorized access even if the storage layer is compromised.",
        "details": "Bucket does not have default server-side encryption configured.",
    },
    Vulnerability.s3_bucket_logging_disabled: {
        "techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "desc": "Missing access logging reduces visibility into bucket access, delaying detection of unauthorized usage.",
                "remediation": "Enable S3 access logging.",
            }
        ],
        "note": "Access logs improve forensics and monitoring.",
        "details": "Bucket logging is not enabled.",
    },
    Vulnerability.s3_bucket_block_public_access_disabled: {
        "techniques": [
            {
                "id": "T1530",
                "name": "Data from Cloud Storage",
                "desc": "Block Public Access settings disabled can allow unintended public access to buckets.",
                "remediation": "Enable and enforce Block Public Access settings account-wide or per bucket.",
            }
        ],
        "note": "Block Public Access prevents accidental exposure.",
        "details": "Bucket block public access settings are not fully enabled.",
    },
    Vulnerability.over_permissive_iam: {
        "techniques": [
            {
                "id": "T1098.003",
                "name": "Account Manipulation (Cloud Roles/Permissions)",
                "desc": "Overly permissive IAM policies allow adversaries to escalate privileges or persist in the environment.",
                "remediation": "Enforce least privilege, review and remove '*' actions/resources, use IAM Access Analyzer, enable MFA and monitoring.",
            },
            {
                "id": "T1078.004",
                "name": "Valid Accounts (Cloud Accounts)",
                "desc": "Compromised or misconfigured valid accounts may be used by adversaries to act within the cloud environment.",
                "remediation": "Rotate credentials, monitor for anomalous API calls, restrict long-lived credentials.",
            },
        ],
        "note": "Policies with Action or Resource set to '*' are high risk.",
        "details": "Bucket block public access settings are not fully enabled.",
    },
    Vulnerability.iam_user_no_mfa: {
        "techniques": [
            {
                "id": "T1098.003",
                "name": "Account Manipulation",
                "desc": "Users without MFA are more vulnerable to credential compromise.",
                "remediation": "Require and enforce MFA for all users.",
            }
        ],
        "note": "MFA is critical for protecting account access.",
        "details": "IAM user does not have MFA enabled.",
    },
    Vulnerability.iam_unused_access_key: {
        "techniques": [
            {
                "id": "T1078.004",
                "name": "Valid Accounts",
                "desc": "Unused credentials may be forgotten but can be used by attackers if compromised.",
                "remediation": "Rotate or disable unused access keys regularly.",
            }
        ],
        "note": "Managing credential lifecycle is good hygiene.",
        "details": "IAM access key unused for over 90 days.",
    },
    Vulnerability.iam_inline_policy: {
        "techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "desc": "Inline policies complicate management and increase attack surface.",
                "remediation": "Use managed policies to improve visibility and control.",
            }
        ],
        "note": "Inline policies are harder to audit and control.",
        "details": "IAM inline policy attached to user or role.",
    },
    Vulnerability.iam_root_access_key: {
        "techniques": [
            {
                "id": "T1098",
                "name": "Account Manipulation",
                "desc": "Root access keys pose extremely high risk if compromised.",
                "remediation": "Avoid using root keys; remove root access keys if possible; secure root account with MFA and strong credentials.",
            }
        ],
        "note": "Root credentials should be tightly controlled.",
        "details": "Root user has access keys, which is risky.",
    },
    Vulnerability.open_security_group_ingress: {
        "techniques": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application / Exposed Services",
                "desc": "Security groups with wide ingress exposure increase risk.",
                "remediation": "Limit ingress rules to known IPs where possible, avoid open 0.0.0.0/0.",
            }
        ],
        "note": "Open ingress rules increase attack surface.",
        "details": "Security group has ingress rule open to the world.",
    },
    Vulnerability.open_security_group_egress: {
        "techniques": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application / Exposed Services",
                "desc": "Open egress may allow data exfiltration or unwanted outbound traffic.",
                "remediation": "Restrict egress rules tightly.",
            }
        ],
        "note": "Open egress rules can facilitate exfiltration.",
        "details": "Security group has egress rule open to the world.",
    },
    Vulnerability.unused_security_group: {
        "techniques": [
            {
                "id": "T1070",
                "name": "Indicator Removal on Host",
                "desc": "Unused security groups increase attack surface and complicate management.",
                "remediation": "Remove or audit unused security groups regularly.",
            }
        ],
        "note": "Clean up unused resources for security hygiene.",
        "details": "Security group is not attached to any resource.",
    },
    Vulnerability.cloudtrail_not_logging: {
        "techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts / Cloud Log Tampering",
                "desc": "If CloudTrail is not logging, it becomes harder to detect abuse or suspicious API activity.",
                "remediation": "Enable CloudTrail across all regions, ensure logging is active.",
            }
        ],
        "note": "CloudTrail logging is critical for detection.",
        "details": "CloudTrail exists but not logging.",
    },
    Vulnerability.cloudtrail_not_multi_region: {
        "techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts / Cloud Log Tampering",
                "desc": "CloudTrail should be multi-region to cover all API activity.",
                "remediation": "Enable multi-region CloudTrail.",
            }
        ],
        "note": "Multi-region improves visibility and security.",
        "details": "CloudTrail is not multi-region.",
    },
    Vulnerability.cloudtrail_no_log_file_validation: {
        "techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts / Cloud Log Tampering",
                "desc": "Log file validation prevents tampering with CloudTrail logs.",
                "remediation": "Enable log file validation for integrity checks.",
            }
        ],
        "note": "Enables trustworthiness of logs.",
        "details": "CloudTrail log file validation is not enabled.",
    },
    Vulnerability.cloudtrail_bucket_public: {
        "techniques": [
            {
                "id": "T1530",
                "name": "Data from Cloud Storage",
                "desc": "CloudTrail logs stored in publicly accessible buckets risk exposure.",
                "remediation": "Ensure S3 buckets storing logs are not public.",
            }
        ],
        "note": "Secure CloudTrail buckets against public access.",
        "details": "CloudTrail log bucket is publicly accessible.",
    },
    Vulnerability.cloudtrail_bucket_encryption_disabled: {
        "techniques": [
            {
                "id": "T1530",
                "name": "Data from Cloud Storage",
                "desc": "CloudTrail logs stored in unencrypted S3 buckets are at risk of exposure.",
                "remediation": "Enable encryption on S3 buckets storing CloudTrail logs.",
            }
        ],
        "note": "Encrypted buckets prevent log data exposure.",
        "details": "CloudTrail log bucket encryption is disabled or missing.",
    },
    Vulnerability.guardduty_disabled: {
        "techniques": [
            {
                "id": "T1064",
                "name": "Security Monitoring",
                "desc": "GuardDuty provides intelligent threat detection.",
                "remediation": "Enable GuardDuty on all supported regions and accounts.",
            }
        ],
        "note": "GuardDuty helps detect threats early.",
        "details": "GuardDuty is not enabled.",
    },
    Vulnerability.vpc_flow_logs_disabled: {
        "techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts / Network Monitoring",
                "desc": "VPC Flow Logs capture network traffic metadata.",
                "remediation": "Enable flow logs for all VPCs.",
            }
        ],
        "note": "Flow logs help detect malicious network activity.",
        "details": "VPC Flow Logs are not enabled.",
    },
    Vulnerability.ebs_volume_unencrypted: {
        "techniques": [
            {
                "id": "T1530",
                "name": "Data from Cloud Storage",
                "desc": "Unencrypted EBS volumes risk data exposure if compromised.",
                "remediation": "Enable encryption for all EBS volumes.",
            }
        ],
        "note": "Encryption protects data at rest.",
        "details": "EBS volume is not encrypted.",
    },
    Vulnerability.rds_instance_unencrypted: {
        "techniques": [
            {
                "id": "T1530",
                "name": "Data from Cloud Storage",
                "desc": "Unencrypted RDS instances risk data exposure if compromised.",
                "remediation": "Enable encryption for all RDS storage.",
            }
        ],
        "note": "Encryption protects database storage.",
        "details": "RDS instance storage is not encrypted.",
    },
    Vulnerability.rds_instance_public_access: {
        "techniques": [
            {
                "id": "T1530",
                "name": "Data from Cloud Storage",
                "desc": "Publicly accessible RDS instances risk unauthorized data access.",
                "remediation": "Restrict RDS instance to private subnets or use proper security groups.",
            }
        ],
        "note": "Public accessibility increases attack surface.",
        "details": "RDS instance is publicly accessible.",
    },
    Vulnerability.ssm_parameter_unencrypted: {
        "techniques": [
            {
                "id": "T1530",
                "name": "Data from Cloud Storage",
                "desc": "Unencrypted SSM parameters may expose sensitive data.",
                "remediation": "Encrypt parameters and restrict access.",
            }
        ],
        "note": "Encrypt sensitive parameters in SSM.",
        "details": "SSM parameter is unencrypted or could not be decrypted.",
    },
    Vulnerability.lambda_overpermissive_role: {
        "techniques": [
            {
                "id": "T1098.003",
                "name": "Account Manipulation (Cloud Roles/Permissions)",
                "desc": "Lambda functions with overly permissive roles can be exploited.",
                "remediation": "Apply least privilege roles to Lambda functions.",
            }
        ],
        "note": "Least privilege limits function access.",
        "details": "Lambda function assigned role with overly permissive policies.",
    },
    Vulnerability.lambda_public_access: {
        "techniques": [
            {
                "id": "T1098.003",
                "name": "Account Manipulation (Cloud Roles/Permissions)",
                "desc": "Lambda functions with public access can be triggered by unauthorized parties.",
                "remediation": "Apply strict IAM roles and resource policies limiting invocation.",
            }
        ],
        "note": "Restrict Lambda invocation to trusted principals.",
        "details": "Lambda function possibly has public access.",
    },
    Vulnerability.apigateway_open_resource: {
        "techniques": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application / Exposed Services",
                "desc": "API Gateway endpoints without authorization allow open access.",
                "remediation": "Require authentication and authorization for all endpoints.",
            }
        ],
        "note": "Open APIs risk unauthorized access.",
        "details": "API Gateway resource allows open access without authorization.",
    },
    Vulnerability.iam_user_with_console_access: {
        "techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "desc": "Users with console access increase attack surface if credentials are compromised.",
                "remediation": "Review and limit console access to necessary users only.",
            }
        ],
        "note": "Console access should be carefully controlled.",
        "details": "IAM user has console login enabled.",
    },
    Vulnerability.ec2_instance_public_ip: {
        "techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "desc": "EC2 instances with public IP addresses are directly accessible from the internet.",
                "remediation": "Limit public IP usage and secure instances with security groups and NACLs.",
            }
        ],
        "note": "Public IP increases attack surface.",
        "details": "EC2 instance has a public IPv4 address.",
    },
}


def new_vulnerability(type, resource):
    return {
        "type": type,
        "name": resource,
        "severity": SEVERITY[type],
        "details": MITRE_MAP[type]["details"],
    }
