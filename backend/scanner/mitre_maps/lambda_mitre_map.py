from enum import Enum


class LambdaVulnerability(str, Enum):
    lambda_overpermissive_role = "lambda_overpermissive_role"
    lambda_public_access = "lambda_public_access"
    lambda_no_vpc = "lambda_no_vpc"
    lambda_no_dlq = "lambda_no_dlq"
    lambda_xray_disabled = "lambda_xray_disabled"
    lambda_high_timeout = "lambda_high_timeout"
    lambda_high_memory = "lambda_high_memory"
    lambda_no_encryption = "lambda_no_encryption"
    lambda_no_logging = "lambda_no_logging"
    lambda_outdated_runtime = "lambda_outdated_runtime"
    lambda_no_reserved_concurrency = "lambda_no_reserved_concurrency"
    lambda_no_code_signing = "lambda_no_code_signing"
    lambda_env_not_encrypted = "lambda_env_not_encrypted"
    lambda_no_tags = "lambda_no_tags"
    lambda_no_description = "lambda_no_description"
    lambda_unrestricted_vpc = "lambda_unrestricted_vpc"
    lambda_ephemeral_unencrypted = "lambda_ephemeral_unencrypted"
    lambda_layer_not_vetted = "lambda_layer_not_vetted"
    lambda_function_url_enabled = "lambda_function_url_enabled"
    lambda_function_url_no_auth = "lambda_function_url_no_auth"
    lambda_function_url_cors_all = "lambda_function_url_cors_all"
    lambda_image_scan_disabled = "lambda_image_scan_disabled"
    lambda_role_trusts_all = "lambda_role_trusts_all"
    lambda_no_resource_policy = "lambda_no_resource_policy"


LAMBDA_SEVERITY = {
    "lambda_overpermissive_role": "High",
    "lambda_public_access": "High",
    "lambda_env_not_encrypted": "High",
    "lambda_ephemeral_unencrypted": "High",
    "lambda_function_url_no_auth": "High",
    "lambda_role_trusts_all": "High",
    "lambda_no_vpc": "Medium",
    "lambda_no_logging": "Medium",
    "lambda_outdated_runtime": "Medium",
    "lambda_no_code_signing": "Medium",
    "lambda_unrestricted_vpc": "Medium",
    "lambda_layer_not_vetted": "Medium",
    "lambda_function_url_enabled": "Medium",
    "lambda_function_url_cors_all": "Medium",
    "lambda_image_scan_disabled": "Medium",
    "lambda_no_resource_policy": "Medium",
    "lambda_no_dlq": "Low",
    "lambda_xray_disabled": "Low",
    "lambda_high_timeout": "Low",
    "lambda_high_memory": "Low",
    "lambda_no_encryption": "Medium",
    "lambda_no_tags": "Low",
    "lambda_no_description": "Low",
    "lambda_no_reserved_concurrency": "Low",
}


LAMBDA_MITRE_MAP = {
    "lambda_overpermissive_role": {
        "mitre_id": "T1098.003",
        "mitre_name": "Account Manipulation: Cloud Roles/Permissions",
        "description": "Lambda function has overly permissive execution role",
        "remediation": "Apply least-privilege IAM role to Lambda function",
    },
    "lambda_public_access": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Lambda function has public resource policy",
        "remediation": "Restrict Lambda function access via resource policy",
    },
    "lambda_env_not_encrypted": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "Lambda environment variables not encrypted",
        "remediation": "Enable KMS encryption for Lambda environment variables",
    },
    "lambda_ephemeral_unencrypted": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "Lambda ephemeral storage not encrypted",
        "remediation": "Enable KMS encryption for ephemeral storage",
    },
    "lambda_function_url_no_auth": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Lambda Function URL has no authentication",
        "remediation": "Require AWS IAM authentication for Function URL",
    },
    "lambda_role_trusts_all": {
        "mitre_id": "T1098.003",
        "mitre_name": "Account Manipulation: Cloud Roles/Permissions",
        "description": "Lambda execution role trust policy allows all principals",
        "remediation": "Restrict role trust policy to specific Lambda service/ARNs",
    },
    "lambda_no_vpc": {
        "mitre_id": "T1570",
        "mitre_name": "Lateral Tool Transfer",
        "description": "Lambda function not deployed in VPC",
        "remediation": "Deploy Lambda in VPC for network isolation",
    },
    "lambda_no_logging": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "Lambda function logging to CloudWatch not enabled",
        "remediation": "Enable CloudWatch Logs for Lambda functions",
    },
    "lambda_outdated_runtime": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Lambda using deprecated or end-of-life runtime",
        "remediation": "Update Lambda to latest supported runtime version",
    },
    "lambda_no_code_signing": {
        "mitre_id": "T1204",
        "mitre_name": "User Execution",
        "description": "Lambda function code not signed",
        "remediation": "Enable code signing for Lambda functions",
    },
    "lambda_unrestricted_vpc": {
        "mitre_id": "T1570",
        "mitre_name": "Lateral Tool Transfer",
        "description": "Lambda VPC security group allows unrestricted access",
        "remediation": "Restrict Lambda VPC to specific subnets and security groups",
    },
    "lambda_layer_not_vetted": {
        "mitre_id": "T1204",
        "mitre_name": "User Execution",
        "description": "Lambda function using unvetted layer",
        "remediation": "Only use Lambda layers from trusted sources",
    },
    "lambda_function_url_enabled": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Lambda Function URL is enabled",
        "remediation": "Disable Function URL if not needed, require authentication",
    },
    "lambda_function_url_cors_all": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Lambda Function URL CORS allows all origins",
        "remediation": "Restrict CORS to trusted origins only",
    },
    "lambda_image_scan_disabled": {
        "mitre_id": "T1204",
        "mitre_name": "User Execution",
        "description": "Lambda container image scanning not enabled",
        "remediation": "Enable container image scanning in Lambda",
    },
    "lambda_no_resource_policy": {
        "mitre_id": "T1078.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "description": "Lambda function has no resource policy",
        "remediation": "Define explicit resource policy for Lambda",
    },
    "lambda_no_dlq": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "Lambda function has no DLQ configured",
        "remediation": "Configure Dead Letter Queue for Lambda",
    },
    "lambda_xray_disabled": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "Lambda function X-Ray tracing not enabled",
        "remediation": "Enable X-Ray tracing for Lambda functions",
    },
    "lambda_high_timeout": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "Lambda function timeout set too high (>15 minutes)",
        "remediation": "Set appropriate timeout for function workload",
    },
    "lambda_high_memory": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "Lambda memory set to maximum or very high",
        "remediation": "Set appropriate memory for function workload",
    },
    "lambda_no_encryption": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "Lambda function encryption not enabled",
        "remediation": "Enable KMS encryption for Lambda storage",
    },
    "lambda_no_tags": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "Lambda function not tagged",
        "remediation": "Add tags to all Lambda functions",
    },
    "lambda_no_description": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "Lambda function lacks description",
        "remediation": "Add descriptive name and description to functions",
    },
    "lambda_no_reserved_concurrency": {
        "mitre_id": "T1499",
        "mitre_name": "Endpoint Denial of Service",
        "description": "Lambda function has no reserved concurrency",
        "remediation": "Set reserved concurrency for predictable workloads",
    },
}
