from enum import Enum


class APIGatewayVulnerability(str, Enum):
    apigateway_open_resource = "apigateway_open_resource"
    apigateway_no_cors = "apigateway_no_cors"
    apigateway_cors_all_origins = "apigateway_cors_all_origins"
    apigateway_no_waf = "apigateway_no_waf"
    apigateway_no_logging = "apigateway_no_logging"
    apigateway_no_throttling = "apigateway_no_throttling"
    apigateway_no_xray = "apigateway_no_xray"
    apigateway_default_method = "apigateway_default_method"
    apigateway_no_ssl = "apigateway_no_ssl"
    apigateway_no_auth = "apigateway_no_auth"
    apigateway_no_api_key = "apigateway_no_api_key"
    apigateway_no_request_validation = "apigateway_no_request_validation"
    apigateway_no_cache = "apigateway_no_cache"
    apigateway_cache_unencrypted = "apigateway_cache_unencrypted"
    apigateway_no_execution_logs = "apigateway_no_execution_logs"
    apigateway_plaintext_logs = "apigateway_plaintext_logs"
    apigateway_no_access_logs = "apigateway_no_access_logs"
    apigateway_no_domain_cert = "apigateway_no_domain_cert"
    apigateway_certificate_expired = "apigateway_certificate_expired"
    apigateway_no_cloudtrail = "apigateway_no_cloudtrail"
    apigateway_no_tags = "apigateway_no_tags"
    apigateway_test_endpoint_enabled = "apigateway_test_endpoint_enabled"
    apigateway_method_no_auth = "apigateway_method_no_auth"
    apigateway_binary_media_unencrypted = "apigateway_binary_media_unencrypted"
    apigateway_no_minimum_tls = "apigateway_no_minimum_tls"
    apigateway_no_api_endpoint = "apigateway_no_api_endpoint"
    apigateway_private_not_configured = "apigateway_private_not_configured"


APIGATEWAY_SEVERITY = {
    "apigateway_open_resource": "High",
    "apigateway_cors_all_origins": "High",
    "apigateway_no_auth": "High",
    "apigateway_no_ssl": "High",
    "apigateway_method_no_auth": "High",
    "apigateway_no_waf": "High",
    "apigateway_no_domain_cert": "High",
    "apigateway_certificate_expired": "High",
    "apigateway_no_minimum_tls": "High",
    "apigateway_no_cors": "Low",
    "apigateway_no_logging": "Medium",
    "apigateway_no_throttling": "Medium",
    "apigateway_no_xray": "Low",
    "apigateway_default_method": "Low",
    "apigateway_no_api_key": "Medium",
    "apigateway_no_request_validation": "Medium",
    "apigateway_no_cache": "Low",
    "apigateway_cache_unencrypted": "Medium",
    "apigateway_no_execution_logs": "Medium",
    "apigateway_plaintext_logs": "Medium",
    "apigateway_no_access_logs": "Medium",
    "apigateway_no_cloudtrail": "Medium",
    "apigateway_no_tags": "Low",
    "apigateway_test_endpoint_enabled": "Low",
    "apigateway_binary_media_unencrypted": "Medium",
    "apigateway_no_api_endpoint": "Low",
    "apigateway_private_not_configured": "Medium",
}


APIGATEWAY_MITRE_MAP = {
    "apigateway_open_resource": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "API Gateway resource allows unauthenticated access",
        "remediation": "Require authentication and authorization for all API resources",
    },
    "apigateway_no_cors": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "CORS not configured for API Gateway",
        "remediation": "Configure CORS with trusted origins",
    },
    "apigateway_cors_all_origins": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "CORS allows requests from all origins",
        "remediation": "Restrict CORS to specific trusted origins",
    },
    "apigateway_no_waf": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "API Gateway not protected by AWS WAF",
        "remediation": "Attach AWS WAF to API Gateway",
    },
    "apigateway_no_logging": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "API Gateway logging is not enabled",
        "remediation": "Enable CloudWatch logging for API Gateway",
    },
    "apigateway_no_throttling": {
        "mitre_id": "T1499",
        "mitre_name": "Endpoint Denial of Service",
        "description": "API Gateway throttling not configured",
        "remediation": "Configure throttle settings for API",
    },
    "apigateway_no_xray": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "X-Ray tracing not enabled for API Gateway",
        "remediation": "Enable X-Ray tracing for visibility",
    },
    "apigateway_default_method": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "API using default method (ANY)",
        "remediation": "Use specific HTTP methods instead of ANY",
    },
    "apigateway_no_ssl": {
        "mitre_id": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "description": "API Gateway not enforcing HTTPS",
        "remediation": "Enforce HTTPS/TLS for all communications",
    },
    "apigateway_no_auth": {
        "mitre_id": "T1078.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "description": "API Gateway resource has no authentication",
        "remediation": "Implement authorization using API keys or IAM",
    },
    "apigateway_no_api_key": {
        "mitre_id": "T1078.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "description": "API Gateway does not require API key",
        "remediation": "Enable API key requirement for access control",
    },
    "apigateway_no_request_validation": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "API Gateway request validation not enabled",
        "remediation": "Enable request validation for schema enforcement",
    },
    "apigateway_no_cache": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "API Gateway caching is disabled",
        "remediation": "Enable caching for improved performance",
    },
    "apigateway_cache_unencrypted": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "API Gateway cache not encrypted",
        "remediation": "Enable cache encryption",
    },
    "apigateway_no_execution_logs": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "Execution logs not configured for API",
        "remediation": "Enable execution logs for debugging",
    },
    "apigateway_plaintext_logs": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "API logs contain plaintext sensitive data",
        "remediation": "Filter sensitive data from logs",
    },
    "apigateway_no_access_logs": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "Access logs not enabled for API",
        "remediation": "Configure access logging to CloudWatch or S3",
    },
    "apigateway_no_domain_cert": {
        "mitre_id": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "description": "API Gateway custom domain certificate not configured",
        "remediation": "Configure custom domain with SSL/TLS certificate",
    },
    "apigateway_certificate_expired": {
        "mitre_id": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "description": "SSL/TLS certificate is expired",
        "remediation": "Renew SSL/TLS certificate immediately",
    },
    "apigateway_no_cloudtrail": {
        "mitre_id": "T1562.008",
        "mitre_name": "Indicator Removal: Disable/Modify Cloud Logs",
        "description": "API Gateway activities not logged to CloudTrail",
        "remediation": "Enable CloudTrail for audit logging",
    },
    "apigateway_no_tags": {
        "mitre_id": "T1087.004",
        "mitre_name": "Enumerate Cloud Accounts",
        "description": "API Gateway resource not tagged",
        "remediation": "Add tags for resource organization",
    },
    "apigateway_test_endpoint_enabled": {
        "mitre_id": "T1590",
        "mitre_name": "Gather Victim Network Information",
        "description": "Test invocation URL is publicly accessible",
        "remediation": "Disable or restrict test endpoint access",
    },
    "apigateway_method_no_auth": {
        "mitre_id": "T1078.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "description": "API method lacks authorization",
        "remediation": "Add authorization to API methods",
    },
    "apigateway_binary_media_unencrypted": {
        "mitre_id": "T1530",
        "mitre_name": "Data from Cloud Storage",
        "description": "Binary media types not encrypted",
        "remediation": "Ensure binary media is encrypted in transit",
    },
    "apigateway_no_minimum_tls": {
        "mitre_id": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "description": "Minimum TLS version not enforced",
        "remediation": "Require TLS 1.2 or higher",
    },
    "apigateway_no_api_endpoint": {
        "mitre_id": "T1087.004",
        "mitre_name": "Valid Accounts: Cloud Accounts",
        "description": "API using default invoke URL",
        "remediation": "Use custom domain endpoint",
    },
    "apigateway_private_not_configured": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "API not configured as private/VPC endpoint",
        "remediation": "Use VPC endpoint or private API",
    },
}
