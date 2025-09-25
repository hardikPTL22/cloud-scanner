MITRE_MAP = {
    "public_s3_bucket": {
        "techniques": [
            {
                "id": "T1530",
                "name": "Data from Cloud Storage",
                "desc": "Adversaries may access or exfiltrate data from cloud storage (e.g., S3) if buckets or objects are publicly accessible.",
                "remediation": "Disable public ACLs/policies, enable S3 Block Public Access, apply least-privilege bucket policies, enable logging and encryption.",
            }
        ],
        "note": "Public S3 buckets may allow anyone to list or download objects.",
    },
    "over_permissive_iam": {
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
    },
    "open_security_group": {
        "techniques": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application / Exposed Services",
                "desc": "Security groups that permit 0.0.0.0/0 increase exposure and can allow attackers access to services like SSH/RDP.",
                "remediation": "Restrict ingress to known IPs/ranges, use bastion hosts, remove 0.0.0.0/0 for management ports, enable VPC flow logs.",
            }
        ],
        "note": "Open ingress widens the attack surface and can enable lateral movement or direct compromise.",
    },
    "unencrypted_s3_bucket": {
        "techniques": [
            {
                "id": "T1530",
                "name": "Data from Cloud Storage",
                "desc": "Objects stored without encryption may be accessed and read if other protections are absent.",
                "remediation": "Enable default bucket encryption (SSE-S3 or SSE-KMS), apply encryption at rest policies, and enforce via AWS Config/CIS.",
            }
        ],
        "note": "Missing default encryption increases risk if the bucket becomes exposed.",
    },
    "cloudtrail_not_logging": {
        "techniques": [
            {
                "id": "T1078",
                "name": "Valid Accounts / Cloud Log Tampering",
                "desc": "If CloudTrail is not logging, it becomes harder to detect abuse or suspicious API activity.",
                "remediation": "Enable CloudTrail across regions, ensure trails are multi-region and logging, enable log file validation and delivery to a secure S3 bucket.",
            }
        ],
        "note": "CloudTrail should be enabled and logging to detect suspicious activity.",
    },
    "file_scan": {
        "techniques": [
            {
                "id": "T1065",
                "name": "Indicator Removal on Host",
                "desc": "Malware files may be introduced and hidden on hosts via uploads.",
                "remediation": "Perform malware scanning on all uploaded files, block infected files.",
            }
        ],
        "note": "Scan uploaded files to prevent malware introduction to the environment.",
    },
}
