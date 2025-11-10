from enum import Enum


class EC2Vulnerability(str, Enum):
    open_security_group_ingress = "open_security_group_ingress"
    open_security_group_egress = "open_security_group_egress"
    unused_security_group = "unused_security_group"
    vpc_flow_logs_disabled = "vpc_flow_logs_disabled"
    ebs_volume_unencrypted = "ebs_volume_unencrypted"
    ec2_instance_public_ip = "ec2_instance_public_ip"
    sg_ssh_open = "sg_ssh_open"
    sg_rdp_open = "sg_rdp_open"
    default_vpc_in_use = "default_vpc_in_use"
    default_sg_in_use = "default_sg_in_use"
    ec2_imdsv1_enabled = "ec2_imdsv1_enabled"
    ec2_no_iam_role = "ec2_no_iam_role"
    ec2_monitoring_disabled = "ec2_monitoring_disabled"
    ec2_termination_protection_disabled = "ec2_termination_protection_disabled"
    ec2_no_tags = "ec2_no_tags"
    ec2_volumes_no_encryption = "ec2_volumes_no_encryption"
    ec2_no_kms_encryption = "ec2_no_kms_encryption"
    ec2_instance_no_vpc = "ec2_instance_no_vpc"
    ec2_security_group_overly_permissive = "ec2_security_group_overly_permissive"
    ec2_instance_profile_missing = "ec2_instance_profile_missing"
    ec2_unrestricted_access = "ec2_unrestricted_access"
    ec2_no_detailed_monitoring = "ec2_no_detailed_monitoring"
    ec2_instance_no_description = "ec2_instance_no_description"
    ec2_instance_public_ipv4 = "ec2_instance_public_ipv4"
    ec2_security_group_no_description = "ec2_security_group_no_description"
    ec2_instance_high_risk_ports = "ec2_instance_high_risk_ports"
    ec2_vpc_flow_logs_not_enabled = "ec2_vpc_flow_logs_not_enabled"
    ec2_instance_root_volume_encrypted = "ec2_instance_root_volume_encrypted"
    ec2_instance_ebs_optimization_disabled = "ec2_instance_ebs_optimization_disabled"


EC2_SEVERITY = {
    "open_security_group_ingress": "High",
    "open_security_group_egress": "Medium",
    "unused_security_group": "Low",
    "vpc_flow_logs_disabled": "Medium",
    "ebs_volume_unencrypted": "High",
    "ec2_instance_public_ip": "Medium",
    "sg_ssh_open": "High",
    "sg_rdp_open": "High",
    "default_vpc_in_use": "Low",
    "default_sg_in_use": "Medium",
    "ec2_imdsv1_enabled": "Medium",
    "ec2_no_iam_role": "High",
    "ec2_monitoring_disabled": "Low",
    "ec2_termination_protection_disabled": "Low",
    "ec2_no_tags": "Low",
    "ec2_volumes_no_encryption": "High",
    "ec2_no_kms_encryption": "Medium",
    "ec2_instance_no_vpc": "High",
    "ec2_security_group_overly_permissive": "High",
    "ec2_instance_profile_missing": "High",
    "ec2_unrestricted_access": "High",
    "ec2_no_detailed_monitoring": "Low",
    "ec2_instance_no_description": "Low",
    "ec2_instance_public_ipv4": "Medium",
    "ec2_security_group_no_description": "Low",
    "ec2_instance_high_risk_ports": "High",
    "ec2_vpc_flow_logs_not_enabled": "Medium",
    "ec2_instance_root_volume_encrypted": "High",
    "ec2_instance_ebs_optimization_disabled": "Low",
}


EC2_MITRE_MAP = {
    "open_security_group_ingress": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Security group allows unrestricted inbound traffic",
        "remediation": "Restrict inbound rules to specific IPs and ports",
    },
    "open_security_group_egress": {
        "mitre_id": "T1048",
        "mitre_name": "Exfiltration Over Alternative Protocol",
        "description": "Security group allows unrestricted outbound traffic",
        "remediation": "Restrict outbound rules to required destinations",
    },
    "unused_security_group": {
        "mitre_id": "T1087",
        "mitre_name": "Enumerate Cloud Infrastructure",
        "description": "Security group is not associated with any resources",
        "remediation": "Delete unused security groups",
    },
    "vpc_flow_logs_disabled": {
        "mitre_id": "T1087",
        "mitre_name": "Enumerate Cloud Infrastructure",
        "description": "VPC Flow Logs are not enabled for monitoring",
        "remediation": "Enable VPC Flow Logs for network monitoring",
    },
    "ebs_volume_unencrypted": {
        "mitre_id": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "description": "EBS volume is not encrypted",
        "remediation": "Enable encryption for EBS volumes",
    },
    "ec2_instance_public_ip": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "EC2 instance has public IP address",
        "remediation": "Use private subnets or restrict public access",
    },
    "sg_ssh_open": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Security group allows SSH from 0.0.0.0/0",
        "remediation": "Restrict SSH access to specific IPs",
    },
    "sg_rdp_open": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Security group allows RDP from 0.0.0.0/0",
        "remediation": "Restrict RDP access to specific IPs",
    },
    "default_vpc_in_use": {
        "mitre_id": "T1087",
        "mitre_name": "Enumerate Cloud Infrastructure",
        "description": "Default VPC is in use",
        "remediation": "Use custom VPCs with controlled security settings",
    },
    "default_sg_in_use": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Default security group is in use",
        "remediation": "Create and use custom security groups",
    },
    "ec2_imdsv1_enabled": {
        "mitre_id": "T1526",
        "mitre_name": "Gather Victim Host Information",
        "description": "EC2 instance uses IMDSv1 instead of IMDSv2",
        "remediation": "Require IMDSv2 for metadata service",
    },
    "ec2_no_iam_role": {
        "mitre_id": "T1078",
        "mitre_name": "Valid Accounts",
        "description": "EC2 instance does not have an IAM role attached",
        "remediation": "Attach appropriate IAM role to instance",
    },
    "ec2_monitoring_disabled": {
        "mitre_id": "T1087",
        "mitre_name": "Enumerate Cloud Infrastructure",
        "description": "Detailed monitoring is disabled for EC2 instance",
        "remediation": "Enable detailed CloudWatch monitoring",
    },
    "ec2_termination_protection_disabled": {
        "mitre_id": "T1578",
        "mitre_name": "Modify Cloud Compute Infrastructure",
        "description": "Termination protection is not enabled",
        "remediation": "Enable termination protection for critical instances",
    },
    "ec2_no_tags": {
        "mitre_id": "T1580",
        "mitre_name": "Cloud Infrastructure Discovery",
        "description": "EC2 instance has no tags for identification",
        "remediation": "Add tags for resource identification and tracking",
    },
    "ec2_volumes_no_encryption": {
        "mitre_id": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "description": "EC2 volumes are not encrypted",
        "remediation": "Enable encryption for all volumes",
    },
    "ec2_no_kms_encryption": {
        "mitre_id": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "description": "EC2 volumes use default encryption instead of CMK",
        "remediation": "Use customer-managed KMS keys",
    },
    "ec2_instance_no_vpc": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "EC2 instance is in EC2-Classic",
        "remediation": "Move instance to VPC",
    },
    "ec2_security_group_overly_permissive": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Security group has overly permissive rules",
        "remediation": "Apply principle of least privilege",
    },
    "ec2_instance_profile_missing": {
        "mitre_id": "T1078",
        "mitre_name": "Valid Accounts",
        "description": "Instance profile is missing from EC2 instance",
        "remediation": "Create and attach instance profile",
    },
    "ec2_unrestricted_access": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "EC2 resources allow unrestricted access",
        "remediation": "Implement network segmentation",
    },
    "ec2_no_detailed_monitoring": {
        "mitre_id": "T1087",
        "mitre_name": "Enumerate Cloud Infrastructure",
        "description": "Detailed monitoring not enabled",
        "remediation": "Enable detailed CloudWatch metrics",
    },
    "ec2_instance_no_description": {
        "mitre_id": "T1580",
        "mitre_name": "Cloud Infrastructure Discovery",
        "description": "EC2 instance has no description",
        "remediation": "Add description to instance",
    },
    "ec2_instance_public_ipv4": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "EC2 instance has public IPv4 address",
        "remediation": "Use NAT gateway or VPN for outbound",
    },
    "ec2_security_group_no_description": {
        "mitre_id": "T1580",
        "mitre_name": "Cloud Infrastructure Discovery",
        "description": "Security group has no description",
        "remediation": "Add description to security group",
    },
    "ec2_instance_high_risk_ports": {
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Instance exposes high-risk ports",
        "remediation": "Close unnecessary ports",
    },
    "ec2_vpc_flow_logs_not_enabled": {
        "mitre_id": "T1087",
        "mitre_name": "Enumerate Cloud Infrastructure",
        "description": "VPC Flow Logs not enabled",
        "remediation": "Enable VPC Flow Logs",
    },
    "ec2_instance_root_volume_encrypted": {
        "mitre_id": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "description": "Root volume is not encrypted",
        "remediation": "Enable encryption on root volume",
    },
    "ec2_instance_ebs_optimization_disabled": {
        "mitre_id": "T1578",
        "mitre_name": "Modify Cloud Compute Infrastructure",
        "description": "EBS optimization is not enabled",
        "remediation": "Enable EBS optimization for better performance",
    },
}
