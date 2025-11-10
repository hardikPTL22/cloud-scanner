from enum import Enum


class EBSVulnerability(str, Enum):
    ebs_volume_unencrypted = "ebs_volume_unencrypted"
    ebs_no_snapshots = "ebs_no_snapshots"
    ebs_snapshot_public = "ebs_snapshot_public"
    ebs_snapshot_unencrypted = "ebs_snapshot_unencrypted"
    ebs_no_tags = "ebs_no_tags"
    ebs_default_kms_key = "ebs_default_kms_key"
    ebs_snapshot_shared = "ebs_snapshot_shared"
    ebs_no_delete_on_termination = "ebs_no_delete_on_termination"
    ebs_unattached = "ebs_unattached"
    ebs_old_snapshots = "ebs_old_snapshots"
    ebs_snapshot_no_description = "ebs_snapshot_no_description"
    ebs_no_description = "ebs_no_description"
    ebs_io_unencrypted = "ebs_io_unencrypted"
    ebs_gp2_large = "ebs_gp2_large"
    ebs_snapshot_copy_encrypted = "ebs_snapshot_copy_encrypted"
    ebs_iops_not_optimized = "ebs_iops_not_optimized"
    ebs_snapshots_too_many = "ebs_snapshots_too_many"
    ebs_volume_excessive = "ebs_volume_excessive"
    ebs_copy_no_encryption = "ebs_copy_no_encryption"
    ebs_no_backup_plan = "ebs_no_backup_plan"
    ebs_snapshot_copy_unencrypted = "ebs_snapshot_copy_unencrypted"
    ebs_no_fast_restore = "ebs_no_fast_restore"
    ebs_old_volume_type = "ebs_old_volume_type"


EBS_SEVERITY = {
    "ebs_volume_unencrypted": "HIGH",
    "ebs_no_snapshots": "MEDIUM",
    "ebs_snapshot_public": "CRITICAL",
    "ebs_snapshot_unencrypted": "HIGH",
    "ebs_no_tags": "LOW",
    "ebs_default_kms_key": "MEDIUM",
    "ebs_snapshot_shared": "HIGH",
    "ebs_no_delete_on_termination": "LOW",
    "ebs_unattached": "LOW",
    "ebs_old_snapshots": "MEDIUM",
    "ebs_snapshot_no_description": "LOW",
    "ebs_no_description": "LOW",
    "ebs_io_unencrypted": "HIGH",
    "ebs_gp2_large": "MEDIUM",
    "ebs_snapshot_copy_encrypted": "MEDIUM",
    "ebs_iops_not_optimized": "LOW",
    "ebs_snapshots_too_many": "MEDIUM",
    "ebs_volume_excessive": "MEDIUM",
    "ebs_copy_no_encryption": "HIGH",
    "ebs_no_backup_plan": "MEDIUM",
    "ebs_snapshot_copy_unencrypted": "HIGH",
    "ebs_no_fast_restore": "LOW",
    "ebs_old_volume_type": "LOW",
}


EBS_MITRE_MAP = {
    "ebs_volume_unencrypted": {
        "mitre_id": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "description": "EBS volume is not encrypted at rest",
        "remediation": "Enable encryption for EBS volumes",
    },
    "ebs_no_snapshots": {
        "mitre_id": "T1490",
        "mitre_name": "Service Stop",
        "description": "EBS volume has no snapshots for backup and recovery",
        "remediation": "Create regular snapshots for critical volumes",
    },
    "ebs_snapshot_public": {
        "mitre_id": "T1537",
        "mitre_name": "Transfer Data to Cloud Account",
        "description": "EBS snapshot is publicly accessible",
        "remediation": "Make snapshot private and restrict access",
    },
    "ebs_snapshot_unencrypted": {
        "mitre_id": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "description": "EBS snapshot is not encrypted",
        "remediation": "Enable encryption for snapshots",
    },
    "ebs_no_tags": {
        "mitre_id": "T1580",
        "mitre_name": "Cloud Infrastructure Discovery",
        "description": "EBS volume has no tags for identification and tracking",
        "remediation": "Add descriptive tags to all volumes",
    },
    "ebs_default_kms_key": {
        "mitre_id": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "description": "EBS volume uses default AWS managed key instead of CMK",
        "remediation": "Use customer-managed KMS keys for encryption",
    },
    "ebs_snapshot_shared": {
        "mitre_id": "T1537",
        "mitre_name": "Transfer Data to Cloud Account",
        "description": "EBS snapshot is shared with other AWS accounts",
        "remediation": "Review snapshot sharing permissions",
    },
    "ebs_no_delete_on_termination": {
        "mitre_id": "T1561",
        "mitre_name": "Disk Wipe",
        "description": "EBS volume will not be deleted when instance terminates",
        "remediation": "Enable delete on termination for non-persistent volumes",
    },
    "ebs_unattached": {
        "mitre_id": "T1578",
        "mitre_name": "Modify Cloud Compute Infrastructure",
        "description": "EBS volume is not attached to any instance",
        "remediation": "Attach volume to instance or delete if unused",
    },
    "ebs_old_snapshots": {
        "mitre_id": "T1490",
        "mitre_name": "Service Stop",
        "description": "Latest snapshot for volume is older than 30 days",
        "remediation": "Create regular snapshots of critical volumes",
    },
    "ebs_snapshot_no_description": {
        "mitre_id": "T1580",
        "mitre_name": "Cloud Infrastructure Discovery",
        "description": "EBS snapshot has no description",
        "remediation": "Add descriptive information to snapshots",
    },
    "ebs_no_description": {
        "mitre_id": "T1580",
        "mitre_name": "Cloud Infrastructure Discovery",
        "description": "EBS volume has no description tag",
        "remediation": "Add description tag to volume",
    },
    "ebs_io_unencrypted": {
        "mitre_id": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "description": "IO1/IO2 volume is not encrypted",
        "remediation": "Enable encryption for high-performance volumes",
    },
    "ebs_gp2_large": {
        "mitre_id": "T1578",
        "mitre_name": "Modify Cloud Compute Infrastructure",
        "description": "GP2 volume larger than 1TB should use GP3",
        "remediation": "Migrate to GP3 for better performance and cost",
    },
    "ebs_snapshot_copy_encrypted": {
        "mitre_id": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "description": "Snapshot copy is not encrypted",
        "remediation": "Enable encryption when copying snapshots",
    },
    "ebs_iops_not_optimized": {
        "mitre_id": "T1578",
        "mitre_name": "Modify Cloud Compute Infrastructure",
        "description": "EBS volume IOPS configuration is not optimal",
        "remediation": "Adjust IOPS provisioning for workload requirements",
    },
    "ebs_snapshots_too_many": {
        "mitre_id": "T1578",
        "mitre_name": "Modify Cloud Compute Infrastructure",
        "description": "Account has more than 100 snapshots",
        "remediation": "Review and delete unnecessary snapshots",
    },
    "ebs_volume_excessive": {
        "mitre_id": "T1578",
        "mitre_name": "Modify Cloud Compute Infrastructure",
        "description": "EBS volume size exceeds 5TB",
        "remediation": "Review volume size requirements",
    },
    "ebs_copy_no_encryption": {
        "mitre_id": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "description": "Copied snapshot not encrypted",
        "remediation": "Ensure encryption during snapshot copy operations",
    },
    "ebs_no_backup_plan": {
        "mitre_id": "T1490",
        "mitre_name": "Service Stop",
        "description": "EBS volume has no backup plan or strategy",
        "remediation": "Implement backup strategy with regular snapshots",
    },
    "ebs_snapshot_copy_unencrypted": {
        "mitre_id": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "description": "Snapshot copy is not encrypted",
        "remediation": "Enable encryption for snapshot copies",
    },
    "ebs_no_fast_restore": {
        "mitre_id": "T1578",
        "mitre_name": "Modify Cloud Compute Infrastructure",
        "description": "EBS snapshot does not have Fast Snapshot Restore enabled",
        "remediation": "Enable Fast Snapshot Restore for critical snapshots",
    },
    "ebs_old_volume_type": {
        "mitre_id": "T1578",
        "mitre_name": "Modify Cloud Compute Infrastructure",
        "description": "EBS volume uses old ST1/SC1 volume types",
        "remediation": "Migrate to newer gp3/io2 volume types",
    },
}
