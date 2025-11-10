from botocore.exceptions import ClientError
from scanner.mitre_maps.ebs_mitre_map import EBSVulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients


@inject_clients(clients=["ec2"])
def find_ebs_volumes_unencrypted(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        if not vol.get("Encrypted", False):
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_volume_unencrypted,
                    vol.get("VolumeId"),
                    "ebs",
                )
            )


@inject_clients(clients=["ec2"])
def find_ebs_volumes_no_snapshots(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        vol_id = vol.get("VolumeId")
        snapshots = ec2_client.describe_snapshots(
            Filters=[{"Name": "volume-id", "Values": [vol_id]}]
        ).get("Snapshots", [])
        if not snapshots:
            findings.append(
                new_vulnerability(EBSVulnerability.ebs_no_snapshots, vol_id, "ebs")
            )


@inject_clients(clients=["ec2"])
def find_ebs_snapshots_public(ec2_client, findings):
    snapshots = ec2_client.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
    for snapshot in snapshots:
        if snapshot.get("Public", False):
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_snapshot_public,
                    snapshot.get("SnapshotId"),
                    "ebs",
                )
            )


@inject_clients(clients=["ec2"])
def find_ebs_snapshots_unencrypted(ec2_client, findings):
    snapshots = ec2_client.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
    for snapshot in snapshots:
        if not snapshot.get("Encrypted", False):
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_snapshot_unencrypted,
                    snapshot.get("SnapshotId"),
                    "ebs",
                )
            )


@inject_clients(clients=["ec2"])
def find_ebs_volumes_no_tags(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        if not vol.get("Tags"):
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_no_tags, vol.get("VolumeId"), "ebs"
                )
            )


@inject_clients(clients=["ec2"])
def find_ebs_volumes_no_kms_encryption(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        if vol.get("Encrypted", False):
            kms_key = vol.get("KmsKeyId")
            if not kms_key or "aws/ebs" in kms_key:
                findings.append(
                    new_vulnerability(
                        EBSVulnerability.ebs_default_kms_key,
                        vol.get("VolumeId"),
                        "ebs",
                    )
                )


@inject_clients(clients=["ec2"])
def find_ebs_snapshots_shared_with_accounts(ec2_client, findings):
    snapshots = ec2_client.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
    for snapshot in snapshots:
        snap_id = snapshot.get("SnapshotId")
        try:
            attrs = ec2_client.describe_snapshot_attribute(
                SnapshotId=snap_id, Attribute="createVolumePermission"
            )
            perms = attrs.get("CreateVolumePermissions", [])
            if perms:
                for perm in perms:
                    if perm.get("UserId") or perm.get("Group"):
                        findings.append(
                            new_vulnerability(
                                EBSVulnerability.ebs_snapshot_shared,
                                snap_id,
                                "ebs",
                            )
                        )
                        break
        except ClientError:
            pass


@inject_clients(clients=["ec2"])
def find_ebs_volumes_no_delete_on_termination(ec2_client, findings):
    reservations = ec2_client.describe_instances().get("Reservations", [])
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            instance_id = instance.get("InstanceId")
            for block_device in instance.get("BlockDeviceMappings", []):
                vol_id = block_device.get("Ebs", {}).get("VolumeId")
                if vol_id:
                    if not block_device.get("Ebs", {}).get(
                        "DeleteOnTermination", False
                    ):
                        findings.append(
                            new_vulnerability(
                                EBSVulnerability.ebs_no_delete_on_termination,
                                vol_id,
                                "ebs",
                            )
                        )


@inject_clients(clients=["ec2"])
def find_ebs_volumes_not_attached(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        if not vol.get("Attachments"):
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_unattached, vol.get("VolumeId"), "ebs"
                )
            )


@inject_clients(clients=["ec2"])
def find_ebs_volumes_old_snapshots(ec2_client, findings):
    import datetime

    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        vol_id = vol.get("VolumeId")
        snapshots = ec2_client.describe_snapshots(
            Filters=[{"Name": "volume-id", "Values": [vol_id]}]
        ).get("Snapshots", [])
        if snapshots:
            latest_snap = max(snapshots, key=lambda x: x.get("StartTime"))
            start_time = latest_snap.get("StartTime")
            if start_time:
                age = (datetime.datetime.now(start_time.tzinfo) - start_time).days
                if age > 30:
                    findings.append(
                        new_vulnerability(
                            EBSVulnerability.ebs_old_snapshots, vol_id, "ebs"
                        )
                    )


@inject_clients(clients=["ec2"])
def find_ebs_snapshots_no_description(ec2_client, findings):
    snapshots = ec2_client.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
    for snapshot in snapshots:
        if not snapshot.get("Description"):
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_snapshot_no_description,
                    snapshot.get("SnapshotId"),
                    "ebs",
                )
            )


@inject_clients(clients=["ec2"])
def find_ebs_volumes_no_description(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        vol_id = vol.get("VolumeId")
        tags = vol.get("Tags", [])
        has_description = any(tag.get("Key") == "Description" for tag in tags)
        if not has_description:
            findings.append(
                new_vulnerability(EBSVulnerability.ebs_no_description, vol_id, "ebs")
            )


@inject_clients(clients=["ec2"])
def find_ebs_io1_io2_volumes_unencrypted(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        vol_type = vol.get("VolumeType", "")
        if vol_type in ["io1", "io2"]:
            if not vol.get("Encrypted", False):
                findings.append(
                    new_vulnerability(
                        EBSVulnerability.ebs_io_unencrypted,
                        vol.get("VolumeId"),
                        "ebs",
                    )
                )


@inject_clients(clients=["ec2"])
def find_ebs_gp2_volumes_large(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        if vol.get("VolumeType") == "gp2":
            size = vol.get("Size", 0)
            if size > 1000:
                findings.append(
                    new_vulnerability(
                        EBSVulnerability.ebs_gp2_large, vol.get("VolumeId"), "ebs"
                    )
                )


@inject_clients(clients=["ec2"])
def find_ebs_snapshots_no_copy_encryption(ec2_client, findings):
    snapshots = ec2_client.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
    for snapshot in snapshots:
        if not snapshot.get("Encrypted", False):
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_snapshot_copy_encrypted,
                    snapshot.get("SnapshotId"),
                    "ebs",
                )
            )


@inject_clients(clients=["ec2"])
def find_ebs_volumes_iops_not_optimized(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        vol_type = vol.get("VolumeType", "")
        iops = vol.get("Iops", 0)
        size = vol.get("Size", 0)
        if vol_type == "gp3":
            if iops < 3000 or size > 500:
                findings.append(
                    new_vulnerability(
                        EBSVulnerability.ebs_iops_not_optimized,
                        vol.get("VolumeId"),
                        "ebs",
                    )
                )


@inject_clients(clients=["ec2"])
def find_ebs_snapshots_too_many(ec2_client, findings):
    snapshots = ec2_client.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
    if len(snapshots) > 100:
        findings.append(
            new_vulnerability(
                EBSVulnerability.ebs_snapshots_too_many,
                f"Total: {len(snapshots)}",
                "ebs",
            )
        )


@inject_clients(clients=["ec2"])
def find_ebs_volumes_excessive_size(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        size = vol.get("Size", 0)
        if size > 5000:
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_volume_excessive, vol.get("VolumeId"), "ebs"
                )
            )


@inject_clients(clients=["ec2"])
def find_ebs_snapshot_copy_no_encryption(ec2_client, findings):
    snapshots = ec2_client.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
    for snapshot in snapshots:
        source_snapshot = snapshot.get("SourceSnapshotId")
        if source_snapshot:
            if not snapshot.get("Encrypted", False):
                findings.append(
                    new_vulnerability(
                        EBSVulnerability.ebs_copy_no_encryption,
                        snapshot.get("SnapshotId"),
                        "ebs",
                    )
                )


@inject_clients(clients=["ec2"])
def find_ebs_volumes_no_backup_plan(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        vol_id = vol.get("VolumeId")
        tags = vol.get("Tags", [])
        has_backup_tag = any(
            tag.get("Key").lower() == "backup" for tag in tags if tag.get("Key")
        )
        if not has_backup_tag:
            findings.append(
                new_vulnerability(EBSVulnerability.ebs_no_backup_plan, vol_id, "ebs")
            )


@inject_clients(clients=["ec2"])
def find_ebs_snapshots_unencrypted_copies(ec2_client, findings):
    snapshots = ec2_client.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
    for snapshot in snapshots:
        if snapshot.get("SourceSnapshotId"):
            if not snapshot.get("Encrypted", False):
                findings.append(
                    new_vulnerability(
                        EBSVulnerability.ebs_snapshot_copy_unencrypted,
                        snapshot.get("SnapshotId"),
                        "ebs",
                    )
                )


@inject_clients(clients=["ec2"])
def find_ebs_volumes_fast_snapshot_restore(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        vol_id = vol.get("VolumeId")
        snapshots = ec2_client.describe_snapshots(
            Filters=[{"Name": "volume-id", "Values": [vol_id]}]
        ).get("Snapshots", [])
        for snapshot in snapshots:
            snap_id = snapshot.get("SnapshotId")
            try:
                attrs = ec2_client.describe_snapshot_attribute(
                    SnapshotId=snap_id, Attribute="fastRestoreable"
                )
                if not attrs.get("FastRestoreableByAccountId"):
                    findings.append(
                        new_vulnerability(
                            EBSVulnerability.ebs_no_fast_restore, snap_id, "ebs"
                        )
                    )
            except ClientError:
                pass


@inject_clients(clients=["ec2"])
def find_ebs_volumes_st1_sc1_old_generation(ec2_client, findings):
    volumes = ec2_client.describe_volumes().get("Volumes", [])
    for vol in volumes:
        vol_type = vol.get("VolumeType", "")
        if vol_type in ["st1", "sc1"]:
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_old_volume_type, vol.get("VolumeId"), "ebs"
                )
            )
