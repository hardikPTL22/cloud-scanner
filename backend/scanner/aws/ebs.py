from botocore.exceptions import ClientError
from scanner.mitre_maps.ebs_mitre_map import EBSVulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients
from concurrent.futures import ThreadPoolExecutor
import logging
import datetime

logger = logging.getLogger(__name__)


def fetch_volumes(ec2_client):
    """Fetch all EBS volumes once for reuse across checks"""
    try:
        return ec2_client.describe_volumes().get("Volumes", [])
    except Exception as e:
        logger.error(f"Error fetching volumes: {e}")
        return []


def fetch_snapshots(ec2_client):
    """Fetch all snapshots once for reuse across checks"""
    try:
        return ec2_client.describe_snapshots(OwnerIds=["self"]).get("Snapshots", [])
    except Exception as e:
        logger.error(f"Error fetching snapshots: {e}")
        return []


@inject_clients(clients=["ec2"])
def find_ebs_volumes_unencrypted(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_encryption(vol):
        if not vol.get("Encrypted", False):
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_volume_unencrypted,
                    vol.get("VolumeId"),
                    "ebs",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_encryption, volumes)


@inject_clients(clients=["ec2"])
def find_ebs_volumes_no_snapshots(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_snapshots(vol):
        vol_id = vol.get("VolumeId")
        try:
            snapshots = ec2_client.describe_snapshots(
                Filters=[{"Name": "volume-id", "Values": [vol_id]}]
            ).get("Snapshots", [])
            if not snapshots:
                findings.append(
                    new_vulnerability(EBSVulnerability.ebs_no_snapshots, vol_id, "ebs")
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_snapshots, volumes)


@inject_clients(clients=["ec2"])
def find_ebs_snapshots_public(ec2_client, findings, snapshots=None):
    if snapshots is None:
        snapshots = fetch_snapshots(ec2_client)

    def check_public(snapshot):
        if snapshot.get("Public", False):
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_snapshot_public,
                    snapshot.get("SnapshotId"),
                    "ebs",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_public, snapshots)


@inject_clients(clients=["ec2"])
def find_ebs_snapshots_unencrypted(ec2_client, findings, snapshots=None):
    if snapshots is None:
        snapshots = fetch_snapshots(ec2_client)

    def check_encryption(snapshot):
        if not snapshot.get("Encrypted", False):
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_snapshot_unencrypted,
                    snapshot.get("SnapshotId"),
                    "ebs",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_encryption, snapshots)


@inject_clients(clients=["ec2"])
def find_ebs_volumes_no_tags(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_tags(vol):
        if not vol.get("Tags"):
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_no_tags, vol.get("VolumeId"), "ebs"
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_tags, volumes)


@inject_clients(clients=["ec2"])
def find_ebs_volumes_no_kms_encryption(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_kms(vol):
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

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_kms, volumes)


@inject_clients(clients=["ec2"])
def find_ebs_snapshots_shared_with_accounts(ec2_client, findings, snapshots=None):
    if snapshots is None:
        snapshots = fetch_snapshots(ec2_client)

    def check_shared(snapshot):
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

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_shared, snapshots)


@inject_clients(clients=["ec2"])
def find_ebs_volumes_no_delete_on_termination(ec2_client, findings):
    try:
        reservations = ec2_client.describe_instances().get("Reservations", [])
    except Exception as e:
        logger.error(f"Error fetching instances: {e}")
        return

    def check_instance(instance):
        for block_device in instance.get("BlockDeviceMappings", []):
            vol_id = block_device.get("Ebs", {}).get("VolumeId")
            if vol_id:
                if not block_device.get("Ebs", {}).get("DeleteOnTermination", False):
                    findings.append(
                        new_vulnerability(
                            EBSVulnerability.ebs_no_delete_on_termination,
                            vol_id,
                            "ebs",
                        )
                    )

    instances = []
    for reservation in reservations:
        instances.extend(reservation.get("Instances", []))

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_instance, instances)


@inject_clients(clients=["ec2"])
def find_ebs_volumes_not_attached(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_attached(vol):
        if not vol.get("Attachments"):
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_unattached, vol.get("VolumeId"), "ebs"
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_attached, volumes)


@inject_clients(clients=["ec2"])
def find_ebs_volumes_old_snapshots(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_old_snapshots(vol):
        vol_id = vol.get("VolumeId")
        try:
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
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_old_snapshots, volumes)


@inject_clients(clients=["ec2"])
def find_ebs_snapshots_no_description(ec2_client, findings, snapshots=None):
    if snapshots is None:
        snapshots = fetch_snapshots(ec2_client)

    def check_description(snapshot):
        if not snapshot.get("Description"):
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_snapshot_no_description,
                    snapshot.get("SnapshotId"),
                    "ebs",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_description, snapshots)


@inject_clients(clients=["ec2"])
def find_ebs_volumes_no_description(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_description(vol):
        vol_id = vol.get("VolumeId")
        tags = vol.get("Tags", [])
        has_description = any(tag.get("Key") == "Description" for tag in tags)
        if not has_description:
            findings.append(
                new_vulnerability(EBSVulnerability.ebs_no_description, vol_id, "ebs")
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_description, volumes)


@inject_clients(clients=["ec2"])
def find_ebs_io1_io2_volumes_unencrypted(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_io_encryption(vol):
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

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_io_encryption, volumes)


@inject_clients(clients=["ec2"])
def find_ebs_gp2_volumes_large(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_gp2_size(vol):
        if vol.get("VolumeType") == "gp2":
            size = vol.get("Size", 0)
            if size > 1000:
                findings.append(
                    new_vulnerability(
                        EBSVulnerability.ebs_gp2_large, vol.get("VolumeId"), "ebs"
                    )
                )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_gp2_size, volumes)


@inject_clients(clients=["ec2"])
def find_ebs_snapshots_no_copy_encryption(ec2_client, findings, snapshots=None):
    if snapshots is None:
        snapshots = fetch_snapshots(ec2_client)

    def check_copy_encryption(snapshot):
        if not snapshot.get("Encrypted", False):
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_snapshot_copy_encrypted,
                    snapshot.get("SnapshotId"),
                    "ebs",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_copy_encryption, snapshots)


@inject_clients(clients=["ec2"])
def find_ebs_volumes_iops_not_optimized(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_iops(vol):
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

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_iops, volumes)


@inject_clients(clients=["ec2"])
def find_ebs_snapshots_too_many(ec2_client, findings):
    snapshots = fetch_snapshots(ec2_client)
    if len(snapshots) > 100:
        findings.append(
            new_vulnerability(
                EBSVulnerability.ebs_snapshots_too_many,
                f"Total: {len(snapshots)}",
                "ebs",
            )
        )


@inject_clients(clients=["ec2"])
def find_ebs_volumes_excessive_size(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_size(vol):
        size = vol.get("Size", 0)
        if size > 5000:
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_volume_excessive, vol.get("VolumeId"), "ebs"
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_size, volumes)


@inject_clients(clients=["ec2"])
def find_ebs_snapshot_copy_no_encryption(ec2_client, findings, snapshots=None):
    if snapshots is None:
        snapshots = fetch_snapshots(ec2_client)

    def check_copy_no_encryption(snapshot):
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

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_copy_no_encryption, snapshots)


@inject_clients(clients=["ec2"])
def find_ebs_volumes_no_backup_plan(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_backup_plan(vol):
        vol_id = vol.get("VolumeId")
        tags = vol.get("Tags", [])
        has_backup_tag = any(
            tag.get("Key").lower() == "backup" for tag in tags if tag.get("Key")
        )
        if not has_backup_tag:
            findings.append(
                new_vulnerability(EBSVulnerability.ebs_no_backup_plan, vol_id, "ebs")
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_backup_plan, volumes)


@inject_clients(clients=["ec2"])
def find_ebs_snapshots_unencrypted_copies(ec2_client, findings, snapshots=None):
    if snapshots is None:
        snapshots = fetch_snapshots(ec2_client)

    def check_unencrypted_copy(snapshot):
        if snapshot.get("SourceSnapshotId"):
            if not snapshot.get("Encrypted", False):
                findings.append(
                    new_vulnerability(
                        EBSVulnerability.ebs_snapshot_copy_unencrypted,
                        snapshot.get("SnapshotId"),
                        "ebs",
                    )
                )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_unencrypted_copy, snapshots)


@inject_clients(clients=["ec2"])
def find_ebs_volumes_fast_snapshot_restore(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_fast_restore(vol):
        vol_id = vol.get("VolumeId")
        try:
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
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_fast_restore, volumes)


@inject_clients(clients=["ec2"])
def find_ebs_volumes_st1_sc1_old_generation(ec2_client, findings, volumes=None):
    if volumes is None:
        volumes = fetch_volumes(ec2_client)

    def check_old_type(vol):
        vol_type = vol.get("VolumeType", "")
        if vol_type in ["st1", "sc1"]:
            findings.append(
                new_vulnerability(
                    EBSVulnerability.ebs_old_volume_type, vol.get("VolumeId"), "ebs"
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_old_type, volumes)
