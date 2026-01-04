from botocore.exceptions import ClientError
from scanner.mitre_maps.rds_mitre_map import RDSVulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients
from concurrent.futures import ThreadPoolExecutor
import logging

logger = logging.getLogger(__name__)


def fetch_db_instances(rds_client):
    """Fetch all RDS DB instances once for reuse across checks"""
    try:
        return rds_client.describe_db_instances().get("DBInstances", [])
    except Exception as e:
        logger.error(f"Error fetching DB instances: {e}")
        return []


def fetch_db_clusters(rds_client):
    """Fetch all RDS DB clusters once for reuse across checks"""
    try:
        return rds_client.describe_db_clusters().get("DBClusters", [])
    except Exception as e:
        logger.error(f"Error fetching DB clusters: {e}")
        return []


@inject_clients(clients=["rds"])
def find_rds_unencrypted(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_encryption(db):
        if not db.get("StorageEncrypted", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_instance_unencrypted,
                    db.get("DBInstanceArn"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_encryption, dbs)


@inject_clients(clients=["rds"])
def find_rds_public_access_enabled(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_public_access(db):
        if db.get("PubliclyAccessible"):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_instance_public_access,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_public_access, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_backup(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_backup(db):
        if db.get("BackupRetentionPeriod", 0) == 0:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_backup,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_backup, dbs)


@inject_clients(clients=["rds"])
def find_rds_backup_retention_low(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_retention(db):
        if db.get("BackupRetentionPeriod", 0) < 7:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_low_backup_retention,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_retention, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_multi_az(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_multi_az(db):
        if not db.get("MultiAZ", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_multi_az,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_multi_az, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_enhanced_monitoring(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_monitoring(db):
        if not db.get("EnabledCloudwatchLogsExports"):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_enhanced_monitoring,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_monitoring, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_deletion_protection(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_deletion_protection(db):
        if not db.get("DeletionProtection", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_deletion_protection,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_deletion_protection, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_copy_snapshots_to_region(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_copy_snapshots(db):
        if not db.get("CopyTagsToSnapshot", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_copy_snapshots,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_copy_snapshots, dbs)


@inject_clients(clients=["rds"])
def find_rds_minor_version_upgrade_auto_enabled(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_auto_upgrade(db):
        if db.get("AutoMinorVersionUpgrade", True):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_auto_minor_upgrade,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_auto_upgrade, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_performance_insights(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_performance_insights(db):
        if not db.get("PerfInsightsEnabled", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_performance_insights,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_performance_insights, dbs)


@inject_clients(clients=["rds"])
def find_rds_iam_authentication_disabled(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_iam_auth(db):
        if not db.get("IAMDatabaseAuthenticationEnabled", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_iam_auth_disabled,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_iam_auth, dbs)


@inject_clients(clients=["rds"])
def find_rds_default_port_exposed(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    default_ports = {
        "mysql": 3306,
        "postgres": 5432,
        "mariadb": 3306,
        "oracle": 1521,
        "sqlserver": 1433,
    }

    def check_default_port(db):
        engine = db.get("Engine", "")
        port = db.get("Endpoint", {}).get("Port")
        if engine in default_ports and port == default_ports[engine]:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_default_port,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_default_port, dbs)


@inject_clients(clients=["rds"])
def find_rds_database_parameter_group_default(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_param_group(db):
        param_group = db.get("DBParameterGroups", [{}])[0].get(
            "DBParameterGroupName", ""
        )
        if "default" in param_group.lower():
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_default_param_group,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_param_group, dbs)


@inject_clients(clients=["rds"])
def find_rds_cluster_no_encryption(rds_client, findings, clusters=None):
    if clusters is None:
        clusters = fetch_db_clusters(rds_client)

    def check_cluster_encryption(cluster):
        if not cluster.get("StorageEncrypted", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_cluster_unencrypted,
                    cluster.get("DBClusterIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_cluster_encryption, clusters)


@inject_clients(clients=["rds"])
def find_rds_cluster_public_access(rds_client, findings, clusters=None):
    if clusters is None:
        clusters = fetch_db_clusters(rds_client)

    def check_cluster_public(cluster):
        try:
            members = cluster.get("DBClusterMembers", [])
            for member in members:
                db_id = member.get("DBInstanceIdentifier")
                db = rds_client.describe_db_instances(DBInstanceIdentifier=db_id).get(
                    "DBInstances", [{}]
                )[0]
                if db.get("PubliclyAccessible"):
                    findings.append(
                        new_vulnerability(
                            RDSVulnerability.rds_cluster_public,
                            cluster.get("DBClusterIdentifier"),
                            "rds",
                        )
                    )
                    return
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_cluster_public, clusters)


@inject_clients(clients=["rds"])
def find_rds_no_automated_backups(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_automated_backup(db):
        if not db.get("BackupRetentionPeriod") or db.get("BackupRetentionPeriod") < 1:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_automated_backup,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_automated_backup, dbs)


@inject_clients(clients=["rds"])
def find_rds_snapshots_public(rds_client, findings):
    try:
        snapshots = rds_client.describe_db_snapshots().get("DBSnapshots", [])
    except Exception as e:
        logger.error(f"Error fetching snapshots: {e}")
        return

    def check_snapshot_public(snapshot):
        try:
            attrs = rds_client.describe_db_snapshot_attributes(
                DBSnapshotIdentifier=snapshot.get("DBSnapshotIdentifier")
            )
            attributes = attrs.get("DBSnapshotAttributesResult", {}).get(
                "DBSnapshotAttributes", []
            )
            for attr in attributes:
                if attr.get("AttributeName") == "restore" and "all" in attr.get(
                    "AttributeValues", []
                ):
                    findings.append(
                        new_vulnerability(
                            RDSVulnerability.rds_snapshot_public,
                            snapshot.get("DBSnapshotIdentifier"),
                            "rds",
                        )
                    )
                    return
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_snapshot_public, snapshots)


@inject_clients(clients=["rds"])
def find_rds_no_tags(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_tags(db):
        try:
            tags = rds_client.list_tags_for_resource(
                ResourceName=db.get("DBInstanceArn")
            )
            if not tags.get("TagList"):
                findings.append(
                    new_vulnerability(
                        RDSVulnerability.rds_no_tags,
                        db.get("DBInstanceIdentifier"),
                        "rds",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_tags, dbs)


@inject_clients(clients=["rds"])
def find_rds_storage_not_encrypted_at_rest(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_storage_encryption(db):
        if not db.get("StorageEncrypted", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_storage_not_encrypted,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_storage_encryption, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_option_group(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_option_group(db):
        option_groups = db.get("OptionGroupMemberships", [])
        if not option_groups:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_option_group,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_option_group, dbs)


@inject_clients(clients=["rds"])
def find_rds_instance_no_vpc(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_vpc(db):
        vpc_id = db.get("DBSubnetGroup", {}).get("VpcId")
        if not vpc_id:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_vpc, db.get("DBInstanceIdentifier"), "rds"
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_vpc, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_cloudtrail_logging(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_cloudtrail_logging(db):
        logs = db.get("EnabledCloudwatchLogsExports", [])
        if not logs or "error" not in logs:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_cloudtrail,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_cloudtrail_logging, dbs)


@inject_clients(clients=["rds"])
def find_rds_cluster_backup_retention_low(rds_client, findings, clusters=None):
    if clusters is None:
        clusters = fetch_db_clusters(rds_client)

    def check_cluster_retention(cluster):
        if cluster.get("BackupRetentionPeriod", 0) < 7:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_cluster_low_retention,
                    cluster.get("DBClusterIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_cluster_retention, clusters)


@inject_clients(clients=["rds"])
def find_rds_instance_with_default_security_group(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_default_sg(db):
        vpc_sgs = db.get("VpcSecurityGroups", [])
        for sg in vpc_sgs:
            if sg.get("VpcSecurityGroupId") == "default":
                findings.append(
                    new_vulnerability(
                        RDSVulnerability.rds_default_sg,
                        db.get("DBInstanceIdentifier"),
                        "rds",
                    )
                )
                return

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_default_sg, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_kms_key(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_kms_key(db):
        if not db.get("KmsKeyId"):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_kms_key,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_kms_key, dbs)


@inject_clients(clients=["rds"])
def find_rds_engine_unsupported(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    unsupported = ["mysql5.6", "postgres9.5", "mariadb10.0"]

    def check_engine_version(db):
        version = db.get("EngineVersion", "")
        for unsup in unsupported:
            if version.startswith(unsup):
                findings.append(
                    new_vulnerability(
                        RDSVulnerability.rds_unsupported_engine,
                        db.get("DBInstanceIdentifier"),
                        "rds",
                    )
                )
                return

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_engine_version, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_audit_logs(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_audit_logs(db):
        logs = db.get("EnabledCloudwatchLogsExports", [])
        if not logs or "audit" not in logs:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_audit_logs,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_audit_logs, dbs)


from botocore.exceptions import ClientError
from scanner.mitre_maps.rds_mitre_map import RDSVulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients
from concurrent.futures import ThreadPoolExecutor
import logging

logger = logging.getLogger(__name__)


def fetch_db_instances(rds_client):
    """Fetch all RDS DB instances once for reuse across checks"""
    try:
        return rds_client.describe_db_instances().get("DBInstances", [])
    except Exception as e:
        logger.error(f"Error fetching DB instances: {e}")
        return []


def fetch_db_clusters(rds_client):
    """Fetch all RDS DB clusters once for reuse across checks"""
    try:
        return rds_client.describe_db_clusters().get("DBClusters", [])
    except Exception as e:
        logger.error(f"Error fetching DB clusters: {e}")
        return []


@inject_clients(clients=["rds"])
def find_rds_unencrypted(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_encryption(db):
        if not db.get("StorageEncrypted", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_instance_unencrypted,
                    db.get("DBInstanceArn"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_encryption, dbs)


@inject_clients(clients=["rds"])
def find_rds_public_access_enabled(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_public_access(db):
        if db.get("PubliclyAccessible"):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_instance_public_access,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_public_access, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_backup(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_backup(db):
        if db.get("BackupRetentionPeriod", 0) == 0:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_backup,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_backup, dbs)


@inject_clients(clients=["rds"])
def find_rds_backup_retention_low(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_retention(db):
        if db.get("BackupRetentionPeriod", 0) < 7:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_low_backup_retention,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_retention, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_multi_az(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_multi_az(db):
        if not db.get("MultiAZ", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_multi_az,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_multi_az, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_enhanced_monitoring(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_monitoring(db):
        if not db.get("EnabledCloudwatchLogsExports"):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_enhanced_monitoring,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_monitoring, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_deletion_protection(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_deletion_protection(db):
        if not db.get("DeletionProtection", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_deletion_protection,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_deletion_protection, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_copy_snapshots_to_region(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_copy_snapshots(db):
        if not db.get("CopyTagsToSnapshot", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_copy_snapshots,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_copy_snapshots, dbs)


@inject_clients(clients=["rds"])
def find_rds_minor_version_upgrade_auto_enabled(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_auto_upgrade(db):
        if db.get("AutoMinorVersionUpgrade", True):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_auto_minor_upgrade,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_auto_upgrade, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_performance_insights(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_performance_insights(db):
        if not db.get("PerfInsightsEnabled", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_performance_insights,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_performance_insights, dbs)


@inject_clients(clients=["rds"])
def find_rds_iam_authentication_disabled(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_iam_auth(db):
        if not db.get("IAMDatabaseAuthenticationEnabled", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_iam_auth_disabled,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_iam_auth, dbs)


@inject_clients(clients=["rds"])
def find_rds_default_port_exposed(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    default_ports = {
        "mysql": 3306,
        "postgres": 5432,
        "mariadb": 3306,
        "oracle": 1521,
        "sqlserver": 1433,
    }

    def check_default_port(db):
        engine = db.get("Engine", "")
        port = db.get("Endpoint", {}).get("Port")
        if engine in default_ports and port == default_ports[engine]:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_default_port,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_default_port, dbs)


@inject_clients(clients=["rds"])
def find_rds_database_parameter_group_default(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_param_group(db):
        param_group = db.get("DBParameterGroups", [{}])[0].get(
            "DBParameterGroupName", ""
        )
        if "default" in param_group.lower():
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_default_param_group,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_param_group, dbs)


@inject_clients(clients=["rds"])
def find_rds_cluster_no_encryption(rds_client, findings, clusters=None):
    if clusters is None:
        clusters = fetch_db_clusters(rds_client)

    def check_cluster_encryption(cluster):
        if not cluster.get("StorageEncrypted", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_cluster_unencrypted,
                    cluster.get("DBClusterIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_cluster_encryption, clusters)


@inject_clients(clients=["rds"])
def find_rds_cluster_public_access(rds_client, findings, clusters=None):
    if clusters is None:
        clusters = fetch_db_clusters(rds_client)

    def check_cluster_public(cluster):
        try:
            members = cluster.get("DBClusterMembers", [])
            for member in members:
                db_id = member.get("DBInstanceIdentifier")
                db = rds_client.describe_db_instances(DBInstanceIdentifier=db_id).get(
                    "DBInstances", [{}]
                )[0]
                if db.get("PubliclyAccessible"):
                    findings.append(
                        new_vulnerability(
                            RDSVulnerability.rds_cluster_public,
                            cluster.get("DBClusterIdentifier"),
                            "rds",
                        )
                    )
                    return
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_cluster_public, clusters)


@inject_clients(clients=["rds"])
def find_rds_no_automated_backups(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_automated_backup(db):
        if not db.get("BackupRetentionPeriod") or db.get("BackupRetentionPeriod") < 1:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_automated_backup,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_automated_backup, dbs)


@inject_clients(clients=["rds"])
def find_rds_snapshots_public(rds_client, findings):
    try:
        snapshots = rds_client.describe_db_snapshots().get("DBSnapshots", [])
    except Exception as e:
        logger.error(f"Error fetching snapshots: {e}")
        return

    def check_snapshot_public(snapshot):
        try:
            attrs = rds_client.describe_db_snapshot_attributes(
                DBSnapshotIdentifier=snapshot.get("DBSnapshotIdentifier")
            )
            attributes = attrs.get("DBSnapshotAttributesResult", {}).get(
                "DBSnapshotAttributes", []
            )
            for attr in attributes:
                if attr.get("AttributeName") == "restore" and "all" in attr.get(
                    "AttributeValues", []
                ):
                    findings.append(
                        new_vulnerability(
                            RDSVulnerability.rds_snapshot_public,
                            snapshot.get("DBSnapshotIdentifier"),
                            "rds",
                        )
                    )
                    return
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_snapshot_public, snapshots)


@inject_clients(clients=["rds"])
def find_rds_no_tags(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_tags(db):
        try:
            tags = rds_client.list_tags_for_resource(
                ResourceName=db.get("DBInstanceArn")
            )
            if not tags.get("TagList"):
                findings.append(
                    new_vulnerability(
                        RDSVulnerability.rds_no_tags,
                        db.get("DBInstanceIdentifier"),
                        "rds",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_tags, dbs)


@inject_clients(clients=["rds"])
def find_rds_storage_not_encrypted_at_rest(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_storage_encryption(db):
        if not db.get("StorageEncrypted", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_storage_not_encrypted,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_storage_encryption, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_option_group(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_option_group(db):
        option_groups = db.get("OptionGroupMemberships", [])
        if not option_groups:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_option_group,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_option_group, dbs)


@inject_clients(clients=["rds"])
def find_rds_instance_no_vpc(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_vpc(db):
        vpc_id = db.get("DBSubnetGroup", {}).get("VpcId")
        if not vpc_id:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_vpc, db.get("DBInstanceIdentifier"), "rds"
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_vpc, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_cloudtrail_logging(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_cloudtrail_logging(db):
        logs = db.get("EnabledCloudwatchLogsExports", [])
        if not logs or "error" not in logs:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_cloudtrail,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_cloudtrail_logging, dbs)


@inject_clients(clients=["rds"])
def find_rds_cluster_backup_retention_low(rds_client, findings, clusters=None):
    if clusters is None:
        clusters = fetch_db_clusters(rds_client)

    def check_cluster_retention(cluster):
        if cluster.get("BackupRetentionPeriod", 0) < 7:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_cluster_low_retention,
                    cluster.get("DBClusterIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_cluster_retention, clusters)


@inject_clients(clients=["rds"])
def find_rds_instance_with_default_security_group(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_default_sg(db):
        vpc_sgs = db.get("VpcSecurityGroups", [])
        for sg in vpc_sgs:
            if sg.get("VpcSecurityGroupId") == "default":
                findings.append(
                    new_vulnerability(
                        RDSVulnerability.rds_default_sg,
                        db.get("DBInstanceIdentifier"),
                        "rds",
                    )
                )
                return

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_default_sg, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_kms_key(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_kms_key(db):
        if not db.get("KmsKeyId"):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_kms_key,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_kms_key, dbs)


@inject_clients(clients=["rds"])
def find_rds_engine_unsupported(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    unsupported = ["mysql5.6", "postgres9.5", "mariadb10.0"]

    def check_engine_version(db):
        version = db.get("EngineVersion", "")
        for unsup in unsupported:
            if version.startswith(unsup):
                findings.append(
                    new_vulnerability(
                        RDSVulnerability.rds_unsupported_engine,
                        db.get("DBInstanceIdentifier"),
                        "rds",
                    )
                )
                return

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_engine_version, dbs)


@inject_clients(clients=["rds"])
def find_rds_no_audit_logs(rds_client, findings, dbs=None):
    if dbs is None:
        dbs = fetch_db_instances(rds_client)

    def check_audit_logs(db):
        logs = db.get("EnabledCloudwatchLogsExports", [])
        if not logs or "audit" not in logs:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_audit_logs,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_audit_logs, dbs)
