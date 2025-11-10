from botocore.exceptions import ClientError
from scanner.mitre_maps.rds_mitre_map import RDSVulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients


@inject_clients(clients=["rds"])
def find_rds_unencrypted(rds_client, findings):
    unencrypted = []
    dbs = rds_client.describe_db_instances()
    for db in dbs.get("DBInstances", []):
        arn = db.get("DBInstanceArn")
        if not db.get("StorageEncrypted", False):
            unencrypted.append(arn)
    for db in unencrypted:
        findings.append(
            new_vulnerability(RDSVulnerability.rds_instance_unencrypted, db, "rds")
        )


@inject_clients(clients=["rds"])
def find_rds_public_access_enabled(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if db.get("PubliclyAccessible"):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_instance_public_access,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )


@inject_clients(clients=["rds"])
def find_rds_no_backup(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if db.get("BackupRetentionPeriod", 0) == 0:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_backup,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )


@inject_clients(clients=["rds"])
def find_rds_backup_retention_low(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if db.get("BackupRetentionPeriod", 0) < 7:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_low_backup_retention,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )


@inject_clients(clients=["rds"])
def find_rds_no_multi_az(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if not db.get("MultiAZ", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_multi_az,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )


@inject_clients(clients=["rds"])
def find_rds_no_enhanced_monitoring(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if not db.get("EnabledCloudwatchLogsExports"):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_enhanced_monitoring,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )


@inject_clients(clients=["rds"])
def find_rds_no_deletion_protection(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if not db.get("DeletionProtection", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_deletion_protection,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )


@inject_clients(clients=["rds"])
def find_rds_no_copy_snapshots_to_region(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if not db.get("CopyTagsToSnapshot", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_copy_snapshots,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )


@inject_clients(clients=["rds"])
def find_rds_minor_version_upgrade_auto_enabled(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if db.get("AutoMinorVersionUpgrade", True):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_auto_minor_upgrade,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )


@inject_clients(clients=["rds"])
def find_rds_no_performance_insights(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if not db.get("PerfInsightsEnabled", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_performance_insights,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )


@inject_clients(clients=["rds"])
def find_rds_iam_authentication_disabled(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if not db.get("IAMDatabaseAuthenticationEnabled", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_iam_auth_disabled,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )


@inject_clients(clients=["rds"])
def find_rds_default_port_exposed(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    default_ports = {
        "mysql": 3306,
        "postgres": 5432,
        "mariadb": 3306,
        "oracle": 1521,
        "sqlserver": 1433,
    }
    for db in dbs:
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


@inject_clients(clients=["rds"])
def find_rds_database_parameter_group_default(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
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


@inject_clients(clients=["rds"])
def find_rds_cluster_no_encryption(rds_client, findings):
    try:
        clusters = rds_client.describe_db_clusters().get("DBClusters", [])
        for cluster in clusters:
            if not cluster.get("StorageEncrypted", False):
                findings.append(
                    new_vulnerability(
                        RDSVulnerability.rds_cluster_unencrypted,
                        cluster.get("DBClusterIdentifier"),
                        "rds",
                    )
                )
    except ClientError:
        pass


@inject_clients(clients=["rds"])
def find_rds_cluster_public_access(rds_client, findings):
    try:
        clusters = rds_client.describe_db_clusters().get("DBClusters", [])
        for cluster in clusters:
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
                    break
    except ClientError:
        pass


@inject_clients(clients=["rds"])
def find_rds_no_automated_backups(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if not db.get("BackupRetentionPeriod") or db.get("BackupRetentionPeriod") < 1:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_automated_backup,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )


@inject_clients(clients=["rds"])
def find_rds_snapshots_public(rds_client, findings):
    try:
        snapshots = rds_client.describe_db_snapshots().get("DBSnapshots", [])
        for snapshot in snapshots:
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
    except ClientError:
        pass


@inject_clients(clients=["rds"])
def find_rds_no_tags(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
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


@inject_clients(clients=["rds"])
def find_rds_storage_not_encrypted_at_rest(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if not db.get("StorageEncrypted", False):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_storage_not_encrypted,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )


@inject_clients(clients=["rds"])
def find_rds_no_option_group(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        option_groups = db.get("OptionGroupMemberships", [])
        if not option_groups:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_option_group,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )


@inject_clients(clients=["rds"])
def find_rds_instance_no_vpc(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        vpc_id = db.get("DBSubnetGroup", {}).get("VpcId")
        if not vpc_id:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_vpc, db.get("DBInstanceIdentifier"), "rds"
                )
            )


@inject_clients(clients=["rds"])
def find_rds_no_cloudtrail_logging(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        logs = db.get("EnabledCloudwatchLogsExports", [])
        if not logs or "error" not in logs:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_cloudtrail,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )


@inject_clients(clients=["rds"])
def find_rds_cluster_backup_retention_low(rds_client, findings):
    try:
        clusters = rds_client.describe_db_clusters().get("DBClusters", [])
        for cluster in clusters:
            if cluster.get("BackupRetentionPeriod", 0) < 7:
                findings.append(
                    new_vulnerability(
                        RDSVulnerability.rds_cluster_low_retention,
                        cluster.get("DBClusterIdentifier"),
                        "rds",
                    )
                )
    except ClientError:
        pass


@inject_clients(clients=["rds"])
def find_rds_instance_with_default_security_group(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
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
                break


@inject_clients(clients=["rds"])
def find_rds_no_kms_key(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if not db.get("KmsKeyId"):
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_kms_key,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )


@inject_clients(clients=["rds"])
def find_rds_engine_unsupported(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    unsupported = ["mysql5.6", "postgres9.5", "mariadb10.0"]
    for db in dbs:
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


@inject_clients(clients=["rds"])
def find_rds_no_audit_logs(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        logs = db.get("EnabledCloudwatchLogsExports", [])
        if not logs or "audit" not in logs:
            findings.append(
                new_vulnerability(
                    RDSVulnerability.rds_no_audit_logs,
                    db.get("DBInstanceIdentifier"),
                    "rds",
                )
            )
