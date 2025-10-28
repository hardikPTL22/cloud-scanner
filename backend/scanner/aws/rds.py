from scanner.mitre_map import Vulnerability
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
        findings.append(new_vulnerability(Vulnerability.rds_instance_unencrypted, db))


@inject_clients(clients=["rds"])
def find_rds_public_access_enabled(rds_client, findings):
    dbs = rds_client.describe_db_instances().get("DBInstances", [])
    for db in dbs:
        if db.get("PubliclyAccessible"):
            findings.append(
                {
                    "type": Vulnerability.rds_instance_public_access,
                    "name": db.get("DBInstanceIdentifier"),
                    "severity": "High",
                    "details": "RDS instance is publicly accessible.",
                }
            )
