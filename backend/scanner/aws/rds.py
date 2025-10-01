from scanner.mitre_map import Vulnerability, new_vulnerability


def find_rds_unencrypted(rds_client, findings):
    unencrypted = []
    dbs = rds_client.describe_db_instances()
    for db in dbs.get("DBInstances", []):
        arn = db.get("DBInstanceArn")
        if not db.get("StorageEncrypted", False):
            unencrypted.append(arn)
    for db in unencrypted:
        findings.append(new_vulnerability(Vulnerability.rds_instance_unencrypted, db))
