from botocore.exceptions import ClientError
import json
from scanner.mitre_map import Vulnerability, new_vulnerability
from scanner.aws.decorator import inject_clients


@inject_clients(clients=["s3"])
def find_public_s3_buckets(s3_client, findings):
    try:
        bucket_list = s3_client.list_buckets()
    except Exception:
        return []

    public_buckets = set()

    for bucket in bucket_list.get("Buckets", []):
        bucket_name = bucket["Name"]

        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") in [
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                ]:
                    public_buckets.add(bucket_name)
                    break

            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_dict = json.loads(policy["Policy"])
            for statement in policy_dict.get("Statement", []):
                if statement.get("Effect") == "Allow" and (
                    statement.get("Principal") == "*"
                    or statement.get("Principal", {}).get("AWS") == "*"
                ):
                    actions = statement.get("Action", [])
                    if not isinstance(actions, list):
                        actions = [actions]
                    resources = statement.get("Resource", [])
                    if not isinstance(resources, list):
                        resources = [resources]
                    if "s3:GetObject" in actions or "s3:*" in actions:
                        for resource in resources:
                            if resource.endswith("/*") and bucket_name in resource:
                                public_buckets.add(bucket_name)
                                break
        except s3_client.exceptions.NoSuchBucketPolicy:
            pass
        except ClientError:
            pass
        except Exception:
            pass

    for b in public_buckets:
        findings.append(new_vulnerability(Vulnerability.public_s3_bucket, b))


@inject_clients(clients=["s3"])
def find_unencrypted_s3_buckets(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    unencrypted = []
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            s3_client.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in (
                "ServerSideEncryptionConfigurationNotFoundError",
                "NoSuchEncryptionConfiguration",
                "404",
                "AccessDenied",
            ):
                if code == "AccessDenied":
                    continue
                unencrypted.append(name)
            else:
                continue
        except Exception:
            continue
    for b in unencrypted:
        findings.append(new_vulnerability(Vulnerability.unencrypted_s3_bucket, b))


@inject_clients(clients=["s3"])
def find_bucket_versioning_disabled(s3_client, findings):
    versioning_disabled = []
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=name)
            status = versioning.get("Status", "")
            if status != "Enabled":
                versioning_disabled.append(name)
        except Exception:
            continue
    for b in versioning_disabled:
        findings.append(
            new_vulnerability(Vulnerability.s3_bucket_versioning_disabled, b)
        )


@inject_clients(clients=["s3"])
def find_bucket_logging_disabled(s3_client, findings):
    logging_disabled = []
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            logging = s3_client.get_bucket_logging(Bucket=name)
            if not logging.get("LoggingEnabled"):
                logging_disabled.append(name)
        except Exception:
            continue
    for b in logging_disabled:
        findings.append(new_vulnerability(Vulnerability.s3_bucket_logging_disabled, b))


@inject_clients(clients=["s3"])
def find_bucket_block_public_access_disabled(s3_client, findings):
    disabled = []
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            response = s3_client.get_public_access_block(Bucket=name)
            config = response.get("PublicAccessBlockConfiguration", {})
            if not all(
                [
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ]
            ):
                disabled.append(name)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "NoSuchPublicAccessBlockConfiguration":
                disabled.append(name)
        except Exception:
            continue
    for b in disabled:
        findings.append(
            new_vulnerability(Vulnerability.s3_bucket_block_public_access_disabled, b)
        )


@inject_clients(clients=["s3"])
def find_s3_bucket_public_read_acls(s3_client, findings):
    buckets = s3_client.list_buckets().get("Buckets", [])
    for bucket in buckets:
        bucket_name = bucket["Name"]
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") in [
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                ]:
                    findings.append(
                        {
                            "type": Vulnerability.public_s3_bucket,
                            "name": bucket_name,
                            "severity": "High",
                            "details": "Bucket has public read ACL.",
                        }
                    )
                    break
        except Exception:
            continue


@inject_clients(clients=["s3"])
def find_s3_bucket_encryption_disabled(s3_client, findings):
    buckets = s3_client.list_buckets().get("Buckets", [])
    for bucket in buckets:
        try:
            s3_client.get_bucket_encryption(Bucket=bucket["Name"])
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(
                    {
                        "type": Vulnerability.unencrypted_s3_bucket,
                        "name": bucket["Name"],
                        "severity": "Medium",
                        "details": "Bucket encryption is not enabled.",
                    }
                )
