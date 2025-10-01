from botocore.exceptions import ClientError
import json
from scanner.mitre_map import Vulnerability, new_vulnerability


def find_public_s3_buckets_by_acl(s3_client):
    try:
        bucket_list = s3_client.list_buckets()
    except Exception:
        return []
    public_buckets_acl = []
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
                    public_buckets_acl.append(bucket_name)
                    break
        except ClientError:
            continue
        except Exception:
            continue
    return public_buckets_acl


def find_public_s3_buckets_by_policy(s3_client):
    try:
        bucket_list = s3_client.list_buckets()
    except Exception:
        return []
    public_buckets_policy = []
    for bucket in bucket_list.get("Buckets", []):
        bucket_name = bucket["Name"]
        try:
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
                                public_buckets_policy.append(bucket_name)
                                break
        except s3_client.exceptions.NoSuchBucketPolicy:
            continue
        except ClientError:
            continue
        except Exception:
            continue
    return public_buckets_policy


def find_public_s3_buckets(s3_client, findings):
    acl_buckets = find_public_s3_buckets_by_acl(s3_client)
    policy_buckets = find_public_s3_buckets_by_policy(s3_client)
    combined = list(set(acl_buckets + policy_buckets))
    for b in combined:
        findings.append(new_vulnerability(Vulnerability.public_s3_bucket, b))


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
