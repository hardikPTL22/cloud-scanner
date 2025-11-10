from botocore.exceptions import ClientError
import json
from scanner.mitre_maps.s3_mitre_map import S3Vulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients


@inject_clients(clients=["s3"])
def find_public_s3_buckets(s3_client, findings):
    try:
        bucket_list = s3_client.list_buckets()
    except Exception:
        return

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
        except ClientError:
            pass
        except Exception:
            pass

    for b in public_buckets:
        findings.append(new_vulnerability(S3Vulnerability.public_s3_bucket, b, "s3"))


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
            ):
                unencrypted.append(name)
        except Exception:
            pass
    for b in unencrypted:
        findings.append(
            new_vulnerability(S3Vulnerability.unencrypted_s3_bucket, b, "s3")
        )


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
            pass
    for b in versioning_disabled:
        findings.append(
            new_vulnerability(S3Vulnerability.s3_bucket_versioning_disabled, b, "s3")
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
            pass
    for b in logging_disabled:
        findings.append(
            new_vulnerability(S3Vulnerability.s3_bucket_logging_disabled, b, "s3")
        )


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
            pass
    for b in disabled:
        findings.append(
            new_vulnerability(
                S3Vulnerability.s3_bucket_block_public_access_disabled, b, "s3"
            )
        )


@inject_clients(clients=["s3"])
def find_bucket_mfa_delete_disabled(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=name)
            if versioning.get("MFADelete") != "Enabled":
                findings.append(
                    new_vulnerability(
                        S3Vulnerability.s3_mfa_delete_disabled, name, "s3"
                    )
                )
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_no_lifecycle_policy(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            s3_client.get_bucket_lifecycle_configuration(Bucket=name)
        except ClientError as e:
            if (
                e.response.get("Error", {}).get("Code")
                == "NoSuchLifecycleConfiguration"
            ):
                findings.append(
                    new_vulnerability(S3Vulnerability.s3_no_lifecycle, name, "s3")
                )
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_no_cors_policy(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            cors = s3_client.get_bucket_cors(Bucket=name)
            if cors.get("CORSRules"):
                for rule in cors["CORSRules"]:
                    allowed_origins = rule.get("AllowedOrigins", [])
                    if "*" in allowed_origins:
                        findings.append(
                            new_vulnerability(
                                S3Vulnerability.s3_cors_all_origins, name, "s3"
                            )
                        )
                        break
        except ClientError:
            pass
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_without_tags(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            tags = s3_client.get_bucket_tagging(Bucket=name)
            if not tags.get("TagSet"):
                findings.append(
                    new_vulnerability(S3Vulnerability.s3_bucket_no_tags, name, "s3")
                )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchTagSet":
                findings.append(
                    new_vulnerability(S3Vulnerability.s3_bucket_no_tags, name, "s3")
                )
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_website_enabled(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            website = s3_client.get_bucket_website(Bucket=name)
            if website.get("WebsiteConfiguration"):
                findings.append(
                    new_vulnerability(S3Vulnerability.s3_website_enabled, name, "s3")
                )
        except ClientError:
            pass
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_no_object_lock(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            lock = s3_client.get_object_lock_configuration(Bucket=name)
            if (
                not lock.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled")
                == "Enabled"
            ):
                findings.append(
                    new_vulnerability(S3Vulnerability.s3_no_object_lock, name, "s3")
                )
        except ClientError:
            findings.append(
                new_vulnerability(S3Vulnerability.s3_no_object_lock, name, "s3")
            )
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_requester_pays_enabled(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            request_payment = s3_client.get_bucket_request_payment(Bucket=name)
            if request_payment.get("Payer") == "Requester":
                findings.append(
                    new_vulnerability(S3Vulnerability.s3_requester_pays, name, "s3")
                )
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_acl_public(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            acl = s3_client.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if (
                    grantee.get("URI")
                    == "http://acs.amazonaws.com/groups/global/AllUsers"
                ):
                    findings.append(
                        new_vulnerability(S3Vulnerability.s3_acl_public, name, "s3")
                    )
                    break
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_policy_allows_unencrypted_upload(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            policy = s3_client.get_bucket_policy(Bucket=name)
            policy_dict = json.loads(policy["Policy"])
            for stmt in policy_dict.get("Statement", []):
                if stmt.get("Effect") == "Deny":
                    condition = stmt.get("Condition", {})
                    if not condition.get("Bool", {}).get(
                        "s3:x-amz-server-side-encryption"
                    ):
                        findings.append(
                            new_vulnerability(
                                S3Vulnerability.s3_unencrypted_upload_allowed,
                                name,
                                "s3",
                            )
                        )
                        break
        except ClientError:
            pass
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_no_replication(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            replication = s3_client.get_bucket_replication(Bucket=name)
            if not replication.get("ReplicationConfiguration"):
                findings.append(
                    new_vulnerability(S3Vulnerability.s3_no_replication, name, "s3")
                )
        except ClientError as e:
            if (
                e.response.get("Error", {}).get("Code")
                == "ReplicationConfigurationNotFoundError"
            ):
                findings.append(
                    new_vulnerability(S3Vulnerability.s3_no_replication, name, "s3")
                )
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_no_server_access_logging(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            logging = s3_client.get_bucket_logging(Bucket=name)
            if not logging.get("LoggingEnabled"):
                findings.append(
                    new_vulnerability(
                        S3Vulnerability.s3_no_server_access_logging, name, "s3"
                    )
                )
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_no_cloudtrail_logging(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            notification = s3_client.get_bucket_notification_configuration(Bucket=name)
            if not notification:
                findings.append(
                    new_vulnerability(
                        S3Vulnerability.s3_no_cloudtrail_logging, name, "s3"
                    )
                )
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_no_intelligent_tiering(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            config = s3_client.get_bucket_intelligent_tiering_configuration(Bucket=name)
            if not config.get("IntelligentTieringConfiguration"):
                findings.append(
                    new_vulnerability(
                        S3Vulnerability.s3_no_intelligent_tiering, name, "s3"
                    )
                )
        except ClientError:
            findings.append(
                new_vulnerability(S3Vulnerability.s3_no_intelligent_tiering, name, "s3")
            )
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_object_lock_retention_default(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            lock = s3_client.get_object_lock_configuration(Bucket=name)
            rule = lock.get("ObjectLockConfiguration", {}).get("Rule", {})
            if not rule.get("DefaultRetention"):
                findings.append(
                    new_vulnerability(
                        S3Vulnerability.s3_object_lock_no_retention, name, "s3"
                    )
                )
        except ClientError:
            pass
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_public_read_access(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            acl = s3_client.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") in [
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                ]:
                    permission = grant.get("Permission", "")
                    if permission in ["READ", "FULL_CONTROL"]:
                        findings.append(
                            new_vulnerability(
                                S3Vulnerability.s3_public_read_access, name, "s3"
                            )
                        )
                        break
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_public_write_access(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            acl = s3_client.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if (
                    grantee.get("URI")
                    == "http://acs.amazonaws.com/groups/global/AllUsers"
                ):
                    permission = grant.get("Permission", "")
                    if permission in ["WRITE", "FULL_CONTROL"]:
                        findings.append(
                            new_vulnerability(
                                S3Vulnerability.s3_public_write_access, name, "s3"
                            )
                        )
                        break
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_default_encryption_not_aes256(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=name)
            rules = encryption.get("ServerSideEncryptionConfiguration", {}).get(
                "Rules", []
            )
            for rule in rules:
                sse = rule.get("ApplyServerSideEncryptionByDefault", {})
                if (
                    sse.get("SSEAlgorithm") != "AES256"
                    and sse.get("SSEAlgorithm") != "aws:kms"
                ):
                    findings.append(
                        new_vulnerability(
                            S3Vulnerability.s3_non_standard_encryption, name, "s3"
                        )
                    )
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_no_bucket_key_enabled(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=name)
            rules = encryption.get("ServerSideEncryptionConfiguration", {}).get(
                "Rules", []
            )
            for rule in rules:
                if not rule.get("BucketKeyEnabled", False):
                    findings.append(
                        new_vulnerability(
                            S3Vulnerability.s3_bucket_key_disabled, name, "s3"
                        )
                    )
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_no_user_versioning(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=name)
            status = versioning.get("Status", "")
            if status != "Enabled":
                findings.append(
                    new_vulnerability(
                        S3Vulnerability.s3_user_versioning_disabled, name, "s3"
                    )
                )
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_unrestricted_policy(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            policy = s3_client.get_bucket_policy(Bucket=name)
            policy_dict = json.loads(policy["Policy"])
            for stmt in policy_dict.get("Statement", []):
                principal = stmt.get("Principal", {})
                if principal == "*" and stmt.get("Effect") == "Allow":
                    findings.append(
                        new_vulnerability(
                            S3Vulnerability.s3_unrestricted_policy, name, "s3"
                        )
                    )
                    break
        except ClientError:
            pass
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_no_kms_encryption(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=name)
            rules = encryption.get("ServerSideEncryptionConfiguration", {}).get(
                "Rules", []
            )
            has_kms = False
            for rule in rules:
                if (
                    rule.get("ApplyServerSideEncryptionByDefault", {}).get(
                        "SSEAlgorithm"
                    )
                    == "aws:kms"
                ):
                    has_kms = True
                    break
            if not has_kms:
                findings.append(
                    new_vulnerability(S3Vulnerability.s3_no_kms_encryption, name, "s3")
                )
        except Exception:
            pass


@inject_clients(clients=["s3"])
def find_bucket_no_access_point(s3_client, findings):
    bucket_list = s3_client.list_buckets()
    for bucket in bucket_list.get("Buckets", []):
        name = bucket["Name"]
        try:
            access_points = s3_client.list_access_points(Bucket=name)
            if not access_points.get("AccessPointList"):
                findings.append(
                    new_vulnerability(S3Vulnerability.s3_no_access_point, name, "s3")
                )
        except ClientError:
            pass
        except Exception:
            pass
