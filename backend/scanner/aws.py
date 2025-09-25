import json
from botocore.exceptions import ClientError

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


def find_public_s3_buckets(s3_client):
    acl_buckets = find_public_s3_buckets_by_acl(s3_client)
    policy_buckets = find_public_s3_buckets_by_policy(s3_client)
    combined = list(set(acl_buckets + policy_buckets))
    return combined


def find_unencrypted_s3_buckets(s3_client):
    """
    Return list of bucket names that do NOT have default bucket encryption configured.
    (Note: objects can still be encrypted individually; this checks bucket default encryption)
    """
    try:
        bucket_list = s3_client.list_buckets()
    except Exception:
        return []
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
    return unencrypted


def find_over_permissive_iam_policies(iam_client):
    over_permissive_policies = []

    paginator = iam_client.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page.get("Policies", []):
            policy_arn = policy["Arn"]
            try:
                versions = iam_client.list_policy_versions(PolicyArn=policy_arn)
                default_version = next(
                    (
                        v
                        for v in versions.get("Versions", [])
                        if v.get("IsDefaultVersion")
                    ),
                    None,
                )
                if default_version:
                    version_info = iam_client.get_policy_version(
                        PolicyArn=policy_arn, VersionId=default_version["VersionId"]
                    )
                    document = version_info["PolicyVersion"]["Document"]
                    statements = document.get("Statement", [])
                    if not isinstance(statements, list):
                        statements = [statements]
                    for stmt in statements:
                        actions = stmt.get("Action", [])
                        resources = stmt.get("Resource", [])
                        if not isinstance(actions, list):
                            actions = [actions]
                        if not isinstance(resources, list):
                            resources = [resources]
                        if "*" in actions or "*" in resources:
                            over_permissive_policies.append(policy["PolicyName"])
                            break
            except ClientError:
                continue
            except Exception:
                continue
    return over_permissive_policies


def find_open_security_groups(ec2_client):
    open_groups = []
    try:
        response = ec2_client.describe_security_groups()
    except Exception:
        return []
    for sg in response.get("SecurityGroups", []):
        for perm in sg.get("IpPermissions", []):

            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    open_groups.append(sg.get("GroupName") or sg.get("GroupId"))
                    break
            for ip_range in perm.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    open_groups.append(sg.get("GroupName") or sg.get("GroupId"))
                    break

    return list(set(open_groups))


def find_cloudtrail_not_logging(cloudtrail_client):
    """
    Returns list of trail names that are present but not currently logging.
    """
    not_logging = []
    try:
        trails_resp = cloudtrail_client.describe_trails(includeShadowTrails=False)
    except Exception:
        return []
    for t in trails_resp.get("trailList", []):
        name = t.get("Name") or t.get("TrailARN")
        try:
            status = (
                cloudtrail_client.get_trail_status(Name=t.get("Name"))
                if t.get("Name")
                else cloudtrail_client.get_trail_status(TrailNameList=[t.get("TrailARN")])
            )

            is_logging = status.get("IsLogging")
            if is_logging is False:
                not_logging.append(name)
        except ClientError:

            continue
        except Exception:
            continue
    return not_logging
