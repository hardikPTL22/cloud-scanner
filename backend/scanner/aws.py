from botocore.exceptions import ClientError
from scanner.mitre_map import Vulnerability, RESOURCES_MAP
import json
from boto3.session import Session


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
        findings.append(
            {
                "type": Vulnerability.public_s3_bucket,
                "name": b,
                "severity": "High",
                "details": "Bucket has public ACL or bucket policy allowing public read.",
            }
        )


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
        findings.append(
            {
                "type": Vulnerability.unencrypted_s3_bucket,
                "name": b,
                "severity": "Medium",
                "details": "Bucket does not have default server-side encryption configured.",
            }
        )


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
            {
                "type": Vulnerability.s3_bucket_versioning_disabled,
                "name": b,
                "severity": "Medium",
                "details": "Bucket versioning is not enabled.",
            }
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
        findings.append(
            {
                "type": Vulnerability.s3_bucket_logging_disabled,
                "name": b,
                "severity": "Medium",
                "details": "Bucket logging is not enabled.",
            }
        )


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
            {
                "type": Vulnerability.s3_bucket_block_public_access_disabled,
                "name": b,
                "severity": "High",
                "details": "Bucket block public access settings are not fully enabled.",
            }
        )


def find_iam_users_without_mfa(iam_client, findings):
    users_no_mfa = []
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user["UserName"]
            mfa_devices = iam_client.list_mfa_devices(UserName=user_name)
            if len(mfa_devices.get("MFADevices", [])) == 0:
                users_no_mfa.append(user_name)
    for u in users_no_mfa:
        findings.append(
            {
                "type": Vulnerability.iam_user_no_mfa,
                "name": u,
                "severity": "High",
                "details": "IAM user does not have MFA enabled.",
            }
        )


def find_unused_iam_access_keys(iam_client, findings):
    unused_keys = []
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user["UserName"]
            keys = iam_client.list_access_keys(UserName=user_name)
            for key in keys.get("AccessKeyMetadata", []):
                last_used_resp = iam_client.get_access_key_last_used(
                    AccessKeyId=key["AccessKeyId"]
                )
                last_used_date = last_used_resp.get("AccessKeyLastUsed", {}).get(
                    "LastUsedDate", None
                )
                if not last_used_date:
                    unused_keys.append(f"{user_name}:{key['AccessKeyId']}")
                else:
                    from datetime import datetime, timedelta

                    if last_used_date < datetime.now(
                        tz=last_used_date.tzinfo
                    ) - timedelta(days=90):
                        unused_keys.append(f"{user_name}:{key['AccessKeyId']}")
    for key in unused_keys:
        findings.append(
            {
                "type": Vulnerability.iam_unused_access_key,
                "name": key,
                "severity": "Medium",
                "details": "IAM access key unused for over 90 days.",
            }
        )


def find_inline_policies(iam_client, findings):
    inline_policies = []
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user["UserName"]
            policies = iam_client.list_user_policies(UserName=user_name)
            for policy_name in policies.get("PolicyNames", []):
                inline_policies.append(f"user:{user_name}:{policy_name}")
    paginator_roles = iam_client.get_paginator("list_roles")
    for page in paginator_roles.paginate():
        for role in page.get("Roles", []):
            role_name = role["RoleName"]
            policies = iam_client.list_role_policies(RoleName=role_name)
            for policy_name in policies.get("PolicyNames", []):
                inline_policies.append(f"role:{role_name}:{policy_name}")
    for p in inline_policies:
        findings.append(
            {
                "type": Vulnerability.iam_inline_policy,
                "name": p,
                "severity": "Medium",
                "details": "IAM inline policy attached to user or role.",
            }
        )


def find_root_access_keys_exist(iam_client, findings):
    try:
        root_keys = []
        keys = iam_client.list_access_keys(UserName="root")
        for key in keys.get("AccessKeyMetadata", []):
            root_keys.append(key["AccessKeyId"])
        for k in root_keys:
            findings.append(
                {
                    "type": Vulnerability.iam_root_access_key,
                    "name": k,
                    "severity": "High",
                    "details": "Root user has access keys, which is risky.",
                }
            )
    except:
        pass


def find_security_groups_open_ingress(ec2_client, findings):
    open_groups = []
    response = ec2_client.describe_security_groups()
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
    for sg in open_groups:
        findings.append(
            {
                "type": Vulnerability.open_security_group_ingress,
                "name": sg,
                "severity": "High",
                "details": "Security group has ingress rule open to the world.",
            }
        )


def find_security_groups_open_egress(ec2_client, findings):
    open_egress = []
    response = ec2_client.describe_security_groups()
    for sg in response.get("SecurityGroups", []):
        for perm in sg.get("IpPermissionsEgress", []):
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    open_egress.append(sg.get("GroupName") or sg.get("GroupId"))
                    break
            for ip_range in perm.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") == "::/0":
                    open_egress.append(sg.get("GroupName") or sg.get("GroupId"))
                    break
    for sg in open_egress:
        findings.append(
            {
                "type": Vulnerability.open_security_group_egress,
                "name": sg,
                "severity": "Medium",
                "details": "Security group has egress rule open to the world.",
            }
        )


def find_unused_security_groups(ec2_client, findings):
    unused_groups = []
    response = ec2_client.describe_security_groups()
    for sg in response.get("SecurityGroups", []):
        attachments = sg.get("Attachments", [])
        # In some API versions this may not exist, fallback to checking if GroupName matches anything
        if not attachments:
            # Rough check, further improvements may be needed
            unused_groups.append(sg.get("GroupName") or sg.get("GroupId"))
    for sg in unused_groups:
        findings.append(
            {
                "type": Vulnerability.unused_security_group,
                "name": sg,
                "severity": "Low",
                "details": "Security group is not attached to any resource.",
            }
        )


def find_cloudtrail_not_logging(cloudtrail_client):
    not_logging = []
    try:
        trails_resp = cloudtrail_client.describe_trails(includeShadowTrails=False)
        for t in trails_resp.get("trailList", []):
            name = t.get("Name") or t.get("TrailARN")
            try:
                status = (
                    cloudtrail_client.get_trail_status(Name=t.get("Name"))
                    if t.get("Name")
                    else cloudtrail_client.get_trail_status(
                        TrailNameList=[t.get("TrailARN")]
                    )
                )
                is_logging = status.get("IsLogging")
                if is_logging is False:
                    not_logging.append(name)
            except ClientError:
                continue
            except Exception:
                continue
    except Exception:
        return []
    return not_logging


def find_cloudtrail_not_multi_region(cloudtrail_client, findings):
    not_multi_region = []
    trails_resp = cloudtrail_client.describe_trails(includeShadowTrails=False)
    for t in trails_resp.get("trailList", []):
        if not t.get("IsMultiRegionTrail", False):
            name = t.get("Name") or t.get("TrailARN")
            not_multi_region.append(name)
    for t in not_multi_region:
        findings.append(
            {
                "type": Vulnerability.cloudtrail_not_multi_region,
                "name": t,
                "severity": "Medium",
                "details": "CloudTrail is not multi-region.",
            }
        )


def find_cloudtrail_no_log_file_validation(cloudtrail_client, findings):
    no_validation = []
    trails_resp = cloudtrail_client.describe_trails(includeShadowTrails=False)
    for t in trails_resp.get("trailList", []):
        try:
            if not t.get("LogFileValidationEnabled", False):
                name = t.get("Name") or t.get("TrailARN")
                no_validation.append(name)
        except Exception:
            continue
    for t in no_validation:
        findings.append(
            {
                "type": Vulnerability.cloudtrail_no_log_file_validation,
                "name": t,
                "severity": "Medium",
                "details": "CloudTrail log file validation is not enabled.",
            }
        )


def find_cloudtrail_bucket_public(s3_client, cloudtrail_client, findings):
    pub_buckets = []
    trails_resp = cloudtrail_client.describe_trails(includeShadowTrails=False)
    for t in trails_resp.get("trailList", []):
        bucket_name = t.get("S3BucketName")
        if bucket_name:
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if (
                        grantee.get("URI")
                        == "http://acs.amazonaws.com/groups/global/AllUsers"
                    ):
                        pub_buckets.append(bucket_name)
                        break
            except Exception:
                continue
    for b in pub_buckets:
        findings.append(
            {
                "type": Vulnerability.cloudtrail_bucket_public,
                "name": b,
                "severity": "High",
                "details": "CloudTrail log bucket is publicly accessible.",
            }
        )


def find_guardduty_disabled(guardduty_client, findings):
    disabled = []
    detectors = guardduty_client.list_detectors()
    if not detectors.get("DetectorIds"):
        disabled.append("GuardDuty Detector Not Found")
    else:
        for detector_id in detectors.get("DetectorIds"):
            status = guardduty_client.get_detector(DetectorId=detector_id)
            if not status.get("Status") == "ENABLED":
                disabled.append(detector_id)
    for d in disabled:
        findings.append(
            {
                "type": Vulnerability.guardduty_disabled,
                "name": d,
                "severity": "High",
                "details": "GuardDuty is not enabled.",
            }
        )


def find_vpc_flow_logs_disabled(ec2_client, findings):
    disabled = []
    vpcs_resp = ec2_client.describe_vpcs()
    for vpc in vpcs_resp.get("Vpcs", []):
        vpc_id = vpc.get("VpcId")
        flow_logs_resp = ec2_client.describe_flow_logs(
            Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
        )
        if not flow_logs_resp.get("FlowLogs"):
            disabled.append(vpc_id)
    for vpc in disabled:
        findings.append(
            {
                "type": Vulnerability.vpc_flow_logs_disabled,
                "name": vpc,
                "severity": "Medium",
                "details": "VPC Flow Logs are not enabled.",
            }
        )


def find_ebs_unencrypted(ec2_client, findings):
    unencrypted = []
    volumes_resp = ec2_client.describe_volumes()
    for vol in volumes_resp.get("Volumes", []):
        vol_id = vol.get("VolumeId")
        if not vol.get("Encrypted", False):
            unencrypted.append(vol_id)
    for vol in unencrypted:
        findings.append(
            {
                "type": Vulnerability.ebs_volume_unencrypted,
                "name": vol,
                "severity": "High",
                "details": "EBS volume is not encrypted.",
            }
        )


def find_rds_unencrypted(rds_client, findings):
    unencrypted = []
    dbs = rds_client.describe_db_instances()
    for db in dbs.get("DBInstances", []):
        arn = db.get("DBInstanceArn")
        if not db.get("StorageEncrypted", False):
            unencrypted.append(arn)
    for db in unencrypted:
        findings.append(
            {
                "type": Vulnerability.rds_instance_unencrypted,
                "name": db,
                "severity": "High",
                "details": "RDS instance storage is not encrypted.",
            }
        )


def find_ssm_params_unencrypted(ssm_client, findings):
    unencrypted = []
    paginator = ssm_client.get_paginator("describe_parameters")
    for page in paginator.paginate():
        for param in page.get("Parameters", []):
            name = param.get("Name")
            try:
                details = ssm_client.get_parameter(Name=name, WithDecryption=True)
                # If no error, param is encrypted
            except ClientError as e:
                if e.response["Error"]["Code"] == "ParameterNotFound":
                    continue
                elif e.response["Error"]["Code"] == "ValidationException":
                    # This may happen, treat as unencrypted
                    unencrypted.append(name)
    for param in unencrypted:
        findings.append(
            {
                "type": Vulnerability.ssm_parameter_unencrypted,
                "name": param,
                "severity": "High",
                "details": "SSM parameter is unencrypted or could not be decrypted.",
            }
        )


def find_lambda_overpermissive_roles(lambda_client, iam_client, findings):
    overpermissive = []
    funcs = lambda_client.list_functions()
    for f in funcs.get("Functions", []):
        role_arn = f.get("Role")
        if role_arn:
            role_name = role_arn.split("/")[-1]
            try:
                policy_list = iam_client.list_attached_role_policies(RoleName=role_name)
                for p in policy_list.get("AttachedPolicies", []):
                    # Just add the names, detailed checks could be added
                    if "*" in p.get("PolicyName", ""):
                        overpermissive.append(role_name)
            except Exception:
                continue
    for role in overpermissive:
        findings.append(
            {
                "type": Vulnerability.lambda_overpermissive_role,
                "name": role,
                "severity": "High",
                "details": "Lambda function assigned role with overly permissive policies.",
            }
        )


def find_api_gateway_open_resources(apigateway_client, findings):
    open_resources = []
    apis = apigateway_client.get_rest_apis()
    for api in apis.get("items", []):
        api_id = api.get("id")
        resources = apigateway_client.get_resources(restApiId=api_id)
        for res in resources.get("items", []):
            # Check for ANY method without authorization (this is a basic check)
            for method in res.get("resourceMethods", []):
                method_info = res["resourceMethods"][method]
                if (
                    "authorizationType" not in method_info
                    or method_info["authorizationType"] == "NONE"
                ):
                    open_resources.append(f"{api_id}:{res.get('id')}")
    for resource in open_resources:
        findings.append(
            {
                "type": Vulnerability.apigateway_open_resource,
                "name": resource,
                "severity": "High",
                "details": "API Gateway resource allows open access without authorization.",
            }
        )


def find_over_permissive_iam_policies(iam_client, findings):
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
    for b in over_permissive_policies:
        findings.append(
            {
                "type": Vulnerability.s3_bucket_block_public_access_disabled,
                "name": b,
                "severity": "High",
                "details": "Bucket block public access settings are not fully enabled.",
            }
        )


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


def find_cloudtrail_not_logging(cloudtrail_client, findings):
    not_logging = []
    trails_resp = cloudtrail_client.describe_trails(includeShadowTrails=False)

    for t in trails_resp.get("trailList", []):
        name = t.get("Name") or t.get("TrailARN")
        try:
            status = (
                cloudtrail_client.get_trail_status(Name=t.get("Name"))
                if t.get("Name")
                else cloudtrail_client.get_trail_status(
                    TrailNameList=[t.get("TrailARN")]
                )
            )

            is_logging = status.get("IsLogging")
            if is_logging is False:
                not_logging.append(name)
        except ClientError:
            continue
        except Exception:
            continue
    for t in not_logging:
        findings.append(
            {
                "type": Vulnerability.cloudtrail_not_logging,
                "name": t,
                "severity": "High",
                "details": "CloudTrail exists but not logging.",
            }
        )


SCANS = {
    Vulnerability.public_s3_bucket: find_public_s3_buckets,
    Vulnerability.unencrypted_s3_bucket: find_unencrypted_s3_buckets,
    Vulnerability.s3_bucket_versioning_disabled: find_bucket_versioning_disabled,
    Vulnerability.s3_bucket_logging_disabled: find_bucket_logging_disabled,
    Vulnerability.s3_bucket_block_public_access_disabled: find_bucket_block_public_access_disabled,
    Vulnerability.iam_user_no_mfa: find_iam_users_without_mfa,
    Vulnerability.iam_unused_access_key: find_unused_iam_access_keys,
    Vulnerability.iam_inline_policy: find_inline_policies,
    Vulnerability.iam_root_access_key: find_root_access_keys_exist,
    Vulnerability.over_permissive_iam: find_over_permissive_iam_policies,
    Vulnerability.open_security_group_ingress: find_security_groups_open_ingress,
    Vulnerability.open_security_group_egress: find_security_groups_open_egress,
    Vulnerability.unused_security_group: find_unused_security_groups,
    Vulnerability.cloudtrail_not_logging: find_cloudtrail_not_logging,
    Vulnerability.cloudtrail_not_multi_region: find_cloudtrail_not_multi_region,
    Vulnerability.cloudtrail_no_log_file_validation: find_cloudtrail_no_log_file_validation,
    Vulnerability.cloudtrail_bucket_public: find_cloudtrail_bucket_public,
    Vulnerability.guardduty_disabled: find_guardduty_disabled,
    Vulnerability.vpc_flow_logs_disabled: find_vpc_flow_logs_disabled,
    Vulnerability.ebs_volume_unencrypted: find_ebs_unencrypted,
    Vulnerability.rds_instance_unencrypted: find_rds_unencrypted,
    Vulnerability.ssm_parameter_unencrypted: find_ssm_params_unencrypted,
    Vulnerability.lambda_overpermissive_role: find_lambda_overpermissive_roles,
    Vulnerability.apigateway_open_resource: find_api_gateway_open_resources,
}


def run_scans(selected_services, access_key, secret_key, region):
    findings = []
    for service in selected_services:
        scans = RESOURCES_MAP[service]
        client = Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        ).client(service)
        for scan in scans:
            try:
                SCANS[scan](client, findings)
            except Exception as e:
                # TODO: add error handling
                print(f"Error running scan {scan} for service {service}: {e}")
            
    return findings
