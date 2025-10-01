from scanner.mitre_map import Vulnerability, new_vulnerability


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
            new_vulnerability(
                Vulnerability.iam_user_no_mfa,
                u,
            )
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
            new_vulnerability(
                Vulnerability.iam_unused_access_key,
                key,
            )
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
            new_vulnerability(
                Vulnerability.iam_inline_policy,
                p,
            )
        )


def find_root_access_keys_exist(iam_client, findings):
    try:
        root_keys = []
        keys = iam_client.list_access_keys(UserName="root")
        for key in keys.get("AccessKeyMetadata", []):
            root_keys.append(key["AccessKeyId"])
        for k in root_keys:
            findings.append(
                new_vulnerability(
                    Vulnerability.iam_root_access_key,
                    k,
                )
            )
    except:
        pass


def find_over_permissive_iam_policies(iam_client, findings):
    over_permissive_policies = []
    from botocore.exceptions import ClientError

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
            new_vulnerability(
                Vulnerability.over_permissive_iam,
                b,
            )
        )
