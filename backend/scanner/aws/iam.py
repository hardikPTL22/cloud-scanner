from datetime import datetime, timedelta
from botocore.exceptions import ClientError
from scanner.mitre_maps.iam_mitre_map import IAMVulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients
import json


@inject_clients(clients=["iam"])
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
        findings.append(new_vulnerability(IAMVulnerability.iam_user_no_mfa, u, "iam"))


@inject_clients(clients=["iam"])
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
                    if last_used_date < datetime.now(
                        tz=last_used_date.tzinfo
                    ) - timedelta(days=90):
                        unused_keys.append(f"{user_name}:{key['AccessKeyId']}")
    for key in unused_keys:
        findings.append(
            new_vulnerability(IAMVulnerability.iam_unused_access_key, key, "iam")
        )


@inject_clients(clients=["iam"])
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
        findings.append(new_vulnerability(IAMVulnerability.iam_inline_policy, p, "iam"))


@inject_clients(clients=["iam"])
def find_root_access_keys_exist(iam_client, findings):
    try:
        root_keys = []
        keys = iam_client.list_access_keys(UserName="root")
        for key in keys.get("AccessKeyMetadata", []):
            root_keys.append(key["AccessKeyId"])
        for k in root_keys:
            findings.append(
                new_vulnerability(IAMVulnerability.iam_root_access_key, k, "iam")
            )
    except:
        pass


@inject_clients(clients=["iam"])
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
    for p in over_permissive_policies:
        findings.append(
            new_vulnerability(IAMVulnerability.over_permissive_iam, p, "iam")
        )


@inject_clients(clients=["iam"])
def find_iam_user_with_console_access(iam_client, findings):
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user["UserName"]
            try:
                iam_client.get_login_profile(UserName=user_name)
                findings.append(
                    new_vulnerability(
                        IAMVulnerability.iam_user_with_console_access,
                        user_name,
                        "iam",
                    )
                )
            except ClientError:
                continue


@inject_clients(clients=["iam"])
def find_iam_policies_with_wildcards(iam_client, findings):
    paginator = iam_client.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page.get("Policies", []):
            policy_arn = policy["Arn"]
            try:
                versions = iam_client.list_policy_versions(PolicyArn=policy_arn).get(
                    "Versions", []
                )
                default_version = next(
                    (v for v in versions if v.get("IsDefaultVersion")), None
                )
                if default_version:
                    document = iam_client.get_policy_version(
                        PolicyArn=policy_arn, VersionId=default_version["VersionId"]
                    )["PolicyVersion"]["Document"]
                    statements = document.get("Statement", [])
                    if not isinstance(statements, list):
                        statements = [statements]
                    for statement in statements:
                        actions = statement.get("Action", [])
                        if not isinstance(actions, list):
                            actions = [actions]
                        if "*" in actions:
                            findings.append(
                                new_vulnerability(
                                    IAMVulnerability.iam_policy_wildcard,
                                    policy["PolicyName"],
                                    "iam",
                                )
                            )
                            break
            except ClientError:
                continue


@inject_clients(clients=["iam"])
def find_iam_root_mfa_disabled(iam_client, findings):
    try:
        mfa_devices = iam_client.list_mfa_devices(UserName="root")
        if not mfa_devices.get("MFADevices"):
            findings.append(
                new_vulnerability(IAMVulnerability.iam_root_mfa_disabled, "root", "iam")
            )
    except ClientError:
        pass


@inject_clients(clients=["iam"])
def find_access_keys_rotated_more_than_90_days(iam_client, findings):
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user["UserName"]
            keys = iam_client.list_access_keys(UserName=user_name)
            for key in keys.get("AccessKeyMetadata", []):
                create_date = key.get("CreateDate")
                if create_date and datetime.now(
                    create_date.tzinfo
                ) - create_date > timedelta(days=90):
                    findings.append(
                        new_vulnerability(
                            IAMVulnerability.iam_old_access_key,
                            f"{user_name}:{key['AccessKeyId']}",
                            "iam",
                        )
                    )


@inject_clients(clients=["iam"])
def find_password_policy_not_enabled(iam_client, findings):
    try:
        policy = iam_client.get_account_password_policy()
        if not policy.get("PasswordPolicy"):
            findings.append(
                new_vulnerability(
                    IAMVulnerability.iam_no_password_policy, "account", "iam"
                )
            )
    except ClientError:
        findings.append(
            new_vulnerability(IAMVulnerability.iam_no_password_policy, "account", "iam")
        )


@inject_clients(clients=["iam"])
def find_password_policy_weak_requirements(iam_client, findings):
    try:
        policy = iam_client.get_account_password_policy().get("PasswordPolicy", {})
        if not policy.get("MinimumPasswordLength", 0) >= 14:
            findings.append(
                new_vulnerability(
                    IAMVulnerability.iam_weak_password_policy, "min_length", "iam"
                )
            )
        if not policy.get("RequireUppercaseCharacters"):
            findings.append(
                new_vulnerability(
                    IAMVulnerability.iam_weak_password_policy, "uppercase", "iam"
                )
            )
        if not policy.get("RequireNumbers"):
            findings.append(
                new_vulnerability(
                    IAMVulnerability.iam_weak_password_policy, "numbers", "iam"
                )
            )
        if not policy.get("RequireSymbols"):
            findings.append(
                new_vulnerability(
                    IAMVulnerability.iam_weak_password_policy, "symbols", "iam"
                )
            )
    except ClientError:
        pass


@inject_clients(clients=["iam"])
def find_users_with_direct_attached_policies(iam_client, findings):
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user["UserName"]
            attached = iam_client.list_attached_user_policies(UserName=user_name)
            if attached.get("AttachedPolicies"):
                findings.append(
                    new_vulnerability(
                        IAMVulnerability.iam_user_direct_policy, user_name, "iam"
                    )
                )


@inject_clients(clients=["iam"])
def find_roles_with_direct_attached_policies(iam_client, findings):
    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            role_name = role["RoleName"]
            attached = iam_client.list_attached_role_policies(RoleName=role_name)
            if attached.get("AttachedPolicies"):
                findings.append(
                    new_vulnerability(
                        IAMVulnerability.iam_role_direct_policy, role_name, "iam"
                    )
                )


@inject_clients(clients=["iam"])
def find_iam_groups_without_users(iam_client, findings):
    paginator = iam_client.get_paginator("list_groups")
    for page in paginator.paginate():
        for group in page.get("Groups", []):
            group_name = group["GroupName"]
            users = iam_client.get_group(GroupName=group_name)
            if not users.get("Users"):
                findings.append(
                    new_vulnerability(
                        IAMVulnerability.iam_empty_group, group_name, "iam"
                    )
                )


@inject_clients(clients=["iam"])
def find_iam_users_without_access_keys(iam_client, findings):
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user["UserName"]
            try:
                login_profile = iam_client.get_login_profile(UserName=user_name)
                if login_profile and not iam_client.list_access_keys(
                    UserName=user_name
                ).get("AccessKeyMetadata"):
                    findings.append(
                        new_vulnerability(
                            IAMVulnerability.iam_user_no_access_key, user_name, "iam"
                        )
                    )
            except ClientError:
                pass


@inject_clients(clients=["iam"])
def find_iam_users_inactive_for_90_days(iam_client, findings):
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user["UserName"]
            cred_report = iam_client.get_credential_report()
            if cred_report:
                pass


@inject_clients(clients=["iam"])
def find_iam_saml_providers(iam_client, findings):
    providers = iam_client.list_saml_providers()
    if not providers.get("SAMLProviderList"):
        findings.append(
            new_vulnerability(IAMVulnerability.iam_no_saml_provider, "account", "iam")
        )


@inject_clients(clients=["iam"])
def find_iam_role_trust_policy_allows_principal_star(iam_client, findings):
    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            role_name = role["RoleName"]
            assume_policy = role.get("AssumeRolePolicyDocument", {})
            if isinstance(assume_policy, str):
                assume_policy = json.loads(assume_policy)
            for stmt in assume_policy.get("Statement", []):
                principal = stmt.get("Principal", {})
                if principal == "*":
                    findings.append(
                        new_vulnerability(
                            IAMVulnerability.iam_role_trusts_all, role_name, "iam"
                        )
                    )
                    break


@inject_clients(clients=["iam"])
def find_iam_role_overpermissive(iam_client, findings):
    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            role_name = role["RoleName"]
            attached = iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached.get("AttachedPolicies", []):
                if "AdministratorAccess" in policy.get("PolicyName", ""):
                    findings.append(
                        new_vulnerability(
                            IAMVulnerability.iam_role_admin_access, role_name, "iam"
                        )
                    )


@inject_clients(clients=["iam"])
def find_iam_users_with_multiple_access_keys(iam_client, findings):
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user["UserName"]
            keys = iam_client.list_access_keys(UserName=user_name)
            if len(keys.get("AccessKeyMetadata", [])) > 1:
                findings.append(
                    new_vulnerability(
                        IAMVulnerability.iam_multiple_access_keys, user_name, "iam"
                    )
                )


@inject_clients(clients=["iam"])
def find_iam_credential_report_not_generated(iam_client, findings):
    try:
        report = iam_client.get_credential_report()
        if not report:
            findings.append(
                new_vulnerability(
                    IAMVulnerability.iam_no_credential_report, "account", "iam"
                )
            )
    except ClientError:
        findings.append(
            new_vulnerability(
                IAMVulnerability.iam_no_credential_report, "account", "iam"
            )
        )


@inject_clients(clients=["iam"])
def find_iam_no_ssh_keys(iam_client, findings):
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user["UserName"]
            try:
                keys = iam_client.list_ssh_public_keys(UserName=user_name)
                if not keys.get("SSHPublicKeys"):
                    findings.append(
                        new_vulnerability(
                            IAMVulnerability.iam_no_ssh_key, user_name, "iam"
                        )
                    )
            except ClientError:
                pass


@inject_clients(clients=["iam"])
def find_iam_user_no_tags(iam_client, findings):
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            user_name = user["UserName"]
            tags = iam_client.list_user_tags(UserName=user_name)
            if not tags.get("Tags"):
                findings.append(
                    new_vulnerability(
                        IAMVulnerability.iam_user_no_tags, user_name, "iam"
                    )
                )


@inject_clients(clients=["iam"])
def find_iam_role_no_tags(iam_client, findings):
    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page.get("Roles", []):
            role_name = role["RoleName"]
            tags = iam_client.list_role_tags(RoleName=role_name)
            if not tags.get("Tags"):
                findings.append(
                    new_vulnerability(
                        IAMVulnerability.iam_role_no_tags, role_name, "iam"
                    )
                )


@inject_clients(clients=["iam"])
def find_iam_policy_no_tags(iam_client, findings):
    paginator = iam_client.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page.get("Policies", []):
            policy_arn = policy["Arn"]
            try:
                tags = iam_client.list_policy_tags(PolicyArn=policy_arn)
                if not tags.get("Tags"):
                    findings.append(
                        new_vulnerability(
                            IAMVulnerability.iam_policy_no_tags,
                            policy["PolicyName"],
                            "iam",
                        )
                    )
            except ClientError:
                pass


@inject_clients(clients=["iam"])
def find_iam_unused_permissions(iam_client, findings):
    try:
        paginator = iam_client.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                policy_arn = policy["Arn"]
                access_level = iam_client.get_policy_summary(PolicyArn=policy_arn)
                if access_level.get("PolicyUsageCount", 0) == 0:
                    findings.append(
                        new_vulnerability(
                            IAMVulnerability.iam_unused_policy,
                            policy["PolicyName"],
                            "iam",
                        )
                    )
    except ClientError:
        pass
