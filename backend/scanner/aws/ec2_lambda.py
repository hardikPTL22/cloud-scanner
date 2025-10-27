import json
from scanner.mitre_map import Vulnerability, new_vulnerability
from scanner.aws.decorator import inject_clients


@inject_clients(clients=["lambda", "iam"])
def find_lambda_overpermissive_roles(lambda_client, iam_client, findings):
    funcs = lambda_client.list_functions().get("Functions", [])
    for f in funcs:
        role_arn = f.get("Role")
        if role_arn:
            role_name = role_arn.split("/")[-1]
            try:
                attached_policies = iam_client.list_attached_role_policies(
                    RoleName=role_name
                ).get("AttachedPolicies", [])
                for p in attached_policies:
                    policy_arn = p.get("PolicyArn")
                    # Get default policy version to inspect
                    pol = iam_client.get_policy(PolicyArn=policy_arn)
                    version_id = pol["Policy"]["DefaultVersionId"]
                    version = iam_client.get_policy_version(
                        PolicyArn=policy_arn, VersionId=version_id
                    )
                    doc = version["PolicyVersion"]["Document"]
                    # Check each statement for wildcards
                    for stmt in doc.get("Statement", []):
                        actions = stmt.get("Action")
                        resources = stmt.get("Resource")
                        if ("*" in str(actions)) or ("*" in str(resources)):
                            findings.append(
                                new_vulnerability(
                                    Vulnerability.lambda_overpermissive_role,
                                    role_name,
                                )
                            )
                            break
            except Exception:
                continue


@inject_clients(clients=["lambda"])
def find_lambda_functions_with_public_access(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        fn_name = fn.get("FunctionName")
        try:
            policy_resp = lambda_client.get_policy(FunctionName=fn_name)
            policy_doc = json.loads(policy_resp.get("Policy", "{}"))
            for stmt in policy_doc.get("Statement", []):
                principal = stmt.get("Principal")
                if principal == "*" or (
                    isinstance(principal, dict) and principal.get("AWS") == "*"
                ):
                    findings.append(
                        new_vulnerability(
                            Vulnerability.lambda_public_access,
                            fn_name,
                        )
                    )
                    break
        except lambda_client.exceptions.ResourceNotFoundException:
            continue
