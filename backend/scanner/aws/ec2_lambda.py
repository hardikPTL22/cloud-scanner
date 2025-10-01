from scanner.mitre_map import Vulnerability, new_vulnerability


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
                    if "*" in p.get("PolicyName", ""):
                        overpermissive.append(role_name)
            except Exception:
                continue
    for role in overpermissive:
        findings.append(
            new_vulnerability(
                Vulnerability.lambda_overpermissive_roles,
                role,
            )
        )
