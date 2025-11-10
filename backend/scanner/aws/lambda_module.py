import json
from scanner.mitre_maps.lambda_mitre_map import LambdaVulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients
from botocore.exceptions import ClientError


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
                    pol = iam_client.get_policy(PolicyArn=policy_arn)
                    version_id = pol["Policy"]["DefaultVersionId"]
                    version = iam_client.get_policy_version(
                        PolicyArn=policy_arn, VersionId=version_id
                    )
                    doc = version["PolicyVersion"]["Document"]
                    for stmt in doc.get("Statement", []):
                        actions = stmt.get("Action")
                        resources = stmt.get("Resource")
                        if ("*" in str(actions)) or ("*" in str(resources)):
                            findings.append(
                                new_vulnerability(
                                    LambdaVulnerability.lambda_overpermissive_role,
                                    role_name,
                                    "lambda",
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
                            LambdaVulnerability.lambda_public_access,
                            fn_name,
                            "lambda",
                        )
                    )
                    break
        except ClientError:
            continue


@inject_clients(clients=["lambda"])
def find_lambda_no_vpc(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        if not fn.get("VpcConfig", {}).get("SubnetIds"):
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_no_vpc,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )


@inject_clients(clients=["lambda"])
def find_lambda_no_dlq(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        if not fn.get("DeadLetterConfig"):
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_no_dlq,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )


@inject_clients(clients=["lambda"])
def find_lambda_no_xray(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        if fn.get("TracingConfig", {}).get("Mode") != "Active":
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_xray_disabled,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )


@inject_clients(clients=["lambda"])
def find_lambda_high_timeout(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        if fn.get("Timeout", 0) > 300:
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_high_timeout,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )


@inject_clients(clients=["lambda"])
def find_lambda_high_memory(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        if fn.get("MemorySize", 0) > 3008:
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_high_memory,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )


@inject_clients(clients=["lambda"])
def find_lambda_no_encryption(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        if not fn.get("KmsKeyArn"):
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_no_encryption,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )


@inject_clients(clients=["lambda"])
def find_lambda_no_logging(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        fn_name = fn.get("FunctionName")
        try:
            config = lambda_client.get_function_logging_config(FunctionName=fn_name)
            if not config.get("LogGroup"):
                findings.append(
                    new_vulnerability(
                        LambdaVulnerability.lambda_no_logging, fn_name, "lambda"
                    )
                )
        except ClientError:
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_no_logging, fn_name, "lambda"
                )
            )


@inject_clients(clients=["lambda"])
def find_lambda_outdated_runtime(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    deprecated_runtimes = [
        "python2.7",
        "nodejs4.3",
        "nodejs6.10",
        "nodejs8.10",
        "dotnetcore1.0",
        "go1.x",
    ]
    for fn in functions:
        runtime = fn.get("Runtime", "")
        if runtime in deprecated_runtimes:
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_outdated_runtime,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )


@inject_clients(clients=["lambda"])
def find_lambda_reserved_concurrent_executions_not_set(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        fn_name = fn.get("FunctionName")
        try:
            config = lambda_client.get_function_concurrency(FunctionName=fn_name)
            if not config.get("ReservedConcurrentExecutions"):
                findings.append(
                    new_vulnerability(
                        LambdaVulnerability.lambda_no_reserved_concurrency,
                        fn_name,
                        "lambda",
                    )
                )
        except ClientError:
            pass


@inject_clients(clients=["lambda"])
def find_lambda_code_signing_not_enabled(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        if not fn.get("CodeSigningConfigArn"):
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_no_code_signing,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )


@inject_clients(clients=["lambda"])
def find_lambda_environment_variables_not_encrypted(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        env_vars = fn.get("Environment", {}).get("Variables", {})
        if env_vars:
            if not fn.get("KmsKeyArn"):
                findings.append(
                    new_vulnerability(
                        LambdaVulnerability.lambda_env_not_encrypted,
                        fn.get("FunctionName"),
                        "lambda",
                    )
                )


@inject_clients(clients=["lambda"])
def find_lambda_no_tags(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        fn_arn = fn.get("FunctionArn")
        if fn_arn:
            try:
                tags = lambda_client.list_tags(Resource=fn_arn)
                if not tags.get("Tags"):
                    findings.append(
                        new_vulnerability(
                            LambdaVulnerability.lambda_no_tags,
                            fn.get("FunctionName"),
                            "lambda",
                        )
                    )
            except ClientError:
                continue


@inject_clients(clients=["lambda"])
def find_lambda_no_description(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        if not fn.get("Description"):
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_no_description,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )


@inject_clients(clients=["lambda"])
def find_lambda_unrestricted_vpc_access(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        vpc_config = fn.get("VpcConfig", {})
        security_groups = vpc_config.get("SecurityGroupIds", [])
        for sg_id in security_groups:
            try:
                ec2 = lambda_client._client_config
                if "0.0.0.0/0" in str(sg_id):
                    findings.append(
                        new_vulnerability(
                            LambdaVulnerability.lambda_unrestricted_vpc,
                            fn.get("FunctionName"),
                            "lambda",
                        )
                    )
                    break
            except Exception:
                pass


@inject_clients(clients=["lambda"])
def find_lambda_ephemeral_storage_unencrypted(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        ephemeral_storage = fn.get("EphemeralStorage", {})
        if ephemeral_storage.get("Size", 0) > 0:
            if not fn.get("KmsKeyArn"):
                findings.append(
                    new_vulnerability(
                        LambdaVulnerability.lambda_ephemeral_unencrypted,
                        fn.get("FunctionName"),
                        "lambda",
                    )
                )


@inject_clients(clients=["lambda"])
def find_lambda_layers_not_vetted(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        layers = fn.get("Layers", [])
        for layer in layers:
            layer_arn = layer.get("Arn", "")
            if "arn:aws:lambda" in layer_arn:
                try:
                    layer_version = lambda_client.get_layer_version_by_arn(
                        Arn=layer_arn
                    )
                    if not layer_version.get("Description"):
                        findings.append(
                            new_vulnerability(
                                LambdaVulnerability.lambda_layer_not_vetted,
                                fn.get("FunctionName"),
                                "lambda",
                            )
                        )
                except ClientError:
                    pass


@inject_clients(clients=["lambda"])
def find_lambda_function_url_enabled(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        fn_name = fn.get("FunctionName")
        try:
            url_config = lambda_client.get_function_url_config(FunctionName=fn_name)
            if url_config.get("FunctionUrl"):
                findings.append(
                    new_vulnerability(
                        LambdaVulnerability.lambda_function_url_enabled,
                        fn_name,
                        "lambda",
                    )
                )
        except ClientError:
            pass


@inject_clients(clients=["lambda"])
def find_lambda_function_url_without_auth(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        fn_name = fn.get("FunctionName")
        try:
            url_config = lambda_client.get_function_url_config(FunctionName=fn_name)
            if url_config.get("AuthType") == "NONE":
                findings.append(
                    new_vulnerability(
                        LambdaVulnerability.lambda_function_url_no_auth,
                        fn_name,
                        "lambda",
                    )
                )
        except ClientError:
            pass


@inject_clients(clients=["lambda"])
def find_lambda_function_url_cors_allow_all(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        fn_name = fn.get("FunctionName")
        try:
            url_config = lambda_client.get_function_url_config(FunctionName=fn_name)
            cors = url_config.get("Cors", {})
            allowed_origins = cors.get("AllowOrigins", [])
            if "*" in allowed_origins:
                findings.append(
                    new_vulnerability(
                        LambdaVulnerability.lambda_function_url_cors_all,
                        fn_name,
                        "lambda",
                    )
                )
        except ClientError:
            pass


@inject_clients(clients=["lambda"])
def find_lambda_image_scan_disabled(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        package_type = fn.get("PackageType", "Zip")
        if package_type == "Image":
            code_sha = fn.get("CodeSha256", "")
            if not code_sha:
                findings.append(
                    new_vulnerability(
                        LambdaVulnerability.lambda_image_scan_disabled,
                        fn.get("FunctionName"),
                        "lambda",
                    )
                )


@inject_clients(clients=["lambda", "iam"])
def find_lambda_execution_role_trusts_all(lambda_client, iam_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        role_arn = fn.get("Role")
        if role_arn:
            role_name = role_arn.split("/")[-1]
            try:
                role = iam_client.get_role(RoleName=role_name)
                assume_policy = role.get("Role", {}).get("AssumeRolePolicyDocument", {})
                for stmt in assume_policy.get("Statement", []):
                    principal = stmt.get("Principal", {})
                    if principal == "*" or principal.get("Service") == "*":
                        findings.append(
                            new_vulnerability(
                                LambdaVulnerability.lambda_role_trusts_all,
                                role_name,
                                "lambda",
                            )
                        )
                        break
            except ClientError:
                continue


@inject_clients(clients=["lambda"])
def find_lambda_no_resource_based_policy(lambda_client, findings):
    functions = lambda_client.list_functions().get("Functions", [])
    for fn in functions:
        fn_name = fn.get("FunctionName")
        try:
            policy = lambda_client.get_policy(FunctionName=fn_name)
            if not policy.get("Policy"):
                findings.append(
                    new_vulnerability(
                        LambdaVulnerability.lambda_no_resource_policy,
                        fn_name,
                        "lambda",
                    )
                )
        except ClientError:
            pass
