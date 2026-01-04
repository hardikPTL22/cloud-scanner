import json
from scanner.mitre_maps.lambda_mitre_map import LambdaVulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor
import logging

logger = logging.getLogger(__name__)


def fetch_functions(lambda_client):
    """Fetch all Lambda functions once for reuse across checks"""
    try:
        return lambda_client.list_functions().get("Functions", [])
    except Exception as e:
        logger.error(f"Error fetching functions: {e}")
        return []


@inject_clients(clients=["lambda", "iam"])
def find_lambda_overpermissive_roles(
    lambda_client, iam_client, findings, functions=None
):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_role(fn):
        role_arn = fn.get("Role")
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
                            return
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_role, functions)


@inject_clients(clients=["lambda"])
def find_lambda_functions_with_public_access(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_public_access(fn):
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
                    return
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_public_access, functions)


@inject_clients(clients=["lambda"])
def find_lambda_no_vpc(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_vpc(fn):
        if not fn.get("VpcConfig", {}).get("SubnetIds"):
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_no_vpc,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_vpc, functions)


@inject_clients(clients=["lambda"])
def find_lambda_no_dlq(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_dlq(fn):
        if not fn.get("DeadLetterConfig"):
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_no_dlq,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_dlq, functions)


@inject_clients(clients=["lambda"])
def find_lambda_no_xray(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_xray(fn):
        if fn.get("TracingConfig", {}).get("Mode") != "Active":
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_xray_disabled,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_xray, functions)


@inject_clients(clients=["lambda"])
def find_lambda_high_timeout(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_timeout(fn):
        if fn.get("Timeout", 0) > 300:
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_high_timeout,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_timeout, functions)


@inject_clients(clients=["lambda"])
def find_lambda_high_memory(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_memory(fn):
        if fn.get("MemorySize", 0) > 3008:
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_high_memory,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_memory, functions)


@inject_clients(clients=["lambda"])
def find_lambda_no_encryption(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_encryption(fn):
        if not fn.get("KmsKeyArn"):
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_no_encryption,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_encryption, functions)


@inject_clients(clients=["lambda"])
def find_lambda_no_logging(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_logging(fn):
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

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_logging, functions)


@inject_clients(clients=["lambda"])
def find_lambda_outdated_runtime(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    deprecated_runtimes = [
        "python2.7",
        "nodejs4.3",
        "nodejs6.10",
        "nodejs8.10",
        "dotnetcore1.0",
        "go1.x",
    ]

    def check_runtime(fn):
        runtime = fn.get("Runtime", "")
        if runtime in deprecated_runtimes:
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_outdated_runtime,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_runtime, functions)


@inject_clients(clients=["lambda"])
def find_lambda_reserved_concurrent_executions_not_set(
    lambda_client, findings, functions=None
):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_concurrency(fn):
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

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_concurrency, functions)


@inject_clients(clients=["lambda"])
def find_lambda_code_signing_not_enabled(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_code_signing(fn):
        if not fn.get("CodeSigningConfigArn"):
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_no_code_signing,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_code_signing, functions)


@inject_clients(clients=["lambda"])
def find_lambda_environment_variables_not_encrypted(
    lambda_client, findings, functions=None
):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_env_encryption(fn):
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

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_env_encryption, functions)


@inject_clients(clients=["lambda"])
def find_lambda_no_tags(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_tags(fn):
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
                pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_tags, functions)


@inject_clients(clients=["lambda"])
def find_lambda_no_description(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_description(fn):
        if not fn.get("Description"):
            findings.append(
                new_vulnerability(
                    LambdaVulnerability.lambda_no_description,
                    fn.get("FunctionName"),
                    "lambda",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_description, functions)


@inject_clients(clients=["lambda"])
def find_lambda_unrestricted_vpc_access(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_vpc_access(fn):
        vpc_config = fn.get("VpcConfig", {})
        security_groups = vpc_config.get("SecurityGroupIds", [])
        for sg_id in security_groups:
            try:
                if "0.0.0.0/0" in str(sg_id):
                    findings.append(
                        new_vulnerability(
                            LambdaVulnerability.lambda_unrestricted_vpc,
                            fn.get("FunctionName"),
                            "lambda",
                        )
                    )
                    return
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_vpc_access, functions)


@inject_clients(clients=["lambda"])
def find_lambda_ephemeral_storage_unencrypted(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_ephemeral_storage(fn):
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

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_ephemeral_storage, functions)


@inject_clients(clients=["lambda"])
def find_lambda_layers_not_vetted(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_layers(fn):
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
                        return
                except ClientError:
                    pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_layers, functions)


@inject_clients(clients=["lambda"])
def find_lambda_function_url_enabled(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_function_url(fn):
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

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_function_url, functions)


@inject_clients(clients=["lambda"])
def find_lambda_function_url_without_auth(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_url_auth(fn):
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

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_url_auth, functions)


@inject_clients(clients=["lambda"])
def find_lambda_function_url_cors_allow_all(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_cors(fn):
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

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_cors, functions)


@inject_clients(clients=["lambda"])
def find_lambda_image_scan_disabled(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_image_scan(fn):
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

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_image_scan, functions)


@inject_clients(clients=["lambda", "iam"])
def find_lambda_execution_role_trusts_all(
    lambda_client, iam_client, findings, functions=None
):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_role_trust(fn):
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
                        return
            except ClientError:
                pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_role_trust, functions)


@inject_clients(clients=["lambda"])
def find_lambda_no_resource_based_policy(lambda_client, findings, functions=None):
    if functions is None:
        functions = fetch_functions(lambda_client)

    def check_resource_policy(fn):
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

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_resource_policy, functions)
