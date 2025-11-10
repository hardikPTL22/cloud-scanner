from scanner.mitre_maps.apigateway_mitre_map import APIGatewayVulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients
from botocore.exceptions import ClientError
import json


@inject_clients(clients=["apigateway"])
def find_api_gateway_open_resources(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        resources = apigateway_client.get_resources(restApiId=api_id).get("items", [])
        for resource in resources:
            for method in resource.get("resourceMethods", {}).values():
                if method.get("authorizationType") in (None, "NONE"):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_open_resource,
                            f"{api_id}:{resource.get('id')}",
                            "apigateway",
                        )
                    )


@inject_clients(clients=["apigateway"])
def find_api_gateway_no_logging(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            stages = apigateway_client.get_stages(restApiId=api_id).get("item", [])
            for stage in stages:
                if not stage.get("accessLogSetting"):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_no_logging,
                            f"{api_id}:{stage.get('stageName')}",
                            "apigateway",
                        )
                    )
        except ClientError:
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_no_waf(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            stages = apigateway_client.get_stages(restApiId=api_id).get("item", [])
            for stage in stages:
                if not stage.get("webAclArn"):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_no_waf,
                            f"{api_id}:{stage.get('stageName')}",
                            "apigateway",
                        )
                    )
        except ClientError:
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_no_throttling(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            stages = apigateway_client.get_stages(restApiId=api_id).get("item", [])
            for stage in stages:
                settings = stage.get("methodSettings", {})
                has_throttling = False
                for setting in settings.values():
                    if setting.get("ThrottleSettings", {}).get("BurstLimit"):
                        has_throttling = True
                        break
                if not has_throttling:
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_no_throttling,
                            f"{api_id}:{stage.get('stageName')}",
                            "apigateway",
                        )
                    )
        except ClientError:
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_no_cache_encryption(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            stages = apigateway_client.get_stages(restApiId=api_id).get("item", [])
            for stage in stages:
                if not stage.get("cacheClusterEnabled", False):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_no_cache,
                            f"{api_id}:{stage.get('stageName')}",
                            "apigateway",
                        )
                    )
        except ClientError:
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_no_xray_tracing(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            stages = apigateway_client.get_stages(restApiId=api_id).get("item", [])
            for stage in stages:
                if not stage.get("tracingEnabled", False):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_no_xray,
                            f"{api_id}:{stage.get('stageName')}",
                            "apigateway",
                        )
                    )
        except ClientError:
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_unencrypted_transport(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            policy = apigateway_client.get_rest_api(restApiId=api_id).get("policy")
            if policy:
                policy_doc = json.loads(policy)
                for stmt in policy_doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow":
                        condition = stmt.get("Condition", {})
                        if not condition.get("Bool", {}).get("aws:SecureTransport"):
                            findings.append(
                                new_vulnerability(
                                    APIGatewayVulnerability.apigateway_no_ssl,
                                    api_id,
                                    "apigateway",
                                )
                            )
                            break
        except ClientError:
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_default_endpoint_enabled(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        if not api.get("endpointConfiguration", {}).get("types"):
            findings.append(
                new_vulnerability(
                    APIGatewayVulnerability.apigateway_no_api_endpoint,
                    api.get("id"),
                    "apigateway",
                )
            )


@inject_clients(clients=["apigateway"])
def find_api_gateway_resources_with_get_open(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        resources = apigateway_client.get_resources(restApiId=api_id).get("items", [])
        for resource in resources:
            resource_methods = resource.get("resourceMethods", {})
            if "GET" in resource_methods:
                method_info = resource_methods["GET"]
                if method_info.get("authorizationType") in (None, "NONE"):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_method_no_auth,
                            f"{api_id}:{resource.get('id')}",
                            "apigateway",
                        )
                    )


@inject_clients(clients=["apigateway"])
def find_api_gateway_no_access_logging(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            stages = apigateway_client.get_stages(restApiId=api_id).get("item", [])
            for stage in stages:
                if not stage.get("accessLogSetting", {}).get("destinationArn"):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_no_access_logs,
                            f"{api_id}:{stage.get('stageName')}",
                            "apigateway",
                        )
                    )
        except ClientError:
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_post_without_auth(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        resources = apigateway_client.get_resources(restApiId=api_id).get("items", [])
        for resource in resources:
            resource_methods = resource.get("resourceMethods", {})
            if "POST" in resource_methods:
                method_info = resource_methods["POST"]
                if method_info.get("authorizationType") in (None, "NONE"):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_open_resource,
                            f"{api_id}:POST:{resource.get('id')}",
                            "apigateway",
                        )
                    )


@inject_clients(clients=["apigateway"])
def find_api_gateway_put_without_auth(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        resources = apigateway_client.get_resources(restApiId=api_id).get("items", [])
        for resource in resources:
            resource_methods = resource.get("resourceMethods", {})
            if "PUT" in resource_methods:
                method_info = resource_methods["PUT"]
                if method_info.get("authorizationType") in (None, "NONE"):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_open_resource,
                            f"{api_id}:PUT:{resource.get('id')}",
                            "apigateway",
                        )
                    )


@inject_clients(clients=["apigateway"])
def find_api_gateway_delete_without_auth(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        resources = apigateway_client.get_resources(restApiId=api_id).get("items", [])
        for resource in resources:
            resource_methods = resource.get("resourceMethods", {})
            if "DELETE" in resource_methods:
                method_info = resource_methods["DELETE"]
                if method_info.get("authorizationType") in (None, "NONE"):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_open_resource,
                            f"{api_id}:DELETE:{resource.get('id')}",
                            "apigateway",
                        )
                    )


@inject_clients(clients=["apigateway"])
def find_api_gateway_patch_without_auth(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        resources = apigateway_client.get_resources(restApiId=api_id).get("items", [])
        for resource in resources:
            resource_methods = resource.get("resourceMethods", {})
            if "PATCH" in resource_methods:
                method_info = resource_methods["PATCH"]
                if method_info.get("authorizationType") in (None, "NONE"):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_open_resource,
                            f"{api_id}:PATCH:{resource.get('id')}",
                            "apigateway",
                        )
                    )


@inject_clients(clients=["apigateway"])
def find_api_gateway_cors_allow_all_origins(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        resources = apigateway_client.get_resources(restApiId=api_id).get("items", [])
        for resource in resources:
            try:
                cors = resource.get("corsConfiguration", {})
                if cors:
                    allowed_origins = cors.get("allowedOrigins", [])
                    if "*" in allowed_origins:
                        findings.append(
                            new_vulnerability(
                                APIGatewayVulnerability.apigateway_cors_all_origins,
                                f"{api_id}:{resource.get('id')}",
                                "apigateway",
                            )
                        )
            except (ClientError, KeyError):
                continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_no_authorization_type(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            authorizers = apigateway_client.get_authorizers(restApiId=api_id).get(
                "items", []
            )
            if not authorizers:
                findings.append(
                    new_vulnerability(
                        APIGatewayVulnerability.apigateway_no_auth,
                        api_id,
                        "apigateway",
                    )
                )
        except ClientError:
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_no_request_validation(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            validators = apigateway_client.get_request_validators(restApiId=api_id).get(
                "items", []
            )
            if not validators:
                findings.append(
                    new_vulnerability(
                        APIGatewayVulnerability.apigateway_no_request_validation,
                        api_id,
                        "apigateway",
                    )
                )
        except ClientError:
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_no_client_certificate(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            stages = apigateway_client.get_stages(restApiId=api_id).get("item", [])
            for stage in stages:
                if not stage.get("clientCertificateId"):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_no_domain_cert,
                            f"{api_id}:{stage.get('stageName')}",
                            "apigateway",
                        )
                    )
        except ClientError:
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_public_resource_policy(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            policy = apigateway_client.get_rest_api(restApiId=api_id).get("policy")
            if policy:
                policy_doc = json.loads(policy)
                for stmt in policy_doc.get("Statement", []):
                    if stmt.get("Effect") == "Allow" and stmt.get("Principal") == "*":
                        findings.append(
                            new_vulnerability(
                                APIGatewayVulnerability.apigateway_open_resource,
                                api_id,
                                "apigateway",
                            )
                        )
                        break
        except (ClientError, json.JSONDecodeError):
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_missing_stage_variables(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            stages = apigateway_client.get_stages(restApiId=api_id).get("item", [])
            for stage in stages:
                if not stage.get("variables"):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_no_tags,
                            f"{api_id}:{stage.get('stageName')}",
                            "apigateway",
                        )
                    )
        except ClientError:
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_no_request_tracing(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            stages = apigateway_client.get_stages(restApiId=api_id).get("item", [])
            for stage in stages:
                settings = stage.get("methodSettings", {}).get("*/*", {})
                if not settings.get("LoggingLevel"):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_no_logging,
                            f"{api_id}:{stage.get('stageName')}",
                            "apigateway",
                        )
                    )
        except ClientError:
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_no_binary_media_types(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        if not api.get("binaryMediaTypes"):
            findings.append(
                new_vulnerability(
                    APIGatewayVulnerability.apigateway_binary_media_unencrypted,
                    api_id,
                    "apigateway",
                )
            )


@inject_clients(clients=["apigateway"])
def find_api_gateway_no_api_key_required(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        resources = apigateway_client.get_resources(restApiId=api_id).get("items", [])
        for resource in resources:
            resource_methods = resource.get("resourceMethods", {})
            for method, details in resource_methods.items():
                if not details.get("apiKeyRequired", False):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_no_api_key,
                            f"{api_id}:{method}:{resource.get('id')}",
                            "apigateway",
                        )
                    )


@inject_clients(clients=["apigateway"])
def find_api_gateway_stage_no_encryption(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            stages = apigateway_client.get_stages(restApiId=api_id).get("item", [])
            for stage in stages:
                if not stage.get("dataTraceEnabled", False):
                    findings.append(
                        new_vulnerability(
                            APIGatewayVulnerability.apigateway_plaintext_logs,
                            f"{api_id}:{stage.get('stageName')}",
                            "apigateway",
                        )
                    )
        except ClientError:
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_no_execute_permissions(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        resources = apigateway_client.get_resources(restApiId=api_id).get("items", [])
        for resource in resources:
            resource_methods = resource.get("resourceMethods", {})
            for method in resource_methods.keys():
                try:
                    method_auth = apigateway_client.get_method(
                        restApiId=api_id,
                        resourceId=resource.get("id"),
                        httpMethod=method,
                    )
                    if not method_auth.get("authorizationScopes"):
                        findings.append(
                            new_vulnerability(
                                APIGatewayVulnerability.apigateway_method_no_auth,
                                f"{api_id}:{method}",
                                "apigateway",
                            )
                        )
                except ClientError:
                    continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_method_no_models(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            models = apigateway_client.get_models(restApiId=api_id).get("items", [])
            if not models:
                findings.append(
                    new_vulnerability(
                        APIGatewayVulnerability.apigateway_no_request_validation,
                        api_id,
                        "apigateway",
                    )
                )
        except ClientError:
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_invalid_certificate(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            domain_names = apigateway_client.get_domain_names().get("items", [])
            for domain in domain_names:
                cert_arn = domain.get("certificateArn")
                if cert_arn:
                    if not cert_arn.startswith("arn:aws:acm:"):
                        findings.append(
                            new_vulnerability(
                                APIGatewayVulnerability.apigateway_certificate_expired,
                                domain.get("domainName"),
                                "apigateway",
                            )
                        )
        except ClientError:
            continue


@inject_clients(clients=["apigateway"])
def find_api_gateway_execution_logs_disabled(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        api_id = api.get("id")
        try:
            account = apigateway_client.get_account()
            if not account.get("cloudwatchRoleArn"):
                findings.append(
                    new_vulnerability(
                        APIGatewayVulnerability.apigateway_no_execution_logs,
                        api_id,
                        "apigateway",
                    )
                )
        except ClientError:
            continue
