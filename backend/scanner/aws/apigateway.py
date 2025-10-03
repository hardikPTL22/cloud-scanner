from scanner.mitre_map import Vulnerability, new_vulnerability


def find_api_gateway_open_resources(apigateway_client, findings):
    open_resources = []
    apis = apigateway_client.get_rest_apis()
    for api in apis.get("items", []):
        api_id = api.get("id")
        resources = apigateway_client.get_resources(restApiId=api_id)
        for res in resources.get("items", []):
            for method in res.get("resourceMethods", []):
                method_info = res["resourceMethods"][method]
                if (
                    "authorizationType" not in method_info
                    or method_info["authorizationType"] == "NONE"
                ):
                    open_resources.append(f"{api_id}:{res.get('id')}")
    for resource in open_resources:
        findings.append(
            new_vulnerability(
                Vulnerability.apigateway_open_resource,
                resource,
            )
        )


def find_apigateway_resources_without_auth(apigateway_client, findings):
    apis = apigateway_client.get_rest_apis().get("items", [])
    for api in apis:
        resources = apigateway_client.get_resources(restApiId=api.get("id")).get(
            "items", []
        )
        for resource in resources:
            resource_methods = resource.get("resourceMethods", {})
            for method in resource_methods.values():
                if method.get("authorizationType") in (None, "NONE"):
                    findings.append(
                        {
                            "type": Vulnerability.apigateway_open_resource,
                            "name": f"{api.get('id')}:{resource.get('id')}",
                            "severity": "High",
                            "details": "API Gateway resource allows open access without authorization.",
                        }
                    )
