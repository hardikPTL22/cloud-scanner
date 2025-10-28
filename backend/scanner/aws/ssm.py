from botocore.exceptions import ClientError
from scanner.mitre_map import Vulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients


@inject_clients(clients=["ssm"])
def find_ssm_params_unencrypted(ssm_client, findings):
    unencrypted = []
    paginator = ssm_client.get_paginator("describe_parameters")
    for page in paginator.paginate():
        for param in page.get("Parameters", []):
            name = param.get("Name")
            try:
                ssm_client.get_parameter(Name=name, WithDecryption=True)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ParameterNotFound":
                    continue
                elif e.response["Error"]["Code"] == "ValidationException":
                    unencrypted.append(name)
    for param in unencrypted:
        findings.append(
            new_vulnerability(
                Vulnerability.ssm_parameter_unencrypted,
                param,
            )
        )


@inject_clients(clients=["ssm"])
def find_ssm_unencrypted_parameters(ssm_client, findings):
    paginator = ssm_client.get_paginator("describe_parameters")
    for page in paginator.paginate():
        for param in page.get("Parameters", []):
            name = param.get("Name")
            try:
                ssm_client.get_parameter(Name=name, WithDecryption=True)
            except ClientError as e:
                if e.response["Error"]["Code"] in (
                    "ParameterNotFound",
                    "ValidationException",
                ):
                    findings.append(
                        {
                            "type": Vulnerability.ssm_parameter_unencrypted,
                            "name": name,
                            "severity": "High",
                            "details": "SSM Parameter is unencrypted or inaccessible.",
                        }
                    )
