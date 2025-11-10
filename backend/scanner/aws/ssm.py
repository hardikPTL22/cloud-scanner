from botocore.exceptions import ClientError
from scanner.mitre_maps.ssm_mitre_map import SSMVulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients
import json


@inject_clients(clients=["ssm"])
def find_ssm_params_unencrypted(ssm_client, findings):
    unencrypted = []
    paginator = ssm_client.get_paginator("describe_parameters")
    for page in paginator.paginate():
        for param in page.get("Parameters", []):
            name = param.get("Name")
            param_type = param.get("Type", "")
            if param_type == "String" and not param.get("LastModifiedDate"):
                unencrypted.append(name)
    for param in unencrypted:
        findings.append(
            new_vulnerability(SSMVulnerability.ssm_parameter_unencrypted, param, "ssm")
        )


@inject_clients(clients=["ssm"])
def find_ssm_parameters_with_public_tier(ssm_client, findings):
    paginator = ssm_client.get_paginator("describe_parameters")
    for page in paginator.paginate():
        for param in page.get("Parameters", []):
            if param.get("Tier") == "Standard":
                findings.append(
                    new_vulnerability(
                        SSMVulnerability.ssm_param_public_tier, param.get("Name"), "ssm"
                    )
                )


@inject_clients(clients=["ssm"])
def find_ssm_documents_public(ssm_client, findings):
    paginator = ssm_client.get_paginator("list_documents")
    for page in paginator.paginate():
        for doc in page.get("DocumentIdentifiers", []):
            doc_name = doc.get("Name")
            try:
                doc_info = ssm_client.describe_document(Name=doc_name)
                if doc_info.get("Document", {}).get("DocumentFormat") == "JSON":
                    account_owners = doc_info.get("Document", {}).get(
                        "AccountOwners", []
                    )
                    if "*" in account_owners or not account_owners:
                        findings.append(
                            new_vulnerability(
                                SSMVulnerability.ssm_document_public, doc_name, "ssm"
                            )
                        )
            except ClientError:
                pass


@inject_clients(clients=["ssm"])
def find_ssm_no_session_logging(ssm_client, findings):
    try:
        response = ssm_client.get_document_description(Name="AWS-RunShellScript")
        if not response.get("Document", {}).get("Content"):
            findings.append(
                new_vulnerability(
                    SSMVulnerability.ssm_no_session_logging, "Session Manager", "ssm"
                )
            )
    except ClientError:
        findings.append(
            new_vulnerability(
                SSMVulnerability.ssm_no_session_logging, "Session Manager", "ssm"
            )
        )


@inject_clients(clients=["ssm"])
def find_ssm_parameters_without_tags(ssm_client, findings):
    paginator = ssm_client.get_paginator("describe_parameters")
    for page in paginator.paginate():
        for param in page.get("Parameters", []):
            name = param.get("Name")
            try:
                tags = ssm_client.list_tags_for_resource(
                    ResourceType="Parameter", ResourceId=name
                )
                if not tags.get("TagList"):
                    findings.append(
                        new_vulnerability(
                            SSMVulnerability.ssm_param_no_tags, name, "ssm"
                        )
                    )
            except ClientError:
                pass


@inject_clients(clients=["ssm"])
def find_ssm_documents_without_description(ssm_client, findings):
    paginator = ssm_client.get_paginator("list_documents")
    for page in paginator.paginate():
        for doc in page.get("DocumentIdentifiers", []):
            doc_name = doc.get("Name")
            if not doc.get("Description"):
                findings.append(
                    new_vulnerability(
                        SSMVulnerability.ssm_doc_no_description, doc_name, "ssm"
                    )
                )


@inject_clients(clients=["ssm"])
def find_ssm_patch_manager_not_enabled(ssm_client, findings):
    try:
        patch_baselines = ssm_client.describe_patch_baselines()
        if not patch_baselines.get("BaselineIdentities"):
            findings.append(
                new_vulnerability(
                    SSMVulnerability.ssm_patch_manager_disabled, "account", "ssm"
                )
            )
    except ClientError:
        findings.append(
            new_vulnerability(
                SSMVulnerability.ssm_patch_manager_disabled, "account", "ssm"
            )
        )


@inject_clients(clients=["ssm"])
def find_ssm_maintenance_windows_no_logging(ssm_client, findings):
    try:
        windows = ssm_client.describe_maintenance_windows()
        for window in windows.get("WindowIdentities", []):
            window_id = window.get("WindowId")
            window_info = ssm_client.describe_maintenance_window(WindowId=window_id)
            if not window_info.get("LoggingInfo"):
                findings.append(
                    new_vulnerability(
                        SSMVulnerability.ssm_maintenance_window_no_logging,
                        window_id,
                        "ssm",
                    )
                )
    except ClientError:
        pass


@inject_clients(clients=["ssm"])
def find_ssm_no_default_host_management_role(ssm_client, findings):
    try:
        setup = ssm_client.get_setup_configuration()
        if not setup.get("Status") == "Complete":
            findings.append(
                new_vulnerability(
                    SSMVulnerability.ssm_no_host_mgmt_role, "account", "ssm"
                )
            )
    except ClientError:
        findings.append(
            new_vulnerability(SSMVulnerability.ssm_no_host_mgmt_role, "account", "ssm")
        )


@inject_clients(clients=["ssm"])
def find_ssm_no_ops_center_configured(ssm_client, findings):
    try:
        ops_center = ssm_client.describe_ops_items()
        if not ops_center:
            findings.append(
                new_vulnerability(SSMVulnerability.ssm_no_ops_center, "account", "ssm")
            )
    except ClientError:
        pass


@inject_clients(clients=["ssm"])
def find_ssm_automation_no_logging(ssm_client, findings):
    try:
        automations = ssm_client.list_documents(DocumentType="Automation")
        for doc in automations.get("DocumentIdentifiers", []):
            doc_name = doc.get("Name")
            try:
                doc_info = ssm_client.get_document(Name=doc_name)
                if not doc_info.get("Document"):
                    findings.append(
                        new_vulnerability(
                            SSMVulnerability.ssm_automation_no_logging, doc_name, "ssm"
                        )
                    )
            except ClientError:
                pass
    except ClientError:
        pass


@inject_clients(clients=["ssm"])
def find_ssm_command_document_no_logging(ssm_client, findings):
    try:
        commands = ssm_client.list_command_invocations()
        for cmd in commands.get("CommandInvocations", []):
            if not cmd.get("DocumentName"):
                findings.append(
                    new_vulnerability(
                        SSMVulnerability.ssm_command_no_logging, "SSM Commands", "ssm"
                    )
                )
    except ClientError:
        pass


@inject_clients(clients=["ssm"])
def find_ssm_no_document_versioning(ssm_client, findings):
    paginator = ssm_client.get_paginator("list_documents")
    for page in paginator.paginate():
        for doc in page.get("DocumentIdentifiers", []):
            doc_name = doc.get("Name")
            if not doc.get("DocumentVersion"):
                findings.append(
                    new_vulnerability(
                        SSMVulnerability.ssm_doc_no_versioning, doc_name, "ssm"
                    )
                )


@inject_clients(clients=["ssm"])
def find_ssm_parameter_policy_too_permissive(ssm_client, findings):
    paginator = ssm_client.get_paginator("describe_parameters")
    for page in paginator.paginate():
        for param in page.get("Parameters", []):
            name = param.get("Name")
            try:
                attrs = ssm_client.get_parameter_attributes(Name=name)
                for attr in attrs.get("Attributes", []):
                    if attr.get("Name") == "Tier" and attr.get("Value") == "Standard":
                        findings.append(
                            new_vulnerability(
                                SSMVulnerability.ssm_param_permissive, name, "ssm"
                            )
                        )
            except ClientError:
                pass


@inject_clients(clients=["ssm"])
def find_ssm_parameters_unchanged_90_days(ssm_client, findings):
    import datetime

    paginator = ssm_client.get_paginator("describe_parameters")
    for page in paginator.paginate():
        for param in page.get("Parameters", []):
            last_modified = param.get("LastModifiedDate")
            if last_modified:
                age = (datetime.datetime.now(last_modified.tzinfo) - last_modified).days
                if age > 90:
                    findings.append(
                        new_vulnerability(
                            SSMVulnerability.ssm_param_stale,
                            param.get("Name"),
                            "ssm",
                        )
                    )


@inject_clients(clients=["ssm"])
def find_ssm_documents_unchanged_90_days(ssm_client, findings):
    import datetime

    paginator = ssm_client.get_paginator("list_documents")
    for page in paginator.paginate():
        for doc in page.get("DocumentIdentifiers", []):
            created_date = doc.get("CreatedDate")
            if created_date:
                age = (datetime.datetime.now(created_date.tzinfo) - created_date).days
                if age > 90:
                    findings.append(
                        new_vulnerability(
                            SSMVulnerability.ssm_doc_stale, doc.get("Name"), "ssm"
                        )
                    )


@inject_clients(clients=["ssm"])
def find_ssm_no_inventory_enabled(ssm_client, findings):
    try:
        inventory = ssm_client.list_inventory_entries()
        if not inventory.get("Entries"):
            findings.append(
                new_vulnerability(SSMVulnerability.ssm_no_inventory, "account", "ssm")
            )
    except ClientError:
        findings.append(
            new_vulnerability(SSMVulnerability.ssm_no_inventory, "account", "ssm")
        )


@inject_clients(clients=["ssm"])
def find_ssm_compliance_not_enabled(ssm_client, findings):
    try:
        compliance = ssm_client.list_compliance_items()
        if not compliance.get("ComplianceItems"):
            findings.append(
                new_vulnerability(
                    SSMVulnerability.ssm_compliance_disabled, "account", "ssm"
                )
            )
    except ClientError:
        pass


@inject_clients(clients=["ssm"])
def find_ssm_state_manager_not_configured(ssm_client, findings):
    try:
        associations = ssm_client.list_associations()
        if not associations.get("Associations"):
            findings.append(
                new_vulnerability(
                    SSMVulnerability.ssm_state_manager_disabled, "account", "ssm"
                )
            )
    except ClientError:
        pass


@inject_clients(clients=["ssm"])
def find_ssm_parameters_exceeding_limit(ssm_client, findings):
    paginator = ssm_client.get_paginator("describe_parameters")
    param_count = 0
    for page in paginator.paginate():
        param_count += len(page.get("Parameters", []))
    if param_count > 10000:
        findings.append(
            new_vulnerability(
                SSMVulnerability.ssm_param_limit_high,
                f"Parameters: {param_count}",
                "ssm",
            )
        )


@inject_clients(clients=["ssm"])
def find_ssm_no_kms_encryption(ssm_client, findings):
    paginator = ssm_client.get_paginator("describe_parameters")
    for page in paginator.paginate():
        for param in page.get("Parameters", []):
            if param.get("Type") == "SecureString":
                key_id = param.get("KeyId")
                if not key_id or key_id == "alias/aws/ssm":
                    findings.append(
                        new_vulnerability(
                            SSMVulnerability.ssm_default_kms_key,
                            param.get("Name"),
                            "ssm",
                        )
                    )


@inject_clients(clients=["ssm"])
def find_ssm_document_contains_hardcoded_credentials(ssm_client, findings):
    paginator = ssm_client.get_paginator("list_documents")
    sensitive_keywords = ["password", "secret", "key", "token", "credential"]
    for page in paginator.paginate():
        for doc in page.get("DocumentIdentifiers", []):
            doc_name = doc.get("Name")
            try:
                doc_content = ssm_client.get_document(Name=doc_name)
                content = doc_content.get("Content", "")
                for keyword in sensitive_keywords:
                    if keyword.lower() in content.lower():
                        findings.append(
                            new_vulnerability(
                                SSMVulnerability.ssm_doc_hardcoded_creds,
                                doc_name,
                                "ssm",
                            )
                        )
                        break
            except ClientError:
                pass


@inject_clients(clients=["ssm"])
def find_ssm_parameter_policy_default(ssm_client, findings):
    paginator = ssm_client.get_paginator("describe_parameters")
    for page in paginator.paginate():
        for param in page.get("Parameters", []):
            name = param.get("Name")
            try:
                policy = ssm_client.get_resource_policy(
                    ResourceArn=f"arn:aws:ssm:*:*:parameter{name}"
                )
                if not policy:
                    findings.append(
                        new_vulnerability(
                            SSMVulnerability.ssm_param_no_policy, name, "ssm"
                        )
                    )
            except ClientError:
                pass


@inject_clients(clients=["ssm"])
def find_ssm_automation_document_no_approval(ssm_client, findings):
    try:
        automations = ssm_client.list_documents(DocumentType="Automation")
        for doc in automations.get("DocumentIdentifiers", []):
            doc_name = doc.get("Name")
            try:
                doc_info = ssm_client.get_document(Name=doc_name)
                content = doc_info.get("Content", "{}")
                doc_dict = json.loads(content) if isinstance(content, str) else content
                if not doc_dict.get("assumeRole"):
                    findings.append(
                        new_vulnerability(
                            SSMVulnerability.ssm_automation_no_role, doc_name, "ssm"
                        )
                    )
            except ClientError:
                pass
    except ClientError:
        pass


@inject_clients(clients=["ssm"])
def find_ssm_no_change_calendar(ssm_client, findings):
    try:
        calendars = ssm_client.list_change_calendars()
        if not calendars.get("ChangeCalendars"):
            findings.append(
                new_vulnerability(
                    SSMVulnerability.ssm_no_change_calendar, "account", "ssm"
                )
            )
    except ClientError:
        pass
