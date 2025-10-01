from scanner.mitre_map import Vulnerability, RESOURCES_MAP
from boto3.session import Session

from scanner.aws.s3 import *
from scanner.aws.iam import *
from scanner.aws.ec2 import *
from scanner.aws.cloudtrail import *
from scanner.aws.rds import *
from scanner.aws.ssm import *
from scanner.aws.ec2_lambda import *
from scanner.aws.apigateway import *
from scanner.aws.guardduty import *

SCANS = {
    Vulnerability.public_s3_bucket: find_public_s3_buckets,
    Vulnerability.unencrypted_s3_bucket: find_unencrypted_s3_buckets,
    Vulnerability.s3_bucket_versioning_disabled: find_bucket_versioning_disabled,
    Vulnerability.s3_bucket_logging_disabled: find_bucket_logging_disabled,
    Vulnerability.s3_bucket_block_public_access_disabled: find_bucket_block_public_access_disabled,
    Vulnerability.iam_user_no_mfa: find_iam_users_without_mfa,
    Vulnerability.iam_unused_access_key: find_unused_iam_access_keys,
    Vulnerability.iam_inline_policy: find_inline_policies,
    Vulnerability.iam_root_access_key: find_root_access_keys_exist,
    Vulnerability.over_permissive_iam: find_over_permissive_iam_policies,
    Vulnerability.open_security_group_ingress: find_security_groups_open_ingress,
    Vulnerability.open_security_group_egress: find_security_groups_open_egress,
    Vulnerability.unused_security_group: find_unused_security_groups,
    Vulnerability.cloudtrail_not_logging: find_cloudtrail_not_logging,
    Vulnerability.cloudtrail_not_multi_region: find_cloudtrail_not_multi_region,
    Vulnerability.cloudtrail_no_log_file_validation: find_cloudtrail_no_log_file_validation,
    Vulnerability.cloudtrail_bucket_public: find_cloudtrail_bucket_public,
    Vulnerability.guardduty_disabled: find_guardduty_disabled,
    Vulnerability.vpc_flow_logs_disabled: find_vpc_flow_logs_disabled,
    Vulnerability.ebs_volume_unencrypted: find_ebs_unencrypted,
    Vulnerability.rds_instance_unencrypted: find_rds_unencrypted,
    Vulnerability.ssm_parameter_unencrypted: find_ssm_params_unencrypted,
    Vulnerability.lambda_overpermissive_role: find_lambda_overpermissive_roles,
    Vulnerability.apigateway_open_resource: find_api_gateway_open_resources,
}


def run_scans(selected_services, access_key, secret_key, region):
    findings = []
    for service in selected_services:
        scans = RESOURCES_MAP[service]
        client = Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        ).client(service)
        for scan in scans:
            try:
                SCANS[scan](client, findings)
            except Exception as e:
                print(f"Error running scan {scan} for service {service}: {e}")
    return findings
