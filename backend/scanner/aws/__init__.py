from boto3.session import Session
import logging

from scanner.aws.s3 import *
from scanner.aws.ec2 import *
from scanner.aws.iam import *
from scanner.aws.ebs import *
from scanner.aws.cloudtrail import *
from scanner.aws.rds import *
from scanner.aws.ssm import *
from scanner.aws.lambda_module import *
from scanner.aws.apigateway import *
from scanner.aws.guardduty import *

logger = logging.getLogger(__name__)

SCANS = {
    "s3": {
        "public_s3_bucket": find_public_s3_buckets,
        "unencrypted_s3_bucket": find_unencrypted_s3_buckets,
        "s3_bucket_versioning_disabled": find_bucket_versioning_disabled,
        "s3_bucket_logging_disabled": find_bucket_logging_disabled,
        "s3_bucket_block_public_access_disabled": find_bucket_block_public_access_disabled,
        "s3_mfa_delete_disabled": find_bucket_mfa_delete_disabled,
        "s3_no_lifecycle": find_bucket_no_lifecycle_policy,
        "s3_cors_all_origins": find_bucket_no_cors_policy,
        "s3_bucket_no_tags": find_bucket_without_tags,
        "s3_website_enabled": find_bucket_website_enabled,
        "s3_no_object_lock": find_bucket_no_object_lock,
        "s3_requester_pays": find_bucket_requester_pays_enabled,
        "s3_acl_public": find_bucket_acl_public,
        "s3_unencrypted_upload_allowed": find_bucket_policy_allows_unencrypted_upload,
        "s3_no_replication": find_bucket_no_replication,
        "s3_no_server_access_logging": find_bucket_no_server_access_logging,
        "s3_no_cloudtrail_logging": find_bucket_no_cloudtrail_logging,
        "s3_no_intelligent_tiering": find_bucket_no_intelligent_tiering,
        "s3_object_lock_no_retention": find_bucket_object_lock_retention_default,
        "s3_public_read_access": find_bucket_public_read_access,
        "s3_public_write_access": find_bucket_public_write_access,
        "s3_non_standard_encryption": find_bucket_default_encryption_not_aes256,
        "s3_bucket_key_disabled": find_bucket_no_bucket_key_enabled,
        "s3_user_versioning_disabled": find_bucket_no_user_versioning,
        "s3_unrestricted_policy": find_bucket_unrestricted_policy,
        "s3_no_kms_encryption": find_bucket_no_kms_encryption,
        "s3_no_access_point": find_bucket_no_access_point,
    },
    "iam": {
        "iam_user_no_mfa": find_iam_users_without_mfa,
        "iam_unused_access_key": find_unused_iam_access_keys,
        "iam_inline_policy": find_inline_policies,
        "iam_root_access_key": find_root_access_keys_exist,
        "over_permissive_iam": find_over_permissive_iam_policies,
        "iam_user_with_console_access": find_iam_user_with_console_access,
        "iam_policy_wildcard": find_iam_policies_with_wildcards,
        "iam_root_mfa_disabled": find_iam_root_mfa_disabled,
        "iam_old_access_key": find_access_keys_rotated_more_than_90_days,
        "iam_no_password_policy": find_password_policy_not_enabled,
        "iam_weak_password_policy": find_password_policy_weak_requirements,
        "iam_user_direct_policy": find_users_with_direct_attached_policies,
        "iam_role_direct_policy": find_roles_with_direct_attached_policies,
        "iam_empty_group": find_iam_groups_without_users,
        "iam_user_no_access_key": find_iam_users_without_access_keys,
        "iam_no_saml_provider": find_iam_saml_providers,
        "iam_role_trusts_all": find_iam_role_trust_policy_allows_principal_star,
        "iam_role_admin_access": find_iam_role_overpermissive,
        "iam_multiple_access_keys": find_iam_users_with_multiple_access_keys,
        "iam_no_credential_report": find_iam_credential_report_not_generated,
        "iam_no_ssh_key": find_iam_no_ssh_keys,
        "iam_user_no_tags": find_iam_user_no_tags,
        "iam_role_no_tags": find_iam_role_no_tags,
        "iam_policy_no_tags": find_iam_policy_no_tags,
        "iam_unused_policy": find_iam_unused_permissions,
    },
    "ec2": {
        "open_security_group_ingress": find_security_groups_open_ingress,
        "open_security_group_egress": find_security_groups_open_egress,
        "unused_security_group": find_unused_security_groups,
        "ec2_instance_public_ip": find_ec2_instance_public_ip,
        "vpc_flow_logs_disabled": find_vpc_flow_logs_disabled,
        "sg_ssh_open": find_security_groups_with_ssh_open,
        "sg_rdp_open": find_security_groups_with_rdp_open,
        "default_vpc_in_use": find_default_vpc_in_use,
        "default_sg_in_use": find_default_security_group_in_use,
        "detailed_monitoring_disabled": find_instances_without_monitoring,
        "ebs_optimization_disabled": find_ebs_optimization_disabled,
        "termination_protection_disabled": find_termination_protection_disabled,
        "unattached_eip": find_unattached_elastic_ips,
        "instance_public_eni": find_instances_with_public_eni,
        "no_snapshots": find_volumes_without_snapshots,
        "unencrypted_snapshot": find_unencrypted_snapshots,
        "public_snapshot": find_public_snapshots,
        "public_ami": find_public_amis,
        "nacl_allow_all": find_network_acls_allowing_all_traffic,
        "route_table_open": find_route_tables_with_overly_permissive_routes,
        "nat_gateway_no_eip": find_nat_gateways_without_eip,
        "vpn_not_encrypted": find_vpn_connections_not_encrypted,
        "vpn_not_authenticated": find_vpn_connections_not_authenticated,
        "ebs_delete_on_termination_disabled": find_instances_without_ebs_delete_on_termination,
        "instance_no_iam_profile": find_instances_without_iam_instance_profile,
        "source_dest_check_enabled": find_instances_without_source_destination_check,
        "key_pair_no_tags": find_key_pairs_without_tags,
        "sg_no_description": find_security_groups_without_description,
        "instance_default_tenancy": find_instances_with_default_tenancy,
        "instance_shutdown_behavior": find_instances_without_shutdown_behavior_stop,
    },
    "cloudtrail": {
        "cloudtrail_not_logging": find_cloudtrail_not_logging,
        "cloudtrail_not_multi_region": find_cloudtrail_not_multi_region,
        "cloudtrail_no_log_file_validation": find_cloudtrail_no_log_file_validation,
        "cloudtrail_bucket_public": find_cloudtrail_bucket_public,
        "cloudtrail_bucket_encryption_disabled": find_cloudtrail_encryption_disabled,
        "cloudtrail_no_kms": find_cloudtrail_no_kms_encryption,
        "cloudtrail_not_recording": find_cloudtrail_not_recording,
        "cloudtrail_no_org_trail": find_cloudtrail_no_organization_trail,
        "cloudtrail_no_event_selectors": find_cloudtrail_event_selectors_not_configured,
        "cloudtrail_mgmt_events_disabled": find_cloudtrail_management_events_disabled,
        "cloudtrail_no_data_events": find_cloudtrail_data_events_disabled,
        "cloudtrail_no_cloudwatch": find_cloudtrail_no_cloudwatch_logs,
        "cloudtrail_bucket_versioning_disabled": find_cloudtrail_bucket_versioning_disabled,
        "cloudtrail_bucket_no_mfa_delete": find_cloudtrail_bucket_no_mfa_delete,
        "cloudtrail_bucket_no_logging": find_cloudtrail_bucket_no_access_logging,
        "cloudtrail_shadow_trails": find_cloudtrail_shadow_trails,
        "cloudtrail_no_sns": find_cloudtrail_no_sns_notification,
        "cloudtrail_bucket_public_policy": find_cloudtrail_bucket_public_policy,
        "cloudtrail_no_log_digest": find_cloudtrail_enable_log_file_digest,
        "cloudtrail_no_tags": find_cloudtrail_no_tags,
        "cloudtrail_too_many_trails": find_cloudtrail_too_many_trails,
        "cloudtrail_no_read_events": find_cloudtrail_no_read_events,
        "cloudtrail_bucket_no_lifecycle": find_cloudtrail_bucket_no_lifecycle,
        "cloudtrail_no_advanced_selectors": find_cloudtrail_no_advanced_event_selectors,
        "cloudtrail_invalid_name": find_cloudtrail_name_invalid,
    },
    "guardduty": {
        "guardduty_disabled": find_guardduty_disabled,
        "guardduty_finding_freq_not_optimal": find_guardduty_finding_publishing_frequency_not_optimal,
        "guardduty_no_s3_protection": find_guardduty_no_s3_protection,
        "guardduty_no_eks_protection": find_guardduty_no_eks_protection,
        "guardduty_no_lambda_protection": find_guardduty_no_lambda_protection,
        "guardduty_no_rds_protection": find_guardduty_no_rds_protection,
        "guardduty_no_cloudwatch_logs": find_guardduty_no_cloudwatch_logs_export,
        "guardduty_no_threat_intel": find_guardduty_no_threat_intel_feed,
        "guardduty_findings_not_archived": find_guardduty_findings_not_archived,
        "guardduty_no_ip_set": find_guardduty_no_ip_set,
        "guardduty_no_member_accounts": find_guardduty_no_member_accounts,
        "guardduty_high_severity_findings": find_guardduty_findings_high_severity_not_addressed,
        "guardduty_detector_no_tags": find_guardduty_detectors_no_tagging,
        "guardduty_no_member_invitations": find_guardduty_no_member_account_invitations,
        "guardduty_no_master_account": find_guardduty_master_account_not_enabled,
        "guardduty_no_vpc_flow_logs": find_guardduty_no_vpc_flow_logs,
        "guardduty_no_cloudtrail": find_guardduty_no_cloudtrail_logs,
        "guardduty_no_findings_export": find_guardduty_findings_export_not_configured,
        "guardduty_no_sns_notification": find_guardduty_detector_no_sns_notification,
        "guardduty_orphaned_detector": find_guardduty_orphaned_detectors,
        "guardduty_no_custom_ip_set": find_guardduty_no_custom_ip_set,
        "guardduty_no_custom_threat_intel": find_guardduty_no_custom_threat_intel_set,
        "guardduty_malware_protection_disabled": find_guardduty_malware_protection_disabled,
        "guardduty_runtime_monitoring_disabled": find_guardduty_runtime_monitoring_disabled,
    },
    "ebs": {
        "ebs_volume_unencrypted": find_ebs_volumes_unencrypted,
        "ebs_no_snapshots": find_ebs_volumes_no_snapshots,
        "ebs_snapshot_public": find_ebs_snapshots_public,
        "ebs_snapshot_unencrypted": find_ebs_snapshots_unencrypted,
        "ebs_no_tags": find_ebs_volumes_no_tags,
        "ebs_default_kms_key": find_ebs_volumes_no_kms_encryption,
        "ebs_snapshot_shared": find_ebs_snapshots_shared_with_accounts,
        "ebs_no_delete_on_termination": find_ebs_volumes_no_delete_on_termination,
        "ebs_unattached": find_ebs_volumes_not_attached,
        "ebs_old_snapshots": find_ebs_volumes_old_snapshots,
        "ebs_snapshot_no_description": find_ebs_snapshots_no_description,
        "ebs_no_description": find_ebs_volumes_no_description,
        "ebs_io_unencrypted": find_ebs_io1_io2_volumes_unencrypted,
        "ebs_gp2_large": find_ebs_gp2_volumes_large,
        "ebs_snapshot_copy_encrypted": find_ebs_snapshots_no_copy_encryption,
        "ebs_iops_not_optimized": find_ebs_volumes_iops_not_optimized,
        "ebs_snapshots_too_many": find_ebs_snapshots_too_many,
        "ebs_volume_excessive": find_ebs_volumes_excessive_size,
        "ebs_copy_no_encryption": find_ebs_snapshot_copy_no_encryption,
        "ebs_no_backup_plan": find_ebs_volumes_no_backup_plan,
        "ebs_snapshot_copy_unencrypted": find_ebs_snapshots_unencrypted_copies,
        "ebs_no_fast_restore": find_ebs_volumes_fast_snapshot_restore,
        "ebs_old_volume_type": find_ebs_volumes_st1_sc1_old_generation,
    },
    "rds": {
        "rds_instance_unencrypted": find_rds_unencrypted,
        "rds_instance_public_access": find_rds_public_access_enabled,
        "rds_no_backup": find_rds_no_backup,
        "rds_low_backup_retention": find_rds_backup_retention_low,
        "rds_no_multi_az": find_rds_no_multi_az,
        "rds_no_enhanced_monitoring": find_rds_no_enhanced_monitoring,
        "rds_no_deletion_protection": find_rds_no_deletion_protection,
        "rds_no_copy_snapshots": find_rds_no_copy_snapshots_to_region,
        "rds_auto_minor_upgrade": find_rds_minor_version_upgrade_auto_enabled,
        "rds_no_performance_insights": find_rds_no_performance_insights,
        "rds_iam_auth_disabled": find_rds_iam_authentication_disabled,
        "rds_default_port": find_rds_default_port_exposed,
        "rds_default_param_group": find_rds_database_parameter_group_default,
        "rds_cluster_unencrypted": find_rds_cluster_no_encryption,
        "rds_cluster_public": find_rds_cluster_public_access,
        "rds_no_automated_backup": find_rds_no_automated_backups,
        "rds_snapshot_public": find_rds_snapshots_public,
        "rds_no_tags": find_rds_no_tags,
        "rds_storage_not_encrypted": find_rds_storage_not_encrypted_at_rest,
        "rds_no_option_group": find_rds_no_option_group,
        "rds_no_vpc": find_rds_instance_no_vpc,
        "rds_no_cloudtrail": find_rds_no_cloudtrail_logging,
        "rds_cluster_low_retention": find_rds_cluster_backup_retention_low,
        "rds_default_sg": find_rds_instance_with_default_security_group,
        "rds_no_kms_key": find_rds_no_kms_key,
        "rds_unsupported_engine": find_rds_engine_unsupported,
        "rds_no_audit_logs": find_rds_no_audit_logs,
    },
    "ssm": {
        "ssm_parameter_unencrypted": find_ssm_params_unencrypted,
        "ssm_param_public_tier": find_ssm_parameters_with_public_tier,
        "ssm_document_public": find_ssm_documents_public,
        "ssm_no_session_logging": find_ssm_no_session_logging,
        "ssm_param_no_tags": find_ssm_parameters_without_tags,
        "ssm_doc_no_description": find_ssm_documents_without_description,
        "ssm_patch_manager_disabled": find_ssm_patch_manager_not_enabled,
        "ssm_maintenance_window_no_logging": find_ssm_maintenance_windows_no_logging,
        "ssm_no_host_mgmt_role": find_ssm_no_default_host_management_role,
        "ssm_no_ops_center": find_ssm_no_ops_center_configured,
        "ssm_automation_no_logging": find_ssm_automation_no_logging,
        "ssm_command_no_logging": find_ssm_command_document_no_logging,
        "ssm_doc_no_versioning": find_ssm_no_document_versioning,
        "ssm_param_permissive": find_ssm_parameter_policy_too_permissive,
        "ssm_param_stale": find_ssm_parameters_unchanged_90_days,
        "ssm_doc_stale": find_ssm_documents_unchanged_90_days,
        "ssm_no_inventory": find_ssm_no_inventory_enabled,
        "ssm_compliance_disabled": find_ssm_compliance_not_enabled,
        "ssm_state_manager_disabled": find_ssm_state_manager_not_configured,
        "ssm_param_limit_high": find_ssm_parameters_exceeding_limit,
        "ssm_default_kms_key": find_ssm_no_kms_encryption,
        "ssm_doc_hardcoded_creds": find_ssm_document_contains_hardcoded_credentials,
        "ssm_param_no_policy": find_ssm_parameter_policy_default,
        "ssm_automation_no_role": find_ssm_automation_document_no_approval,
        "ssm_no_change_calendar": find_ssm_no_change_calendar,
    },
    "lambda": {
        "lambda_overpermissive_role": find_lambda_overpermissive_roles,
        "lambda_public_access": find_lambda_functions_with_public_access,
        "lambda_no_vpc": find_lambda_no_vpc,
        "lambda_no_dlq": find_lambda_no_dlq,
        "lambda_xray_disabled": find_lambda_no_xray,
        "lambda_high_timeout": find_lambda_high_timeout,
        "lambda_high_memory": find_lambda_high_memory,
        "lambda_no_encryption": find_lambda_no_encryption,
        "lambda_no_logging": find_lambda_no_logging,
        "lambda_outdated_runtime": find_lambda_outdated_runtime,
        "lambda_no_reserved_concurrency": find_lambda_reserved_concurrent_executions_not_set,
        "lambda_no_code_signing": find_lambda_code_signing_not_enabled,
        "lambda_env_not_encrypted": find_lambda_environment_variables_not_encrypted,
        "lambda_no_tags": find_lambda_no_tags,
        "lambda_no_description": find_lambda_no_description,
        "lambda_unrestricted_vpc": find_lambda_unrestricted_vpc_access,
        "lambda_ephemeral_unencrypted": find_lambda_ephemeral_storage_unencrypted,
        "lambda_layer_not_vetted": find_lambda_layers_not_vetted,
        "lambda_function_url_enabled": find_lambda_function_url_enabled,
        "lambda_function_url_no_auth": find_lambda_function_url_without_auth,
        "lambda_function_url_cors_all": find_lambda_function_url_cors_allow_all,
        "lambda_image_scan_disabled": find_lambda_image_scan_disabled,
        "lambda_role_trusts_all": find_lambda_execution_role_trusts_all,
        "lambda_no_resource_policy": find_lambda_no_resource_based_policy,
    },
    "apigateway": {
        "apigateway_open_resource": find_api_gateway_open_resources,
        "apigateway_no_logging": find_api_gateway_no_logging,
        "apigateway_no_waf": find_api_gateway_no_waf,
        "apigateway_no_throttling": find_api_gateway_no_throttling,
        "apigateway_no_cache": find_api_gateway_no_cache_encryption,
        "apigateway_no_xray": find_api_gateway_no_xray_tracing,
        "apigateway_no_ssl": find_api_gateway_unencrypted_transport,
        "apigateway_no_api_endpoint": find_api_gateway_default_endpoint_enabled,
        "apigateway_method_no_auth": find_api_gateway_resources_with_get_open,
        "apigateway_no_access_logs": find_api_gateway_no_access_logging,
        "apigateway_no_auth": find_api_gateway_post_without_auth,
        "apigateway_no_request_validation": find_api_gateway_no_request_validation,
        "apigateway_no_domain_cert": find_api_gateway_no_client_certificate,
        "apigateway_certificate_expired": find_api_gateway_invalid_certificate,
        "apigateway_no_execution_logs": find_api_gateway_execution_logs_disabled,
        "apigateway_cors_all_origins": find_api_gateway_cors_allow_all_origins,
        "apigateway_binary_media_unencrypted": find_api_gateway_no_binary_media_types,
        "apigateway_no_api_key": find_api_gateway_no_api_key_required,
        "apigateway_plaintext_logs": find_api_gateway_stage_no_encryption,
    },
}


def run_scans(selected_services, access_key, secret_key, region):

    findings = []
    session = Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=region,
    )

    total_scans = sum(len(v) for v in selected_services.values())
    logger.info(
        f"Starting {total_scans} security scans across {len(selected_services)} services"
    )

    for service, scan_list in selected_services.items():
        if service not in SCANS:
            logger.warning(f"Service '{service}' not found in SCANS mapping")
            continue

        logger.info(f"Scanning {service} service with {len(scan_list)} checks")

        for scan_name in scan_list:
            if scan_name not in SCANS[service]:
                logger.warning(f"Scan '{scan_name}' not found for service '{service}'")
                continue

            try:
                scan_func = SCANS[service][scan_name]
                scan_func(session, findings=findings)
                logger.debug(f"✓ Completed scan: {service}/{scan_name}")
            except Exception as e:
                logger.error(
                    f"✗ Error running scan {scan_name} for service {service}: {e}"
                )
                continue

    logger.info(f"Scan complete. Total findings: {len(findings)}")
    return findings
