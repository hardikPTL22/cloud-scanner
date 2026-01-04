from botocore.exceptions import ClientError
from scanner.mitre_maps.guardduty_mitre_map import GuardDutyVulnerability
from scanner.utils import new_vulnerability
from scanner.aws.decorator import inject_clients
from concurrent.futures import ThreadPoolExecutor
import logging
import datetime

logger = logging.getLogger(__name__)


def fetch_detectors(guardduty_client):
    """Fetch all GuardDuty detectors once for reuse across checks"""
    try:
        return guardduty_client.list_detectors().get("DetectorIds", [])
    except Exception as e:
        logger.error(f"Error fetching detectors: {e}")
        return []


@inject_clients(clients=["guardduty"])
def find_guardduty_disabled(guardduty_client, findings, detectors=None):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    if not detectors:
        findings.append(
            new_vulnerability(
                GuardDutyVulnerability.guardduty_disabled,
                "GuardDuty Detector Not Found",
                "guardduty",
            )
        )
        return

    def check_detector_status(detector_id):
        try:
            status = guardduty_client.get_detector(DetectorId=detector_id)
            if not status.get("Status") == "ENABLED":
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_disabled,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_detector_status, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_detectors_disabled(guardduty_client, findings, detectors=None):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    if not detectors:
        findings.append(
            new_vulnerability(
                GuardDutyVulnerability.guardduty_disabled,
                "No Detectors",
                "guardduty",
            )
        )
        return

    def check_detector_enabled(detector_id):
        try:
            status = guardduty_client.get_detector(DetectorId=detector_id).get("Status")
            if status != "ENABLED":
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_disabled,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_detector_enabled, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_finding_publishing_frequency_not_optimal(
    guardduty_client, findings, detectors=None
):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_frequency(detector_id):
        try:
            detector = guardduty_client.get_detector(DetectorId=detector_id)
            frequency = detector.get("FindingPublishingFrequency", "")
            if frequency != "FIFTEEN_MINUTES":
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_finding_freq_not_optimal,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_frequency, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_no_s3_protection(guardduty_client, findings, detectors=None):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_s3_protection(detector_id):
        try:
            members = guardduty_client.list_members(
                DetectorId=detector_id, OnlyAssociated=False
            )
            if not members.get("Members"):
                detector_config = guardduty_client.get_detector(DetectorId=detector_id)
                data_sources = detector_config.get("DataSources", {})
                s3_logs = data_sources.get("S3Logs", {})
                if not s3_logs.get("Enable", False):
                    findings.append(
                        new_vulnerability(
                            GuardDutyVulnerability.guardduty_no_s3_protection,
                            detector_id,
                            "guardduty",
                        )
                    )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_s3_protection, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_no_eks_protection(guardduty_client, findings, detectors=None):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_eks_protection(detector_id):
        try:
            detector_config = guardduty_client.get_detector(DetectorId=detector_id)
            data_sources = detector_config.get("DataSources", {})
            eks_logs = data_sources.get("EKSLogs", {})
            if not eks_logs.get("Enable", False):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_no_eks_protection,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_eks_protection, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_no_lambda_protection(guardduty_client, findings, detectors=None):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_lambda_protection(detector_id):
        try:
            detector_config = guardduty_client.get_detector(DetectorId=detector_id)
            data_sources = detector_config.get("DataSources", {})
            lambda_logs = data_sources.get("Lambda", {})
            if not lambda_logs.get("Enable", False):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_no_lambda_protection,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_lambda_protection, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_no_rds_protection(guardduty_client, findings, detectors=None):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_rds_protection(detector_id):
        try:
            detector_config = guardduty_client.get_detector(DetectorId=detector_id)
            data_sources = detector_config.get("DataSources", {})
            rds_logs = data_sources.get("RDSLoginEvents", {})
            if not rds_logs.get("Enable", False):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_no_rds_protection,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_rds_protection, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_no_cloudwatch_logs_export(
    guardduty_client, findings, detectors=None
):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_cloudwatch_export(detector_id):
        try:
            response = guardduty_client.describe_publishing_destination(
                DetectorId=detector_id
            )
            if not response.get("PublishingDestination"):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_no_cloudwatch_logs,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            findings.append(
                new_vulnerability(
                    GuardDutyVulnerability.guardduty_no_cloudwatch_logs,
                    detector_id,
                    "guardduty",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_cloudwatch_export, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_no_threat_intel_feed(guardduty_client, findings, detectors=None):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_threat_intel(detector_id):
        try:
            threat_intel_sets = guardduty_client.list_threat_intel_sets(
                DetectorId=detector_id
            )
            if not threat_intel_sets.get("ThreatIntelSetIds"):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_no_threat_intel,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_threat_intel, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_findings_not_archived(guardduty_client, findings, detectors=None):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_archived(detector_id):
        try:
            list_findings_response = guardduty_client.list_findings(
                DetectorId=detector_id,
                FindingCriteria={"Criterion": {"severity": {"gte": 4}}},
            )
            finding_ids = list_findings_response.get("FindingIds", [])
            if finding_ids:
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_findings_not_archived,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_archived, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_no_ip_set(guardduty_client, findings, detectors=None):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_ip_set(detector_id):
        try:
            ip_sets = guardduty_client.list_ip_sets(DetectorId=detector_id)
            if not ip_sets.get("IpSetIds"):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_no_ip_set,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_ip_set, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_no_member_accounts(guardduty_client, findings, detectors=None):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_members(detector_id):
        try:
            members = guardduty_client.list_members(
                DetectorId=detector_id, OnlyAssociated=True
            )
            if not members.get("Members"):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_no_member_accounts,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_members, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_findings_high_severity_not_addressed(
    guardduty_client, findings, detectors=None
):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_high_severity(detector_id):
        try:
            high_findings = guardduty_client.list_findings(
                DetectorId=detector_id,
                FindingCriteria={"Criterion": {"severity": {"gte": 7}}},
            )
            if high_findings.get("FindingIds"):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_high_severity_findings,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_high_severity, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_detectors_no_tagging(guardduty_client, findings, detectors=None):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_tags(detector_id):
        try:
            tags = guardduty_client.list_tags_for_resource(
                ResourceArn=f"arn:aws:guardduty:*:*:detector/{detector_id}"
            )
            if not tags.get("Tags"):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_detector_no_tags,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_tags, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_no_member_account_invitations(
    guardduty_client, findings, detectors=None
):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_invitations(detector_id):
        try:
            invitations = guardduty_client.list_invitations()
            if not invitations.get("Invitations"):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_no_member_invitations,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_invitations, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_master_account_not_enabled(guardduty_client, findings):
    try:
        master_account = guardduty_client.get_master_account()
        if not master_account:
            findings.append(
                new_vulnerability(
                    GuardDutyVulnerability.guardduty_no_master_account,
                    "account",
                    "guardduty",
                )
            )
    except ClientError:
        findings.append(
            new_vulnerability(
                GuardDutyVulnerability.guardduty_no_master_account,
                "account",
                "guardduty",
            )
        )


@inject_clients(clients=["guardduty"])
def find_guardduty_no_vpc_flow_logs(guardduty_client, findings, detectors=None):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_vpc_flow_logs(detector_id):
        try:
            detector_config = guardduty_client.get_detector(DetectorId=detector_id)
            data_sources = detector_config.get("DataSources", {})
            flow_logs = data_sources.get("FlowLogs", {})
            if not flow_logs.get("Enable", False):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_no_vpc_flow_logs,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_vpc_flow_logs, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_no_cloudtrail_logs(guardduty_client, findings, detectors=None):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_cloudtrail(detector_id):
        try:
            detector_config = guardduty_client.get_detector(DetectorId=detector_id)
            data_sources = detector_config.get("DataSources", {})
            cloudtrail = data_sources.get("CloudTrail", {})
            if not cloudtrail.get("Enable", False):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_no_cloudtrail,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_cloudtrail, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_findings_export_not_configured(
    guardduty_client, findings, detectors=None
):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_export(detector_id):
        try:
            publishing_dest = guardduty_client.describe_publishing_destination(
                DetectorId=detector_id
            )
            if not publishing_dest.get("PublishingDestination"):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_no_findings_export,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            findings.append(
                new_vulnerability(
                    GuardDutyVulnerability.guardduty_no_findings_export,
                    detector_id,
                    "guardduty",
                )
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_export, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_detector_no_sns_notification(
    guardduty_client, findings, detectors=None
):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_sns(detector_id):
        try:
            events = guardduty_client.list_publishing_destinations(
                DetectorId=detector_id
            )
            destinations = events.get("PublishingDestinations", [])
            has_sns = False
            for dest in destinations:
                if "sns" in dest.get("DestinationArn", "").lower():
                    has_sns = True
                    break
            if not has_sns:
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_no_sns_notification,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_sns, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_orphaned_detectors(guardduty_client, findings, detectors=None):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_orphaned(detector_id):
        try:
            response = guardduty_client.get_detector(DetectorId=detector_id)
            if response.get("CreatedAt"):
                created_at = response.get("CreatedAt") / 1000
                now = datetime.datetime.now().timestamp()
                age_days = (now - created_at) / (24 * 3600)
                if age_days > 90:
                    if not response.get("UpdatedAt"):
                        findings.append(
                            new_vulnerability(
                                GuardDutyVulnerability.guardduty_orphaned_detector,
                                detector_id,
                                "guardduty",
                            )
                        )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_orphaned, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_no_custom_ip_set(guardduty_client, findings, detectors=None):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_custom_ip_set(detector_id):
        try:
            ip_sets = guardduty_client.list_ip_sets(DetectorId=detector_id)
            custom_ip_sets = [
                s for s in ip_sets.get("IpSetIds", []) if not s.startswith("aws-")
            ]
            if not custom_ip_sets:
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_no_custom_ip_set,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_custom_ip_set, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_no_custom_threat_intel_set(
    guardduty_client, findings, detectors=None
):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_custom_threat_intel(detector_id):
        try:
            threat_sets = guardduty_client.list_threat_intel_sets(
                DetectorId=detector_id
            )
            if not threat_sets.get("ThreatIntelSetIds"):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_no_custom_threat_intel,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_custom_threat_intel, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_malware_protection_disabled(
    guardduty_client, findings, detectors=None
):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_malware_protection(detector_id):
        try:
            detector_config = guardduty_client.get_detector(DetectorId=detector_id)
            data_sources = detector_config.get("DataSources", {})
            malware = data_sources.get("Malware", {})
            if not malware.get("ScanEc2InstanceWithFindings", {}).get(
                "EbsVolumes", False
            ):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_malware_protection_disabled,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_malware_protection, detectors)


@inject_clients(clients=["guardduty"])
def find_guardduty_runtime_monitoring_disabled(
    guardduty_client, findings, detectors=None
):
    if detectors is None:
        detectors = fetch_detectors(guardduty_client)

    def check_runtime_monitoring(detector_id):
        try:
            detector_config = guardduty_client.get_detector(DetectorId=detector_id)
            data_sources = detector_config.get("DataSources", {})
            runtime = data_sources.get("RuntimeMonitoring", {})
            if not runtime.get("EksClusterMonitoring", {}).get("EksClusterDetails"):
                findings.append(
                    new_vulnerability(
                        GuardDutyVulnerability.guardduty_runtime_monitoring_disabled,
                        detector_id,
                        "guardduty",
                    )
                )
        except ClientError:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(check_runtime_monitoring, detectors)
