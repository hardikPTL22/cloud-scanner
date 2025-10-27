from scanner.mitre_map import Vulnerability, new_vulnerability
from scanner.aws.decorator import inject_clients


@inject_clients(clients=["guardduty"])
def find_guardduty_disabled(guardduty_client, findings):
    disabled = []
    detectors = guardduty_client.list_detectors()
    if not detectors.get("DetectorIds"):
        disabled.append("GuardDuty Detector Not Found")
    else:
        for detector_id in detectors.get("DetectorIds"):
            status = guardduty_client.get_detector(DetectorId=detector_id)
            if not status.get("Status") == "ENABLED":
                disabled.append(detector_id)
    for d in disabled:
        findings.append(new_vulnerability(Vulnerability.guardduty_disabled, d))


@inject_clients(clients=["guardduty"])
def find_guardduty_detectors_disabled(guardduty_client, findings):
    detectors = guardduty_client.list_detectors().get("DetectorIds", [])
    if not detectors:
        findings.append(
            {
                "type": Vulnerability.guardduty_disabled,
                "name": "No Detectors",
                "severity": "High",
                "details": "GuardDuty detectors are missing or disabled.",
            }
        )
    else:
        for det in detectors:
            status = guardduty_client.get_detector(DetectorId=det).get("Status")
            if status != "ENABLED":
                findings.append(
                    {
                        "type": Vulnerability.guardduty_disabled,
                        "name": det,
                        "severity": "High",
                        "details": "GuardDuty detector is not enabled.",
                    }
                )
