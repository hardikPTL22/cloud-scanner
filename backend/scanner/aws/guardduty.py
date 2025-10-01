from scanner.mitre_map import Vulnerability, new_vulnerability


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
