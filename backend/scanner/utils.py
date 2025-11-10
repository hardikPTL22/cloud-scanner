from scanner.mitre_maps_registry import MITRE_MAPS, SEVERITY_MAPS
from scanner.models import VulnerabilityFinding


def new_vulnerability(vuln_type: str, resource: str, service: str = None):
    if service is None:
        service = "unknown"

    severity_map = SEVERITY_MAPS.get(service, {})
    mitre_map = MITRE_MAPS.get(service, {})

    severity = severity_map.get(vuln_type, "Medium")
    mitre_data = mitre_map.get(vuln_type, {})

    return VulnerabilityFinding(
        type=vuln_type,
        name=resource,
        severity=severity,
        service=service,
        mitre_id=mitre_data.get("mitre_id", ""),
        mitre_name=mitre_data.get("mitre_name", ""),
        description=mitre_data.get("description", ""),
        remediation=mitre_data.get("remediation", ""),
    )


def get_vulnerability_details(service: str, vuln_type: str) -> dict:
    mitre_map = MITRE_MAPS.get(service, {})
    return mitre_map.get(vuln_type, {})


def get_severity(service: str, vuln_type: str) -> str:
    severity_map = SEVERITY_MAPS.get(service, {})
    return severity_map.get(vuln_type, "Medium")
