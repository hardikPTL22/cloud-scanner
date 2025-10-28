from scanner.mitre_map import Vulnerability, SEVERITY, MITRE_MAP
from scanner.models import VulnerabilityFinding


def new_vulnerability(type: Vulnerability, resource: str):
    return VulnerabilityFinding(
        type=type,
        name=resource,
        severity=SEVERITY.get(type, "Medium"),
        details=MITRE_MAP.get(type, {}).get("details", ""),
    )
