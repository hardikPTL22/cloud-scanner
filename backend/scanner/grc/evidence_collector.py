from datetime import datetime
from typing import Dict, List
from scanner.db import get_scan
from scanner.grc.schemas import ComplianceEvidence
from scanner.grc.control_mapper import map_control


def collect_evidence(scan_id: str, control_id: str) -> ComplianceEvidence:

    scan = get_scan(scan_id)

    if not scan:
        raise ValueError(f"Scan {scan_id} not found")

    findings = scan.get("findings", [])

    control_findings = []
    evidence_artifacts = []
    affected_resources = set()
    finding_types = set()

    for finding in findings:
        finding_type = finding.get("type")
        if not finding_type:
            continue

        mapping = map_control(finding_type)
        if not mapping:
            continue

        control_found = False
        frameworks_matched = []

        for fw, controls in mapping.items():
            if control_id in controls:
                control_found = True
                frameworks_matched.append(fw)

        if not control_found:
            continue

        control_findings.append(finding)
        finding_types.add(finding_type)

        resource_id = (
            finding.get("resource_id") or finding.get("details", "").split(":")[0]
            if ":" in finding.get("details", "")
            else "N/A"
        )
        affected_resources.add(resource_id)

        artifact = {
            "type": "security_finding",
            "timestamp": (
                scan.get("created_at").isoformat()
                if scan.get("created_at")
                else datetime.now().isoformat()
            ),
            "source": "aws_cloud_scanner",
            "scan_id": scan_id,
            "finding_data": {
                "finding_type": finding_type,
                "severity": finding.get("severity", "unknown"),
                "service": finding.get("service", "unknown"),
                "resource_id": resource_id,
                "name": finding.get("name", "Unknown Finding"),
                "mitre_mapping": finding.get("mitre_id"),
                "details": finding.get("details", ""),
            },
            "frameworks": frameworks_matched,
        }
        evidence_artifacts.append(artifact)

    status = "PASS" if len(control_findings) == 0 else "FAIL"

    if status == "PASS":
        auditor_notes = f"Control {control_id} PASSED: No security findings detected in scan {scan_id}"
    else:
        auditor_notes = (
            f"Control {control_id} FAILED: {len(control_findings)} finding(s) detected. "
            f"Affected resources: {len(affected_resources)}. "
            f"Finding types: {', '.join(finding_types)}"
        )

    if status == "PASS":
        evidence_artifacts.append(
            {
                "type": "scan_metadata",
                "timestamp": (
                    scan.get("created_at").isoformat()
                    if scan.get("created_at")
                    else datetime.now().isoformat()
                ),
                "source": "aws_cloud_scanner",
                "scan_id": scan_id,
                "data": {
                    "scan_type": scan.get("scan_type", "service"),
                    "total_findings": len(findings),
                    "services_scanned": scan.get("metadata", {}).get("services", []),
                    "control_status": "PASS",
                    "control_id": control_id,
                },
            }
        )

    return ComplianceEvidence(
        control_id=control_id,
        scan_id=scan_id,
        status=status,
        evidence_artifacts=evidence_artifacts,
        collected_at=datetime.now(),
        auditor_notes=auditor_notes,
        attestation_required=(status == "FAIL"),
    )


def collect_all_evidence(scan_id: str) -> Dict[str, ComplianceEvidence]:

    scan = get_scan(scan_id)

    if not scan:
        raise ValueError(f"Scan {scan_id} not found")

    findings = scan.get("findings", [])

    all_controls = set()

    for finding in findings:
        mapping = map_control(finding.get("type"))
        if mapping:
            for controls in mapping.values():
                all_controls.update(controls)

    evidence_map = {}

    for control_id in all_controls:
        try:
            evidence = collect_evidence(scan_id, control_id)
            evidence_map[control_id] = evidence
        except Exception as e:
            import logging

            logger = logging.getLogger(__name__)
            logger.error(f"Failed to collect evidence for control {control_id}: {e}")

    return evidence_map


def export_evidence_report(scan_id: str, format: str = "json") -> str:

    import json
    import csv
    import os
    from pathlib import Path

    evidence_map = collect_all_evidence(scan_id)

    reports_dir = Path("reports/evidence")
    reports_dir.mkdir(parents=True, exist_ok=True)

    if format == "json":
        output_path = reports_dir / f"evidence_{scan_id}.json"

        export_data = {
            "scan_id": scan_id,
            "generated_at": datetime.now().isoformat(),
            "controls": {
                control_id: evidence.model_dump()
                for control_id, evidence in evidence_map.items()
            },
        }

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2, default=str)

    elif format == "csv":
        output_path = reports_dir / f"evidence_{scan_id}.csv"

        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "Control ID",
                    "Status",
                    "Finding Count",
                    "Attestation Required",
                    "Auditor Notes",
                    "Collected At",
                ]
            )

            for control_id, evidence in evidence_map.items():
                writer.writerow(
                    [
                        control_id,
                        evidence.status,
                        len(evidence.evidence_artifacts),
                        evidence.attestation_required,
                        evidence.auditor_notes,
                        evidence.collected_at.isoformat(),
                    ]
                )

    return str(output_path)
