from scanner.db import list_scans, get_scan
from datetime import datetime


def build_grc_trend(aws_access_key: str):
    scans = list_scans(aws_access_key)

    trend = []

    for scan in scans:
        if scan.scan_type != "service":
            continue

        scan_doc = get_scan(scan.scan_id)
        findings = scan_doc.get("findings", [])

        if not findings:
            continue

        compliant = len([f for f in findings if f.get("severity") == "low"])
        total = len(findings)
        non_compliant = total - compliant

        compliance_percentage = round((compliant / total) * 100) if total else 100

        trend.append(
            {
                "scan_id": scan.scan_id,
                "date": scan.created_at.strftime("%Y-%m-%d"),
                "compliance_percentage": compliance_percentage,
                "compliant_controls": compliant,
                "non_compliant_controls": non_compliant,
            }
        )

    # Oldest → newest
    return list(reversed(trend))
