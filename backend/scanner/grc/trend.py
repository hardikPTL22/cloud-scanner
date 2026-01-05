from scanner.db import list_scans, get_scan
from scanner.grc.compliance_engine import build_compliance
from datetime import datetime


def build_grc_trend(aws_access_key: str, limit: int = 10):

    scans = list_scans(aws_access_key, scan_type="service", limit=limit)

    if not scans:
        return []

    trend = []

    for scan in scans:
        scan_doc = get_scan(scan.scan_id)
        findings = scan_doc.get("findings", [])

        if not findings:
            trend.append(
                {
                    "scan_id": scan.scan_id,
                    "date": scan.created_at.strftime("%Y-%m-%d %H:%M"),
                    "compliance_percentage": 100.0,
                    "compliant_controls": 0,
                    "non_compliant_controls": 0,
                    "frameworks": {
                        "iso27001": 100.0,
                        "nist_csf": 100.0,
                        "cis_aws": 100.0,
                    },
                }
            )
            continue

        compliance = build_compliance(findings)

        framework_scores = {}
        for fw_name, fw_score in compliance.frameworks.items():
            framework_scores[fw_name] = fw_score.compliance_percent

        trend.append(
            {
                "scan_id": scan.scan_id,
                "date": scan.created_at.strftime("%Y-%m-%d %H:%M"),
                "compliance_percentage": compliance.overall_compliance,
                "compliant_controls": compliance.control_status.get("compliant", 0),
                "non_compliant_controls": compliance.control_status.get(
                    "non_compliant", 0
                ),
                "frameworks": framework_scores,
            }
        )

    trend.sort(key=lambda x: x["date"])

    return trend


def calculate_compliance_velocity(aws_access_key: str, days: int = 30) -> dict:

    from datetime import timedelta, timezone

    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
    scans = list_scans(aws_access_key, scan_type="service")

    recent_scans = [s for s in scans if s.created_at and s.created_at >= cutoff_date]

    if len(recent_scans) < 2:
        return {
            "velocity": 0.0,
            "trend": "insufficient_data",
            "scans_analyzed": len(recent_scans),
        }

    recent_scans.sort(key=lambda x: x.created_at)

    compliance_scores = []

    for scan in recent_scans:
        scan_doc = get_scan(scan.scan_id)
        findings = scan_doc.get("findings", [])

        if not findings:
            compliance_scores.append(100.0)
        else:
            compliance = build_compliance(findings)
            compliance_scores.append(compliance.overall_compliance)

    first_score = compliance_scores[0]
    last_score = compliance_scores[-1]

    velocity = last_score - first_score

    if velocity > 5:
        trend = "improving"
    elif velocity < -5:
        trend = "degrading"
    else:
        trend = "stable"

    return {
        "velocity": round(velocity, 2),
        "trend": trend,
        "first_compliance": round(first_score, 2),
        "last_compliance": round(last_score, 2),
        "scans_analyzed": len(recent_scans),
        "period_days": days,
    }
