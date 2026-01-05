from datetime import datetime, timedelta
from scanner.db import list_scans, get_scan
from scanner.grc.compliance_engine import build_compliance
from typing import Dict, Optional


def calculate_control_effectiveness(
    aws_access_key: str, days: int = 30
) -> Optional[Dict]:

    cutoff_date = datetime.now() - timedelta(days=days)
    scans = list_scans(aws_access_key)

    recent_scans = [
        s
        for s in scans
        if s.scan_type == "service"
        and s.created_at
        and s.created_at >= cutoff_date
        and s.completed_at is not None
    ]

    if len(recent_scans) < 2:
        return None

    recent_scans.sort(key=lambda x: x.created_at)

    control_history = {}

    for scan in recent_scans:
        scan_doc = get_scan(scan.scan_id)
        findings = scan_doc.get("findings", [])

        if not findings:
            continue

        compliance = build_compliance(findings)

        for fw_name, fw_score in compliance.frameworks.items():
            if fw_name not in control_history:
                control_history[fw_name] = []

            control_history[fw_name].append(
                {
                    "date": scan.created_at,
                    "compliant": fw_score.compliant,
                    "total": fw_score.total_controls,
                    "compliance_percent": fw_score.compliance_percent,
                }
            )

    metrics = {}

    for fw_name, history in control_history.items():
        if len(history) < 2:
            continue

        latest = history[-1]
        previous = history[-2]
        oldest = history[0]

        cer = latest["compliance_percent"]

        improvement = latest["compliant"] - previous["compliant"]
        improvement_rate = (
            (improvement / previous["total"] * 100) if previous["total"] > 0 else 0
        )

        overall_improvement = latest["compliant"] - oldest["compliant"]
        overall_trend = (
            (overall_improvement / oldest["total"] * 100) if oldest["total"] > 0 else 0
        )

        compliance_values = [h["compliant"] for h in history]
        avg_compliance = sum(compliance_values) / len(compliance_values)
        variance = sum((x - avg_compliance) ** 2 for x in compliance_values) / len(
            compliance_values
        )
        stability_score = (
            max(0, 100 - (variance / avg_compliance * 10)) if avg_compliance > 0 else 0
        )

        metrics[fw_name] = {
            "control_effectiveness_rating": round(cer, 2),
            "improvement_rate": round(improvement_rate, 2),
            "overall_trend": round(overall_trend, 2),
            "stability_score": round(stability_score, 2),
            "total_controls": latest["total"],
            "effective_controls": latest["compliant"],
            "failed_controls": latest["total"] - latest["compliant"],
            "scan_count": len(history),
            "period_start": oldest["date"].strftime("%Y-%m-%d"),
            "period_end": latest["date"].strftime("%Y-%m-%d"),
        }

    if metrics:
        total_cer = sum(m["control_effectiveness_rating"] for m in metrics.values())
        avg_cer = total_cer / len(metrics)

        total_controls = sum(m["total_controls"] for m in metrics.values())
        total_effective = sum(m["effective_controls"] for m in metrics.values())
        total_failed = sum(m["failed_controls"] for m in metrics.values())

        metrics["overall"] = {
            "control_effectiveness_rating": round(avg_cer, 2),
            "total_controls": total_controls,
            "effective_controls": total_effective,
            "failed_controls": total_failed,
            "frameworks_tracked": len(metrics) - 1,
        }

    return metrics


def get_control_trend(aws_access_key: str, control_id: str, days: int = 30) -> list:

    from datetime import timezone

    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
    scans = list_scans(aws_access_key)

    recent_scans = [
        s
        for s in scans
        if s.scan_type == "service" and s.created_at and s.created_at >= cutoff_date
    ]

    trend = []

    for scan in recent_scans:
        scan_doc = get_scan(scan.scan_id)
        findings = scan_doc.get("findings", [])

        control_failed = False
        for finding in findings:
            from scanner.grc.control_mapper import map_control

            mapping = map_control(finding.get("type"))
            if mapping:
                for controls in mapping.values():
                    if control_id in controls:
                        control_failed = True
                        break
            if control_failed:
                break

        trend.append(
            {
                "scan_id": scan.scan_id,
                "date": scan.created_at.strftime("%Y-%m-%d %H:%M"),
                "status": "FAIL" if control_failed else "PASS",
            }
        )

    return sorted(trend, key=lambda x: x["date"])
