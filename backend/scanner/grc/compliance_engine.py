from collections import defaultdict
from scanner.grc.control_mapper import map_control
from scanner.grc.calculators import calculate_percentage
from scanner.grc.schemas import ComplianceSummary, FrameworkScore


def build_compliance(findings: list[dict]) -> ComplianceSummary:
    """
    Enhanced compliance calculation that properly handles:
    1. Multiple findings mapping to same control
    2. Different control counts per framework
    3. Severity-based failure logic (High/Critical = fail)
    """
    framework_controls = {
        "iso27001": defaultdict(lambda: {"findings": set(), "failed": False}),
        "nist_csf": defaultdict(lambda: {"findings": set(), "failed": False}),
        "cis_aws": defaultdict(lambda: {"findings": set(), "failed": False}),
    }

    for finding in findings:
        finding_type = finding.get("type")
        severity = finding.get("severity", "").lower()

        mapping = map_control(finding_type.upper() if finding_type else None)
        if not mapping:
            continue

        is_failure = severity in ["high", "critical"]

        for fw in framework_controls.keys():
            controls = mapping.get(fw, [])
            for ctrl in controls:
                framework_controls[fw][ctrl]["findings"].add(finding_type)

                if is_failure:
                    framework_controls[fw][ctrl]["failed"] = True

    summary = {}
    control_status = {"compliant": 0, "non_compliant": 0}

    for fw, controls in framework_controls.items():
        total = len(controls)
        failed = sum(1 for ctrl_data in controls.values() if ctrl_data["failed"])
        passed = total - failed

        control_status["compliant"] += passed
        control_status["non_compliant"] += failed

        summary[fw] = FrameworkScore(
            total_controls=total,
            compliant=passed,
            non_compliant=failed,
            compliance_percent=calculate_percentage(passed, total),
        )

    overall = calculate_percentage(
        control_status["compliant"],
        control_status["compliant"] + control_status["non_compliant"],
    )

    return ComplianceSummary(
        overall_compliance=overall,
        frameworks=summary,
        control_status=control_status,
    )
