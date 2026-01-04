from collections import defaultdict
from scanner.grc.control_mapper import map_control
from scanner.grc.calculators import calculate_percentage
from scanner.grc.schemas import ComplianceSummary, FrameworkScore


def build_compliance(findings: list[dict]) -> ComplianceSummary:
    framework_controls = {
        "iso27001": defaultdict(set),
        "nist_csf": defaultdict(set),
        "cis_aws": defaultdict(set),
    }

    failed_controls = {
        "iso27001": set(),
        "nist_csf": set(),
        "cis_aws": set(),
    }

    for finding in findings:
        mapping = map_control(finding.get("type"))
        if not mapping:
            continue

        for fw in framework_controls.keys():
            for ctrl in mapping.get(fw, []):
                framework_controls[fw][ctrl].add(finding["type"])
                failed_controls[fw].add(ctrl)

    summary = {}
    control_status = {"compliant": 0, "non_compliant": 0}

    for fw, controls in framework_controls.items():
        total = len(controls)
        failed = len(failed_controls[fw])
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
