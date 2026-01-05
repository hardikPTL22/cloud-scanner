from typing import Dict
from scanner.grc.schemas import RiskScore, RiskLevel

SEVERITY_TO_CVSS = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "informational": 0.5,
}

IMPACT_MATRIX = {
    "s3": {"public": 4, "encryption": 4, "versioning": 2, "logging": 3},
    "rds": {"public": 5, "encryption": 5, "backup": 4, "snapshot": 4},
    "iam": {"root": 5, "mfa": 5, "password": 3, "access_key": 4},
    "ec2": {"public": 4, "encryption": 4, "security_group": 4, "ssh": 5},
    "lambda": {"public": 3, "tracing": 2, "environment": 3},
    "cloudtrail": {"logging": 5, "validation": 4, "encryption": 4},
    "guardduty": {"detection": 5, "enabled": 5},
    "apigateway": {"logging": 3, "authorization": 4, "throttling": 2},
    "ebs": {"encryption": 4, "snapshot": 3},
    "ssm": {"encryption": 4, "parameter": 3},
}


def calculate_risk_score(finding: dict) -> RiskScore:

    severity = finding.get("severity", "low").lower()
    service = finding.get("service", "unknown").lower()
    finding_type = finding.get("type", "").lower()

    cvss_score = SEVERITY_TO_CVSS.get(severity, 2.5)

    impact = 1.0
    if service in IMPACT_MATRIX:
        for keyword, impact_value in IMPACT_MATRIX[service].items():
            if keyword in finding_type:
                impact = 1 + (impact_value / 10)
                break

    exploitability = 1.0

    if "public" in finding_type or "exposed" in finding_type:
        exploitability = 1.3
    elif any(
        keyword in finding_type for keyword in ["unencrypted", "encryption", "mfa"]
    ):
        exploitability = 1.15
    elif any(
        keyword in finding_type for keyword in ["logging", "tracing", "monitoring"]
    ):
        exploitability = 1.05

    risk_score = min(10.0, cvss_score * impact * exploitability)

    if risk_score >= 9.0:
        risk_level = RiskLevel.CRITICAL
    elif risk_score >= 7.0:
        risk_level = RiskLevel.HIGH
    elif risk_score >= 4.0:
        risk_level = RiskLevel.MEDIUM
    elif risk_score >= 1.0:
        risk_level = RiskLevel.LOW
    else:
        risk_level = RiskLevel.INFORMATIONAL

    return RiskScore(
        score=round(risk_score, 2),
        level=risk_level,
        cvss_base=cvss_score,
        impact_factor=round(impact, 2),
        exploitability_factor=round(exploitability, 2),
    )


def calculate_aggregate_risk(findings: list[dict]) -> dict:
    if not findings:
        return {
            "total_risk_score": 0.0,
            "average_risk_score": 0.0,
            "max_risk_score": 0.0,
            "risk_distribution": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
            },
        }

    risk_scores = []
    risk_distribution = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }

    for finding in findings:
        risk_score = calculate_risk_score(finding)
        risk_scores.append(risk_score.score)
        risk_distribution[risk_score.level.value] += 1

    return {
        "total_risk_score": round(sum(risk_scores), 2),
        "average_risk_score": round(sum(risk_scores) / len(risk_scores), 2),
        "max_risk_score": round(max(risk_scores), 2),
        "risk_distribution": risk_distribution,
    }
