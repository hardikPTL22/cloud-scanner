SEVERITY_IMPACT = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def risk_score(severity: str) -> int:
    return SEVERITY_IMPACT.get(severity.lower(), 1)
