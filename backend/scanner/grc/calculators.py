def calculate_percentage(passed: int, total: int) -> float:
    if total == 0:
        return 100.0
    return round((passed / total) * 100, 2)
