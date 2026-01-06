
__all__ = ['run_scans']

def __getattr__(name):
    """Lazy import to avoid loading boto3 until needed"""
    if name == 'run_scans':
        from scanner.aws import run_scans as _run_scans
        return _run_scans
    raise AttributeError(f"module 'scanner' has no attribute '{name}'")