import secrets
import os
from redis import Redis
import json


redis = Redis(protocol=3, host=os.getenv("REDIS_HOST", "localhost"), port=6379, db=0)


REDIS_KEY = "scan_reports"


def generate_report_url(scan_id: str, format: str) -> str:
    token = secrets.token_urlsafe(32)
    redis.hset(REDIS_KEY, token, json.dumps({"scan_id": scan_id, "format": format}))
    redis.expire(REDIS_KEY, 600)
    return f"/api/reports/service/{token}"


def get_report_details(token: str) -> tuple[str, str] | tuple[None, None]:
    """Retrieve report token (DO NOT DELETE - allow multiple downloads)"""
    details = redis.hget(REDIS_KEY, token)
    if details:
        data = json.loads(details)
        return data["scan_id"], data["format"]
    return None, None
