import secrets
import os
from redis import Redis
import json

redis = Redis(protocol=3, host=os.getenv("REDIS_HOST", "localhost"), port=6379, db=0)

REDIS_KEY = "scan_reports"


def generate_report_url(scan_id: str, format: str) -> str:
    token = secrets.token_urlsafe(32)
    redis.hsetex(
        REDIS_KEY, token, json.dumps({"scan_id": scan_id, "format": format}), ex=600
    )
    return f"/reports/{token}"


def get_report_details(token: str) -> tuple[str, str] | tuple[None, None]:
    details = redis.hgetdel(REDIS_KEY, token)
    if len(details) > 0:
        details = json.loads(details[0])
        return details["scan_id"], details["format"]
    return None, None
