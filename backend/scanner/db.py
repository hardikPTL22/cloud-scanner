from datetime import datetime, timezone
from pymongo import MongoClient
from bson import ObjectId
import logging
import os
from scanner.models import VulnerabilityFinding, ScanItem

logger = logging.getLogger(__name__)

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27018")
client = MongoClient(MONGO_URI)
db = client.get_database("cloud_scanner")
scans_collection = db.get_collection("scans")


def map_object_to_class(obj: dict):
    selected = obj.get("scans")
    if not selected and "selected_scans" in obj:
        selected = obj.get("selected_scans")

    if selected and isinstance(selected, list):
        if len(selected) > 0 and isinstance(selected[0], list):
            selected = [item for sublist in selected for item in sublist]

    return ScanItem(
        scan_id=str(obj["_id"]),
        access_key=obj["aws_access_key"],
        scan_type=obj.get("scan_type", "service"),
        selected_scans=selected,
        findings=obj.get("findings", []),
        completed_at=obj.get("completed_at"),
        created_at=obj.get("created_at"),
        metadata=obj.get("metadata", {}),
    )


def create_scan(
    aws_access_key: str,
    scans: list = None,
    scan_type: str = "service",
    bucket: str = None,
    metadata: dict = None,
):
    doc = {
        "aws_access_key": aws_access_key,
        "scan_type": scan_type,
        "findings": None,
        "created_at": datetime.now(timezone.utc),
        "completed_at": None,
        "metadata": metadata or {},
    }

    if scan_type == "service":
        doc["scans"] = scans
    elif scan_type == "file":
        doc["bucket"] = bucket
        doc["scans"] = None

    inserted = scans_collection.insert_one(doc)
    return str(inserted.inserted_id)


def update_scan(scan_id: str, findings: list, completed: bool, metadata: dict = None):
    update_fields = {}

    if completed:
        update_fields["completed_at"] = datetime.now(timezone.utc)

    if completed and findings is not None:
        if findings and hasattr(findings[0], "model_dump"):
            update_fields["findings"] = [f.model_dump() for f in findings]
        elif findings:
            update_fields["findings"] = findings
        else:
            update_fields["findings"] = []

    if metadata:
        update_fields["metadata"] = metadata

    result = scans_collection.update_one(
        {"_id": ObjectId(scan_id)}, {"$set": update_fields}
    )

    logger.info(
        f"Updated scan {scan_id}: completed={completed}, findings={len(findings) if findings else 0}"
    )

    return result.modified_count > 0


def list_scans(aws_access_key: str, scan_type: str = None, limit: int = None):
    query = {"aws_access_key": aws_access_key}

    if scan_type:
        query["scan_type"] = scan_type

    cursor = scans_collection.find(query).sort("created_at", -1)
    return list(map(map_object_to_class, cursor.to_list(limit)))


def list_service_scans(aws_access_key: str, limit: int = None):
    return list_scans(aws_access_key, scan_type="service", limit=limit)


def list_file_scans(aws_access_key: str, limit: int = None):
    return list_scans(aws_access_key, scan_type="file", limit=limit)


def get_scan(scan_id: str):
    scan = scans_collection.find_one({"_id": ObjectId(scan_id)})
    if scan:
        scan["_id"] = scan_id
    return scan
