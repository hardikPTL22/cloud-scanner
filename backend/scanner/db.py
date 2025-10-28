from datetime import datetime, timezone
from pymongo import MongoClient
from bson import ObjectId
import os
from scanner.models import VulnerabilityFinding, ScanItem


MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27018")
client = MongoClient(MONGO_URI)

db = client.get_database("cloud_scanner")
scans_collection = db.get_collection("scans")


def map_object_to_class(obj: dict):
    return ScanItem(
        scan_id=str(obj["_id"]),
        access_key=obj["aws_access_key"],
        selected_scans=obj["scans"],
        findings=obj.get("findings", []),
        completed_at=obj.get("completed_at"),
        created_at=obj.get("created_at"),
    )


def create_scan(aws_access_key: str, scans: list):
    doc = {
        "aws_access_key": aws_access_key,
        "scans": scans,
        "findings": None,
        "created_at": datetime.now(timezone.utc),
        "completed_at": None,
    }

    inserted = scans_collection.insert_one(doc)
    return str(inserted.inserted_id)


def update_scan(scan_id: str, findings: list[VulnerabilityFinding], completed: bool):
    update_fields = {
        "completed_at": datetime.now(timezone.utc) if completed else None,
    }

    if completed and findings is not None:
        update_fields["findings"] = list(
            map(lambda finding: finding.model_dump(), findings)
        )
        update_fields["completed_at"] = datetime.now(timezone.utc)

    result = scans_collection.update_one(
        {"_id": ObjectId(scan_id)}, {"$set": update_fields}
    )
    return result.modified_count > 0


def list_scans(aws_access_key: str, limit: int | None = None):
    cursor = scans_collection.find({"aws_access_key": aws_access_key}).sort(
        "created_at", -1
    )

    return list(map(map_object_to_class, cursor.to_list(limit)))


def get_scan(scan_id: str):
    scan = scans_collection.find_one({"_id": ObjectId(scan_id)})
    if scan:
        scan["_id"] = scan_id
    return scan
