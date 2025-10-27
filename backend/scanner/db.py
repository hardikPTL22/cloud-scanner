from datetime import datetime
from pymongo import MongoClient
from bson import ObjectId
import os


MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27018")
client = MongoClient(MONGO_URI)

db = client.get_database("cloud_scanner")
scans_collection = db.get_collection("scans")


def create_scan(aws_access_key: str, scans: list):
    doc = {
        "aws_access_key": aws_access_key,
        "scans": scans,
        "findings": None,
        "created_at": datetime.utcnow(),
        "completed": False,
    }

    inserted = scans_collection.insert_one(doc)
    return str(inserted.inserted_id)


def update_scan(scan_id: str, findings: list, completed: bool):
    update_fields = {
        "completed": completed,
    }

    if completed and findings is not None:
        update_fields["findings"] = findings
        update_fields["completed_at"] = datetime.utcnow()

    result = scans_collection.update_one(
        {"_id": ObjectId(scan_id)}, {"$set": update_fields}
    )
    return result.modified_count > 0


def list_scans(aws_access_key: str, limit: int = 10):
    cursor = scans_collection.find({"aws_access_key": aws_access_key}).sort(
        "created_at", -1
    )

    return cursor.to_list(limit)


def get_scan(scan_id: str):
    scan = scans_collection.find_one({"_id": ObjectId(scan_id)})
    if scan:
        scan["_id"] = scan_id
    return scan
