import vt
import hashlib
import os
import tempfile
import asyncio
from typing import List, Dict, Any
from datetime import datetime
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
MAX_CONCURRENT = 4
REQUEST_DELAY = 0.3


class RateLimiter:
    def __init__(self, max_concurrent: int, delay: float):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.delay = delay
        self.last_request = 0

    async def wait(self):
        async with self.semaphore:
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            now = loop.time()
            if now - self.last_request < self.delay:
                await asyncio.sleep(self.delay - (now - self.last_request))
            self.last_request = loop.time()


def calculate_file_hash(file_path: str) -> Dict[str, str]:
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)

    return {"md5": md5_hash.hexdigest(), "sha256": sha256_hash.hexdigest()}


def download_s3_file(session, bucket: str, key: str) -> str:
    s3_client = session.client("s3")
    file_extension = os.path.splitext(key)[1] or ""
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=file_extension)
    temp_path = temp_file.name
    temp_file.close()

    s3_client.download_file(bucket, key, temp_path)
    return temp_path


async def check_virustotal_hash(
    sha256: str, rate_limiter: RateLimiter
) -> Dict[str, Any]:
    if not VIRUSTOTAL_API_KEY:
        logger.error("VirusTotal API key not configured")
        return None

    try:
        await rate_limiter.wait()

        async with vt.Client(VIRUSTOTAL_API_KEY) as client:
            logger.info(f"Checking VT hash database: {sha256}")

            try:
                file_obj = await client.get_object_async(f"/files/{sha256}")
            except vt.error.APIError as e:
                if "NotFound" in str(e) or "404" in str(e):
                    logger.info(f"Hash not in VT database: {sha256}")
                    return None
                raise

            if not file_obj:
                logger.warning(f"File not found in VT: {sha256}")
                return None

            stats = file_obj.last_analysis_stats or {}
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)

            # NEW - Calculate total_vendors
            total_vendors = malicious + suspicious + undetected + harmless

            logger.info(
                f"VT Results - Malicious: {malicious}, Suspicious: {suspicious}"
            )

            if malicious > 0:
                severity = "High"
                status = "Malicious"
            elif suspicious > 0:
                severity = "Medium"
                status = "Suspicious"
            else:
                severity = "Low"
                status = "Clean"

            detected_engines = []
            vendor_detections = []

            if (
                hasattr(file_obj, "last_analysis_results")
                and file_obj.last_analysis_results
            ):
                for vendor_name, result in file_obj.last_analysis_results.items():
                    if isinstance(result, dict):
                        category = result.get("category", "undetected")

                        if category in ["malicious", "suspicious"]:
                            detected_engines.append(vendor_name)

                        vendor_detections.append(
                            {
                                "vendor": vendor_name,
                                "category": category,
                                "engine_name": result.get("engine_name", vendor_name),
                                "result": result.get("result", "-"),
                            }
                        )

            scan_date = ""
            if hasattr(file_obj, "last_analysis_date") and file_obj.last_analysis_date:
                try:
                    if isinstance(file_obj.last_analysis_date, datetime):
                        scan_date = file_obj.last_analysis_date.isoformat()
                    else:
                        scan_date = datetime.fromtimestamp(
                            file_obj.last_analysis_date
                        ).isoformat()
                except:
                    pass

            return {
                "severity": severity,
                "status": status,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "undetected_count": undetected,
                "harmless_count": harmless,
                "total_vendors": total_vendors,
                "scan_date": scan_date,
                "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
                "file_size": getattr(file_obj, "size", 0),
                "file_type": getattr(file_obj, "type_description", "Unknown"),
                "detected_engines": detected_engines[:10],
            }

    except Exception as e:
        logger.error(f"Error checking VT hash {sha256}: {str(e)}")
        return None


async def scan_single_file(
    session, bucket: str, key: str, rate_limiter: RateLimiter
) -> Dict[str, Any]:
    try:
        logger.info(f"Processing file: {key}")
        local_path = download_s3_file(session, bucket, key)

        hashes = calculate_file_hash(local_path)
        sha256 = hashes["sha256"]
        md5 = hashes["md5"]

        logger.info(f"File hash: {sha256}")
        vt_result = await check_virustotal_hash(sha256, rate_limiter)

        try:
            os.remove(local_path)
        except Exception as e:
            logger.warning(f"Failed to remove temp file: {str(e)}")

        if vt_result:
            result = {
                "file_key": key,
                "file_name": os.path.basename(key),
                "md5": md5,
                "sha256": sha256,
                **vt_result,
            }
            logger.info(f"Scanned {key}: {vt_result['status']}")
            return result
        else:
            return {
                "file_key": key,
                "file_name": os.path.basename(key),
                "severity": "Low",
                "status": "Unknown",
                "malicious_count": 0,
                "suspicious_count": 0,
                "undetected_count": 0,
                "harmless_count": 0,
                "total_vendors": 0,
                "scan_date": "",
                "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
                "file_size": 0,
                "file_type": "Unknown",
                "md5": md5,
                "sha256": sha256,
                "detected_engines": [],
            }

    except Exception as e:
        logger.error(f"Error processing file {key}: {str(e)}", exc_info=True)
        return {
            "file_key": key,
            "file_name": os.path.basename(key),
            "status": "error",
            "error": str(e),
        }


async def scan_s3_files(
    session, bucket: str, file_keys: List[str]
) -> List[Dict[str, Any]]:
    logger.info(f"Starting scan of {len(file_keys)} files")

    rate_limiter = RateLimiter(MAX_CONCURRENT, REQUEST_DELAY)
    tasks = []

    for key in file_keys:
        if not key.endswith("/"):
            tasks.append(scan_single_file(session, bucket, key, rate_limiter))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    final_results = []
    for result in results:
        if isinstance(result, Exception):
            logger.error(f"Task error: {str(result)}")
            final_results.append({"status": "error", "error": str(result)})
        else:
            final_results.append(result)

    logger.info(f"Scan complete. Processed {len(final_results)} files")
    return final_results


def build_file_tree(objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    tree = {}

    for obj in objects:
        key = obj["Key"]
        parts = key.split("/")

        current = tree
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                if part:
                    current[part] = {
                        "key": key,
                        "name": part,
                        "type": "file",
                        "size": obj.get("Size", 0),
                        "lastModified": (
                            obj.get("LastModified").isoformat()
                            if obj.get("LastModified")
                            else None
                        ),
                    }
            else:
                if part not in current:
                    current[part] = {
                        "key": "/".join(parts[: i + 1]) + "/",
                        "name": part,
                        "type": "folder",
                        "children": {},
                        "isExpanded": False,
                    }
                current = current[part].get("children", {})

    def dict_to_list(d):
        result = []
        for key, value in d.items():
            if value["type"] == "folder" and "children" in value:
                children_dict = value.pop("children")
                value["children"] = dict_to_list(children_dict)
            result.append(value)
        return result

    return dict_to_list(tree)
