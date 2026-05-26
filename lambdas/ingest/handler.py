import json
import os
import uuid
from datetime import datetime, timezone

import boto3

from shared.common import (
    build_cve_cluster_hash,
    build_stix_dedup_hash,
    validate_stix_core,
)

s3 = boto3.client("s3")
sqs = boto3.client("sqs")
dynamodb = boto3.resource("dynamodb")

RAW_BUCKET = os.environ["RAW_BUCKET"]
TABLE_NAME = os.environ["TABLE_NAME"]
INGESTION_QUEUE_URL = os.environ["INGESTION_QUEUE_URL"]

table = dynamodb.Table(TABLE_NAME)


def _ingest_one(obj: dict) -> dict:
    """Ingest a single STIX object. Returns a result dict."""
    try:
        validate_stix_core(obj)
    except ValueError as e:
        return {"status": "error", "error": str(e)}

    # Tier 1: exact STIX id dedup
    existing_by_stix_id = table.query(
        IndexName="stix-id-index",
        KeyConditionExpression="stix_id = :sid",
        ExpressionAttributeValues={":sid": obj["id"]},
        Limit=1,
    )
    if existing_by_stix_id.get("Items"):
        return {"status": "duplicate", "threat_id": existing_by_stix_id["Items"][0]["threat_id"]}

    # Tier 2: CVE-cluster dedup (update trail)
    supersedes_id = None
    cve_hash = build_cve_cluster_hash(obj)
    if cve_hash:
        existing_by_cve = table.query(
            IndexName="dedup-index",
            KeyConditionExpression="dedup_hash = :h",
            ExpressionAttributeValues={":h": cve_hash},
            Limit=1,
        )
        if existing_by_cve.get("Items"):
            supersedes_id = existing_by_cve["Items"][0]["threat_id"]

    threat_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    source = obj.get("created_by_ref", "unknown")
    s3_key = f"raw/{obj['type']}/{threat_id}.json"

    s3.put_object(
        Bucket=RAW_BUCKET,
        Key=s3_key,
        Body=json.dumps(obj).encode("utf-8"),
        ContentType="application/json",
    )

    item = {
        "threat_id": threat_id,
        "stix_id": obj["id"],
        "stix_type": obj["type"],
        "dedup_hash": cve_hash or build_stix_dedup_hash(obj),
        "title": obj.get("name", obj["id"]),
        "source": source,
        "raw_s3_key": s3_key,
        "status": "ingested",
        "created_at": now,
        "updated_at": now,
    }
    if supersedes_id:
        item["supersedes"] = supersedes_id

    table.put_item(Item=item)

    sqs.send_message(
        QueueUrl=INGESTION_QUEUE_URL,
        MessageBody=json.dumps({
            "threat_id": threat_id,
            "stix_object": obj,
            "supersedes": supersedes_id,
        }),
    )

    return {"status": "accepted", "threat_id": threat_id}


def handler(event, context):
    body = json.loads(event.get("body") or "{}")

    # Unpack bundle or treat as single object
    if body.get("type") == "bundle":
        objects = body.get("objects", [])
        if not objects:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "bundle contains no objects"}),
            }
        results = [_ingest_one(obj) for obj in objects]
        # 400 if every object errored; otherwise 202
        all_errors = all(r["status"] == "error" for r in results)
        return {
            "statusCode": 400 if all_errors else 202,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"results": results}),
        }

    result = _ingest_one(body)
    status_code = 400 if result["status"] == "error" else (200 if result["status"] == "duplicate" else 202)
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(result),
    }
