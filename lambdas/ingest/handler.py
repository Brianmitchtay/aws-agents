import json
import os
import uuid
from datetime import datetime, timezone

import boto3

from shared.common import build_dedup_hash

s3 = boto3.client("s3")
sqs = boto3.client("sqs")
dynamodb = boto3.resource("dynamodb")

RAW_BUCKET = os.environ["RAW_BUCKET"]
TABLE_NAME = os.environ["TABLE_NAME"]
INGESTION_QUEUE_URL = os.environ["INGESTION_QUEUE_URL"]

table = dynamodb.Table(TABLE_NAME)


def handler(event, context):
    """Receive threat intel via API Gateway and enqueue for classification."""
    body = json.loads(event.get("body") or "{}")

    title = body.get("title", "").strip()
    content = body.get("content", "").strip()
    source = body.get("source", "unknown").strip()

    if not title or not content:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "title and content are required"}),
        }

    dedup_hash = build_dedup_hash(title, content, source)
    existing = table.query(
        IndexName="dedup-index",
        KeyConditionExpression="dedup_hash = :h",
        ExpressionAttributeValues={":h": dedup_hash},
        Limit=1,
    )
    if existing.get("Items"):
        item = existing["Items"][0]
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(
                {
                    "status": "duplicate",
                    "threat_id": item["threat_id"],
                    "message": "This item was already ingested",
                }
            ),
        }

    threat_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    s3_key = f"raw/{source}/{threat_id}.json"

    s3.put_object(
        Bucket=RAW_BUCKET,
        Key=s3_key,
        Body=json.dumps(body).encode("utf-8"),
        ContentType="application/json",
    )

    table.put_item(
        Item={
            "threat_id": threat_id,
            "dedup_hash": dedup_hash,
            "title": title,
            "source": source,
            "raw_s3_key": s3_key,
            "status": "ingested",
            "created_at": now,
            "updated_at": now,
        }
    )

    sqs.send_message(
        QueueUrl=INGESTION_QUEUE_URL,
        MessageBody=json.dumps(
            {
                "threat_id": threat_id,
                "title": title,
                "content": content,
                "source": source,
            }
        ),
    )

    return {
        "statusCode": 202,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"status": "accepted", "threat_id": threat_id}),
    }
