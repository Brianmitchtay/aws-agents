import json
import os
from datetime import datetime, timezone

import boto3

dynamodb = boto3.resource("dynamodb")

TABLE_NAME = os.environ["TABLE_NAME"]
table = dynamodb.Table(TABLE_NAME)


def handler(event, context):
    """Mark a threat as processed and optionally record feedback."""
    threat_id = event.get("pathParameters", {}).get("threat_id")
    if not threat_id:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": "threat_id is required"}),
        }

    body = json.loads(event.get("body") or "{}")
    feedback = body.get("feedback")  # e.g. "accurate" | "overstated" | "understated"
    notes = body.get("notes", "")

    now = datetime.now(timezone.utc).isoformat()
    table.update_item(
        Key={"threat_id": threat_id},
        UpdateExpression=(
            "SET #s = :status, processed_at = :now, updated_at = :now, "
            "feedback = :feedback, feedback_notes = :notes"
        ),
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={
            ":status": "processed",
            ":now": now,
            ":feedback": feedback,
            ":notes": notes,
        },
    )

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"status": "processed", "threat_id": threat_id}),
    }
