import json
import os
from datetime import datetime, timezone

import boto3

from shared.common import build_specialist_prompt, invoke_bedrock_json, load_config, to_decimal

bedrock = boto3.client("bedrock-runtime")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")

TABLE_NAME = os.environ["TABLE_NAME"]
NOTIFICATION_TOPIC_ARN = os.environ["NOTIFICATION_TOPIC_ARN"]
MODEL_ID = os.environ["BEDROCK_MODEL_ID"]

table = dynamodb.Table(TABLE_NAME)


def handler(event, context):
    """Run specialist assessment and publish digest via SNS."""
    for record in event.get("Records", []):
        message = json.loads(record["body"])
        threat_id = message["threat_id"]
        category_id = message["asset_category"]
        config = load_config()

        system_prompt = build_specialist_prompt(config, category_id)
        user_message = (
            f"Title: {message['title']}\n"
            f"Source: {message['source']}\n\n"
            f"{message['content']}"
        )

        result = invoke_bedrock_json(bedrock, MODEL_ID, system_prompt, user_message)
        now = datetime.now(timezone.utc).isoformat()

        table.update_item(
            Key={"threat_id": threat_id},
            UpdateExpression=(
                "SET severity = :sev, assessment_confidence = :conf, summary = :summary, "
                "affected_assets = :assets, cve_ids = :cves, #s = :status, updated_at = :now"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":sev": result.get("severity", "medium"),
                ":conf": to_decimal(result.get("confidence", 0.0)),
                ":summary": result.get("summary", ""),
                ":assets": result.get("affected_assets", []),
                ":cves": result.get("cve_ids", []),
                ":status": "assessed",
                ":now": now,
            },
        )

        category = next(c for c in config["asset_categories"] if c["id"] == category_id)
        digest = {
            "threat_id": threat_id,
            "title": message["title"],
            "source": message["source"],
            "asset_category": category_id,
            "asset_category_display": category["display_name"],
            "severity": result.get("severity"),
            "confidence": result.get("confidence"),
            "summary": result.get("summary"),
            "affected_assets": result.get("affected_assets", []),
            "cve_ids": result.get("cve_ids", []),
            "notify_email": category.get("notify_email"),
            "mark_processed_url_hint": f"POST /threats/{threat_id}/processed",
        }

        sns.publish(
            TopicArn=NOTIFICATION_TOPIC_ARN,
            Subject=f"[{result.get('severity', 'medium').upper()}] {message['title'][:80]}",
            Message=json.dumps(digest, indent=2),
            MessageAttributes={
                "asset_category": {"DataType": "String", "StringValue": category_id},
                "severity": {"DataType": "String", "StringValue": result.get("severity", "medium")},
            },
        )

        table.update_item(
            Key={"threat_id": threat_id},
            UpdateExpression="SET #s = :status, notified_at = :now, updated_at = :now",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":status": "notified", ":now": now},
        )

    return {"statusCode": 200}
