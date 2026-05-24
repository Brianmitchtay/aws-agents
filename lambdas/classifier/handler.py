import json
import os
from datetime import datetime, timezone

import boto3

from shared.common import build_classifier_prompt, invoke_bedrock_json, load_config, to_decimal

bedrock = boto3.client("bedrock-runtime")
dynamodb = boto3.resource("dynamodb")
sqs = boto3.client("sqs")

TABLE_NAME = os.environ["TABLE_NAME"]
SPECIALIST_QUEUE_URLS = json.loads(os.environ["SPECIALIST_QUEUE_URLS"])
MODEL_ID = os.environ["BEDROCK_MODEL_ID"]

table = dynamodb.Table(TABLE_NAME)


def handler(event, context):
    """Classify threat intel and route to the appropriate specialist queue."""
    for record in event.get("Records", []):
        message = json.loads(record["body"])
        threat_id = message["threat_id"]
        config = load_config()
        system_prompt = build_classifier_prompt(config)

        user_message = (
            f"Title: {message['title']}\n"
            f"Source: {message['source']}\n\n"
            f"{message['content']}"
        )

        result = invoke_bedrock_json(bedrock, MODEL_ID, system_prompt, user_message)
        category_id = result["asset_category"]

        if category_id not in SPECIALIST_QUEUE_URLS:
            category_id = config["asset_categories"][0]["id"]

        now = datetime.now(timezone.utc).isoformat()
        table.update_item(
            Key={"threat_id": threat_id},
            UpdateExpression=(
                "SET asset_category = :cat, classification_confidence = :conf, "
                "classification_reasoning = :reason, #s = :status, updated_at = :now"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":cat": category_id,
                ":conf": to_decimal(result.get("confidence", 0.0)),
                ":reason": result.get("reasoning", ""),
                ":status": "classified",
                ":now": now,
            },
        )

        sqs.send_message(
            QueueUrl=SPECIALIST_QUEUE_URLS[category_id],
            MessageBody=json.dumps({**message, "asset_category": category_id}),
        )

    return {"statusCode": 200}
