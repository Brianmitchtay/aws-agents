import json
import os
import uuid
import urllib.request
from datetime import datetime, timezone

import boto3

from shared.common import load_config, get_category, parse_bedrock_json, to_decimal

bedrock_agent_runtime = boto3.client("bedrock-agent-runtime")
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")

TABLE_NAME = os.environ["TABLE_NAME"]
NOTIFICATION_TOPIC_ARN = os.environ["NOTIFICATION_TOPIC_ARN"]
CLASSIFIER_AGENT_ID = os.environ["CLASSIFIER_AGENT_ID"]
CLASSIFIER_AGENT_ALIAS_ID = os.environ["CLASSIFIER_AGENT_ALIAS_ID"]
SPECIALIST_AGENT_IDS = json.loads(os.environ["SPECIALIST_AGENT_IDS"])
SPECIALIST_AGENT_ALIAS_IDS = json.loads(os.environ["SPECIALIST_AGENT_ALIAS_IDS"])
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")

table = dynamodb.Table(TABLE_NAME)


def invoke_agent(agent_id: str, alias_id: str, input_text: str, session_id: str) -> str:
    response = bedrock_agent_runtime.invoke_agent(
        agentId=agent_id,
        agentAliasId=alias_id,
        sessionId=session_id,
        inputText=input_text,
    )

    completion = ""
    for event in response["completion"]:
        if "chunk" in event:
            completion += event["chunk"]["bytes"].decode("utf-8")

    return completion


def handler(event, context):
    """Orchestrate classification and specialist assessment via Bedrock Agents."""
    for record in event.get("Records", []):
        message = json.loads(record["body"])
        threat_id = message["threat_id"]
        stix_object = message["stix_object"]
        supersedes = message.get("supersedes")
        config = load_config()

        session_id = str(uuid.uuid4())
        stix_json = json.dumps(stix_object, indent=2)

        # Step 1: Classify via Bedrock Agent
        classifier_response = invoke_agent(
            CLASSIFIER_AGENT_ID,
            CLASSIFIER_AGENT_ALIAS_ID,
            stix_json,
            session_id,
        )

        classification = parse_bedrock_json(classifier_response)
        category_id = classification.get("asset_category", "service_desk")

        if category_id not in SPECIALIST_AGENT_IDS:
            category_id = "service_desk"

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
                ":conf": to_decimal(classification.get("confidence", 0.0)),
                ":reason": classification.get("reasoning", ""),
                ":status": "classified",
                ":now": now,
            },
        )

        # Step 2: Specialist assessment via Bedrock Agent
        specialist_session_id = str(uuid.uuid4())
        specialist_response = invoke_agent(
            SPECIALIST_AGENT_IDS[category_id],
            SPECIALIST_AGENT_ALIAS_IDS[category_id],
            stix_json,
            specialist_session_id,
        )

        result = parse_bedrock_json(specialist_response)
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

        # Step 3: Notify
        category = get_category(config, category_id)
        digest = {
            "threat_id": threat_id,
            "stix_id": stix_object["id"],
            "stix_type": stix_object["type"],
            "title": stix_object.get("name", stix_object["id"]),
            "supersedes": supersedes,
            "asset_category": category_id,
            "asset_category_display": category["display_name"] if category else category_id,
            "severity": result.get("severity"),
            "confidence": result.get("confidence"),
            "summary": result.get("summary"),
            "affected_assets": result.get("affected_assets", []),
            "cve_ids": result.get("cve_ids", []),
            "assessed_at": now,
            "mark_processed_url_hint": f"POST /threats/{threat_id}/processed",
        }

        title = stix_object.get("name", stix_object["id"])
        sns.publish(
            TopicArn=NOTIFICATION_TOPIC_ARN,
            Subject=f"[{result.get('severity', 'medium').upper()}] {title[:80]}",
            Message=json.dumps(digest, indent=2),
            MessageAttributes={
                "asset_category": {"DataType": "String", "StringValue": category_id},
                "severity": {"DataType": "String", "StringValue": result.get("severity", "medium")},
            },
        )

        if WEBHOOK_URL:
            try:
                if supersedes:
                    update_payload = {
                        "severity": result.get("severity"),
                        "comment": f"Superseded by new intel (threat_id: {threat_id}). Updated assessment: {result.get('summary', '')}",
                    }
                    url = f"{WEBHOOK_URL}/api/update-ticket/{supersedes}"
                    body = json.dumps(update_payload).encode("utf-8")
                else:
                    url = f"{WEBHOOK_URL}/api/tickets"
                    body = json.dumps(digest).encode("utf-8")
                req = urllib.request.Request(
                    url,
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=5)
            except Exception as e:
                print(f"Ticket POST failed (non-fatal): {e}")

        table.update_item(
            Key={"threat_id": threat_id},
            UpdateExpression="SET #s = :status, notified_at = :now, updated_at = :now",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":status": "notified", ":now": now},
        )

    return {"statusCode": 200}
