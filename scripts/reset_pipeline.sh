#!/usr/bin/env bash
# Wipe pipeline state so samples can be re-run from a clean slate.
#
# Usage:
#   ./scripts/reset_pipeline.sh
#   AWS_PROFILE=root ./scripts/reset_pipeline.sh
#   STACK_NAME=ThreatIntelStack AWS_DEFAULT_REGION=ap-southeast-2 ./scripts/reset_pipeline.sh
#
set -euo pipefail

STACK_NAME="${STACK_NAME:-ThreatIntelStack}"
REGION="${AWS_DEFAULT_REGION:-ap-southeast-2}"

echo "Resetting pipeline for stack ${STACK_NAME} in ${REGION}..."

TABLE="$(aws cloudformation describe-stacks \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='ThreatsTableName'].OutputValue" \
  --output text)"

BUCKET="$(aws cloudformation describe-stack-resources \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query "StackResources[?LogicalResourceId=='RawThreatIntel7AC40256'].PhysicalResourceId" \
  --output text)"

QUEUE_URLS="$(aws cloudformation describe-stack-resources \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query "StackResources[?ResourceType=='AWS::SQS::Queue'].PhysicalResourceId" \
  --output text)"

echo "DynamoDB table: ${TABLE}"
echo "S3 bucket:      ${BUCKET}"

# DynamoDB — delete all threat records
echo "Deleting DynamoDB items..."
ITEMS="$(aws dynamodb scan \
  --region "$REGION" \
  --table-name "$TABLE" \
  --projection-expression "threat_id" \
  --query "Items[].threat_id.S" \
  --output text || true)"

if [[ -n "${ITEMS// }" ]]; then
  for threat_id in $ITEMS; do
    aws dynamodb delete-item \
      --region "$REGION" \
      --table-name "$TABLE" \
      --key "{\"threat_id\":{\"S\":\"${threat_id}\"}}"
    echo "  deleted ${threat_id}"
  done
else
  echo "  (no items)"
fi

# S3 — remove raw intel objects
echo "Clearing S3 raw/ prefix..."
if [[ -n "$BUCKET" && "$BUCKET" != "None" ]]; then
  aws s3 rm "s3://${BUCKET}/raw/" --recursive --region "$REGION" || true
else
  echo "  (bucket not found — skipped)"
fi

# SQS — purge pending messages (including stuck classifier retries)
echo "Purging SQS queues..."
for queue_url in $QUEUE_URLS; do
  aws sqs purge-queue --region "$REGION" --queue-url "$queue_url"
  echo "  purged ${queue_url##*/}"
done

echo "Done. Pipeline state cleared."
