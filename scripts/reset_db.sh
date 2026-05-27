#!/usr/bin/env bash
# Clear and re-seed the DynamoDB threats table with the mock-frontend seed data.
# Useful for resetting to a known state before demo retakes.
#
# Usage:
#   ./scripts/reset_db.sh
#   AWS_PROFILE=root ./scripts/reset_db.sh
#   STACK_NAME=ThreatIntelStack AWS_DEFAULT_REGION=us-east-1 ./scripts/reset_db.sh
#
set -euo pipefail

STACK_NAME="${STACK_NAME:-ThreatIntelStack}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SEED_SCRIPT="${SCRIPT_DIR}/../../mock-frontend/seed-dynamodb.js"

echo "=== Resetting DynamoDB threats table ==="
echo "Stack: ${STACK_NAME} | Region: ${REGION}"

# Resolve table name from CloudFormation
TABLE="$(aws cloudformation describe-stacks \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='ThreatsTableName'].OutputValue" \
  --output text)"

if [[ -z "$TABLE" || "$TABLE" == "None" ]]; then
  echo "ERROR: Could not resolve ThreatsTableName from stack ${STACK_NAME}" >&2
  exit 1
fi

echo "Table: ${TABLE}"

# Step 1: Delete all existing items
echo ""
echo "--- Clearing existing items ---"
ITEMS="$(aws dynamodb scan \
  --region "$REGION" \
  --table-name "$TABLE" \
  --projection-expression "threat_id" \
  --query "Items[].threat_id.S" \
  --output text || true)"

if [[ -n "${ITEMS// }" ]]; then
  COUNT=0
  for threat_id in $ITEMS; do
    aws dynamodb delete-item \
      --region "$REGION" \
      --table-name "$TABLE" \
      --key "{\"threat_id\":{\"S\":\"${threat_id}\"}}"
    COUNT=$((COUNT + 1))
  done
  echo "  Deleted ${COUNT} items."
else
  echo "  (table already empty)"
fi

# Step 2: Re-seed from mock-frontend seed data
echo ""
echo "--- Seeding fresh data ---"
if [[ ! -f "$SEED_SCRIPT" ]]; then
  echo "ERROR: Seed script not found at ${SEED_SCRIPT}" >&2
  exit 1
fi

THREATS_TABLE="$TABLE" node "$SEED_SCRIPT"

echo ""
echo "=== Done. Database reset to seed state. ==="
