#!/usr/bin/env bash
# Configure Bedrock model invocation logging to CloudWatch Logs.
#
# Usage:
#   AWS_PROFILE=root ./scripts/enable_bedrock_logging.sh
#
set -euo pipefail

REGION="${AWS_DEFAULT_REGION:-us-east-1}"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
LOG_GROUP="/aws/bedrock/modelinvocations"
ROLE_NAME="threat-intelligence-invocations"
ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/service-role/${ROLE_NAME}"
POLICY_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/infrastructure/iam/bedrock-invocation-logging-policy.json"

echo "Account: ${ACCOUNT_ID}  Region: ${REGION}"
echo "Log group: ${LOG_GROUP}"
echo "Role: ${ROLE_ARN}"

# Log group must exist before Bedrock validates the role.
if ! aws logs describe-log-groups --region "$REGION" --log-group-name-prefix "$LOG_GROUP" \
  --query "logGroups[?logGroupName=='${LOG_GROUP}'] | length(@)" --output text | grep -q '^1$'; then
  echo "Creating log group..."
  aws logs create-log-group --region "$REGION" --log-group-name "$LOG_GROUP"
  aws logs put-retention-policy --region "$REGION" --log-group-name "$LOG_GROUP" --retention-in-days 30
fi

POLICY_ARN="$(aws iam list-policies --scope Local \
  --query "Policies[?PolicyName=='${ROLE_NAME}-logging'].Arn" --output text)"

if [[ -z "$POLICY_ARN" || "$POLICY_ARN" == "None" ]]; then
  echo "Creating IAM policy ${ROLE_NAME}-logging..."
  POLICY_ARN="$(aws iam create-policy \
    --policy-name "${ROLE_NAME}-logging" \
    --path /service-role/ \
    --policy-document "file://${POLICY_FILE}" \
    --query Policy.Arn --output text)"
else
  echo "Updating IAM policy ${POLICY_ARN}..."
  aws iam create-policy-version \
    --policy-arn "$POLICY_ARN" \
    --policy-document "file://${POLICY_FILE}" \
    --set-as-default
fi

if ! aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
  --query "AttachedPolicies[?PolicyArn=='${POLICY_ARN}'] | length(@)" --output text | grep -q '^1$'; then
  # Detach console-generated policy if present (optional)
  OLD="$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
    --query 'AttachedPolicies[0].PolicyArn' --output text 2>/dev/null || true)"
  if [[ -n "$OLD" && "$OLD" != "None" && "$OLD" != "$POLICY_ARN" ]]; then
    aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$OLD" || true
  fi
  aws iam attach-role-policy --role-name "$ROLE_NAME" --policy-arn "$POLICY_ARN"
fi

echo "Enabling Bedrock model invocation logging..."
aws bedrock put-model-invocation-logging-configuration --region "$REGION" \
  --logging-config "{
    \"textDataDeliveryEnabled\": true,
    \"cloudWatchConfig\": {
      \"logGroupName\": \"${LOG_GROUP}\",
      \"roleArn\": \"${ROLE_ARN}\"
    }
  }"

echo ""
aws bedrock get-model-invocation-logging-configuration --region "$REGION" --output json
echo ""
echo "Done. Invocations will appear in CloudWatch log group: ${LOG_GROUP}"
