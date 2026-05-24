#!/usr/bin/env bash
# Run this with an IAM admin profile — NOT threat-intelligence-ai.
#
# Usage:
#   AWS_PROFILE=admin ./scripts/grant-deploy-access.sh
#   AWS_PROFILE=admin ./scripts/grant-deploy-access.sh threat-intelligence-ai
#
set -euo pipefail

USER_NAME="${1:-threat-intelligence-ai}"
POLICY_NAME="ThreatIntelDeployAccess"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_FILE="$SCRIPT_DIR/../infrastructure/iam/threat-intel-deploy-policy.json"
ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
POLICY_ARN="arn:aws:iam::${ACCOUNT_ID}:policy/${POLICY_NAME}"

echo "Caller: $(aws sts get-caller-identity --query Arn --output text)"
echo "Attaching ${POLICY_NAME} to user ${USER_NAME}..."

if aws iam get-policy --policy-arn "$POLICY_ARN" >/dev/null 2>&1; then
  echo "Policy exists — creating new default version..."
  aws iam create-policy-version \
    --policy-arn "$POLICY_ARN" \
    --policy-document "file://${POLICY_FILE}" \
    --set-as-default
else
  echo "Creating policy..."
  POLICY_ARN="$(aws iam create-policy \
    --policy-name "$POLICY_NAME" \
    --policy-document "file://${POLICY_FILE}" \
    --query Policy.Arn --output text)"
fi

aws iam attach-user-policy \
  --user-name "$USER_NAME" \
  --policy-arn "$POLICY_ARN"

echo "Done. ${USER_NAME} can now run:"
echo "  cd infrastructure && npx cdk bootstrap && npm run deploy"
