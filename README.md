# Threat Intelligence — Multi-Agent Pipeline

2026 TasNetworks/AWS/UTAS Hackathon Winner

This prototype ingests threat feeds, classifies by asset category, routes to specialist AI agents, and notifies the right team member (via an API query to an AWS-hosted mock-front-end)

Built on AWS with **Amazon Bedrock**, Lambda, SQS, DynamoDB, S3, SNS, and API Gateway — deployed with **AWS CDK**.

![multi_agent_AWS_ai_architecture.diagram.png](./multi_agent_AWS_ai_architecture.drawio.png)

This whole project was coded using Claude Opus 4.6 on Claude Code, so take care if you fork it or use it, take care to review it well and ensure it meets your requirements.

## Architecture

```
Threat Feed (webhook / manual POST)
        ↓
  API Gateway  →  Lambda (ingestor)  →  S3 (raw) + DynamoDB (dedup)
        ↓
  SQS (ingestion queue)
        ↓
  Lambda (Agent Orchestrator function)
        ↓
  Bedrock Agent (classifier)
        ↓
  SQS (per asset-category queue)
        ↓
  Bedrock Agent (specialist x5)
        ↓
  DynamoDB (assessment)  →  SNS (email digest)
        ↓
  API Gateway  →  Lambda (mark processed + feedback)
```

## Prerequisites

1. **AWS account** with Amazon Bedrock (Our workshop account was set up in `us-east-1`)
2. **AWS CLI v2** configured (`aws configure`)
3. **Node.js 18+** and **npm**
4. **Docker Desktop** (optional — CDK can bundle Python Lambdas locally without it)
5. **AWS CDK CLI**: `npm install -g aws-cdk`

## Quick start

### 1. Customize config for client

Edit `config/asset_categories.json`:

- Replace placeholder asset categories with client's real taxonomy
- Set `notify_email` for each category (SNS will send confirmation links on first deploy)
- Adjust `severity_levels` if they use a different scale

### 2. Deploy

```bash
cd infrastructure
npm install
npx cdk bootstrap   # once per account/region
npm run deploy
```

**IAM note:** `cdk bootstrap` and `cdk deploy` need CloudFormation permissions. If bootstrap fails with `AccessDenied` on `cloudformation:DescribeStacks`, your IAM user needs broader deploy rights — ask your AWS admin to attach a policy that includes CloudFormation, S3, IAM, Lambda, and related services, or to run `cdk bootstrap` once with an admin account.

Note the stack outputs:

- `IngestUrl` — POST new threat intel here
- `MarkProcessedUrl` — POST when a human has actioned a digest
- `NotificationTopicArn` — confirm SNS email subscriptions

### 3. Test with sample data

Reset pipeline state (needed after a failed run or to clear demo data):

```bash
chmod +x scripts/reset_pipeline.sh scripts/reset_db.sh scripts/submit_samples.sh
AWS_PROFILE=root ./scripts/reset_pipeline.sh   # wipes DynamoDB, S3 raw/, and purges SQS queues
```

Reset and re-seed the DynamoDB table from the mock-frontend seed data (useful for demo retakes):

```bash
./scripts/reset_db.sh                          # clears table then seeds from mock-frontend/seed-dynamodb.js
STACK_NAME=ThreatIntelStack ./scripts/reset_db.sh
```

Submit one sample or the full demo set:

```bash
./scripts/submit_sample.sh "https://xxxx.execute-api.ap-southeast-2.amazonaws.com/prod/threats"
./scripts/submit_samples.sh "https://xxxx.execute-api.ap-southeast-2.amazonaws.com/prod/threats"
```

Run the curated demo batch (sends two waves of threats with a delay for live presentations):

````bash
python3 scripts/demo_batch.py                         # uses default deployed URL
python3 scripts/demo_batch.py --url <ingest-url> --delay 3
```                                              |

**Dedup behaviour today:** hash is `title + CVEs + source`. Exact resubmits of `01` return `"status": "duplicate"`. Samples `02` and `03` share CVE-2024-12345 but **different sources**, so they are ingested separately — useful for demoing a real-world dedup gap.

### 4. Mark as processed (feedback loop)

```bash
curl -X POST "https://xxxx.execute-api.ap-southeast-2.amazonaws.com/prod/threats/{threat_id}/processed" \
  -H "Content-Type: application/json" \
  -d '{"feedback": "accurate", "notes": "Already patched in our environment"}'
````

Feedback values are free-form strings for the demo — align with whatever Client prefers.

## API contract

### POST `/threats`

```json
{
  "title": "Short headline",
  "source": "feed-name",
  "content": "Full advisory text, CVE references, etc."
}
```

Response `202`: `{ "status": "accepted", "threat_id": "..." }`  
Response `200` (duplicate): `{ "status": "duplicate", "threat_id": "..." }`

### POST `/threats/{threat_id}/processed`

```json
{
  "feedback": "accurate | overstated | understated",
  "notes": "optional free text"
}
```

## Project layout

```
config/asset_categories.json      # Taxonomy + routing (edit this first)
prompts/                          # Bedrock system prompts (classifier + specialist)
lambdas/
  ingest/                         # API → S3 + dedup + SQS
  classifier/                     # Bedrock classify → specialist queue
  specialist/                     # Bedrock assess → SNS notify
  mark_processed/                 # Feedback loop
  shared/common.py                # Dedup, Bedrock helpers
infrastructure/                   # AWS CDK (TypeScript)
scripts/
  demo_batch.py                   # Curated two-wave demo (live presentation)
  reset_db.sh                     # Clear + re-seed DynamoDB from mock-frontend seed data
  reset_pipeline.sh               # Wipe all pipeline state (DynamoDB, S3, SQS)
  submit_sample.sh                # Submit a single threat to the ingest API
  submit_samples.sh               # Submit all samples/ threats
  enable_bedrock_logging.sh       # Configure Bedrock → CloudWatch invocation logging
  grant-deploy-access.sh          # Attach deploy IAM policy to a user
  samples/                        # Sample threat JSON files
```

## Open questions for clients

Confirm these early — they affect config, not code structure:

| Topic                    | Question                                                                            |
| ------------------------ | ----------------------------------------------------------------------------------- |
| **Asset taxonomy**       | What are your real asset categories? (SCADA/OT, substation, corporate, telco, etc.) |
| **Severity scale**       | Do you use CVSS, a internal 1–5 scale, or Critical/High/Medium/Low?                 |
| **Feed ingestion**       | Push webhooks, polled RSS/API, email, PDF uploads? Who provides credentials?        |
| **Notification channel** | Email (SNS, wired now), Microsoft Teams webhook, SMS, ServiceNow ticket?            |
| **Routing matrix**       | Which person/role owns each asset category?                                         |
| **Dedup rules**          | Is CVE-only dedup enough, or do you dedup on vendor advisory ID too?                |

## Demo tips

1. **Show dedup** — submit the same CVE from two "sources"
2. **Show routing** — submit OT vs corporate threats; different specialist queues fire
3. **Show feedback** — mark processed with `"feedback": "overstated"` and query DynamoDB
4. **Tune prompts** — edit `prompts/specialist.md` live if assessments feel off

## Cost note

This stack uses on-demand DynamoDB, short-lived Lambdas, and pay-per-token Bedrock. Fine for a hackathon; tear down with `cdk destroy` when done.

## Tear down

```bash
cd infrastructure
npx cdk destroy
```
