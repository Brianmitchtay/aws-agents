#!/usr/bin/env bash
# Submit a sample threat to the deployed ingestion API.
set -euo pipefail

INGEST_URL="${1:?Usage: ./submit_sample.sh <ingest-url>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

curl -sS -X POST "$INGEST_URL" \
  -H "Content-Type: application/json" \
  -d @"$SCRIPT_DIR/samples/01_scada_plc_cisa.json" | python3 -m json.tool
