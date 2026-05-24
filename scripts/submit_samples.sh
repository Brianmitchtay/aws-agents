#!/usr/bin/env bash
# Submit all sample threats and label expected dedup / routing behaviour.
#
# Usage:
#   ./scripts/submit_samples.sh <ingest-url>
#
set -euo pipefail

INGEST_URL="${1:?Usage: ./submit_samples.sh <ingest-url>}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES_DIR="$SCRIPT_DIR/samples"

submit() {
  local file="$1"
  local note="$2"
  echo ""
  echo "=== $(basename "$file") ==="
  echo "Note: $note"
  curl -sS -X POST "$INGEST_URL" \
    -H "Content-Type: application/json" \
    -d @"$file" | python3 -m json.tool
  sleep 2
}

submit "$SAMPLES_DIR/01_scada_plc_cisa.json" \
  "SCADA/OT — baseline Schneider PLC advisory (CVE-2024-12345)"

submit "$SAMPLES_DIR/02_scada_plc_vendor_advisory.json" \
  "Near-duplicate: same CVE, different source + phrasing (currently ingested separately — dedup gap demo)"

submit "$SAMPLES_DIR/03_scada_plc_industry_news.json" \
  "Near-duplicate: same CVE again, news-style wording (another separate ingest)"

submit "$SAMPLES_DIR/04_network_cisco_iosxe.json" \
  "Network — Cisco IOS XE (CVE-2024-20399)"

submit "$SAMPLES_DIR/05_corporate_exchange_ntlm.json" \
  "Corporate IT — Microsoft Exchange (CVE-2024-21410)"

submit "$SAMPLES_DIR/06_telco_juniper_junos.json" \
  "Telco — Juniper Junos (CVE-2024-21591)"

echo ""
echo "=== Exact duplicate check ==="
echo "Re-submitting 01 — should return status: duplicate"
curl -sS -X POST "$INGEST_URL" \
  -H "Content-Type: application/json" \
  -d @"$SAMPLES_DIR/01_scada_plc_cisa.json" | python3 -m json.tool
