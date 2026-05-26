"""Tests for the STIX-aware ingest Lambda handler."""
import json
import sys
import os
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("ASSET_CATEGORIES_JSON", "{}")
os.environ["RAW_BUCKET"] = "test-bucket"
os.environ["TABLE_NAME"] = "test-table"
os.environ["INGESTION_QUEUE_URL"] = "https://sqs.test/queue"

VULN = {
    "type": "vulnerability",
    "spec_version": "2.1",
    "id": "vulnerability--12345678-1234-1234-1234-123456789abc",
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "name": "Test Vuln",
    "description": "Buffer overflow",
    "external_references": [{"source_name": "cve", "external_id": "CVE-2024-12345"}],
}

INDICATOR = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--abcdef12-abcd-abcd-abcd-abcdef123456",
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "name": "Malicious IP",
    "pattern": "[ipv4-addr:value = '1.2.3.4']",
    "pattern_type": "stix",
    "valid_from": "2024-01-01T00:00:00.000Z",
}


def _make_table(stix_id_items=None, dedup_items=None):
    table = MagicMock()
    def query(IndexName=None, **kwargs):
        if IndexName == "stix-id-index":
            return {"Items": stix_id_items or []}
        if IndexName == "dedup-index":
            return {"Items": dedup_items or []}
        return {"Items": []}
    table.query.side_effect = query
    return table


def _call(body, table=None):
    import importlib
    mock_s3 = MagicMock()
    mock_sqs = MagicMock()
    mock_table = table or _make_table()
    import ingest.handler as handler_mod
    importlib.reload(handler_mod)
    with patch.object(handler_mod, "s3", mock_s3), \
         patch.object(handler_mod, "sqs", mock_sqs), \
         patch.object(handler_mod, "table", mock_table):
        result = handler_mod.handler({"body": json.dumps(body)}, None)
    return result, mock_table, mock_sqs


def test_single_vulnerability_accepted():
    result, table, sqs = _call(VULN)
    assert result["statusCode"] == 202
    body = json.loads(result["body"])
    assert body["status"] == "accepted"
    assert "threat_id" in body
    table.put_item.assert_called_once()
    sqs.send_message.assert_called_once()


def test_single_indicator_accepted():
    result, table, sqs = _call(INDICATOR)
    assert result["statusCode"] == 202
    assert json.loads(result["body"])["status"] == "accepted"


def test_bundle_two_objects():
    bundle = {
        "type": "bundle",
        "id": "bundle--aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "objects": [VULN, INDICATOR],
    }
    result, table, sqs = _call(bundle)
    assert result["statusCode"] == 202
    body = json.loads(result["body"])
    assert len(body["results"]) == 2
    assert all(r["status"] == "accepted" for r in body["results"])
    assert sqs.send_message.call_count == 2


def test_exact_stix_id_duplicate():
    existing = [{"threat_id": "existing-id-123"}]
    table = _make_table(stix_id_items=existing)
    result, _, sqs = _call(VULN, table=table)
    assert result["statusCode"] == 200
    body = json.loads(result["body"])
    assert body["status"] == "duplicate"
    assert body["threat_id"] == "existing-id-123"
    sqs.send_message.assert_not_called()


def test_cve_match_creates_update_with_supersedes():
    # Different STIX id but same CVE cluster → update trail
    vuln2 = {**VULN, "id": "vulnerability--99999999-9999-9999-9999-999999999999"}
    existing_cve = [{"threat_id": "original-threat-id"}]
    table = _make_table(stix_id_items=[], dedup_items=existing_cve)
    result, mock_table, sqs = _call(vuln2, table=table)
    assert result["statusCode"] == 202
    body = json.loads(result["body"])
    assert body["status"] == "accepted"
    # Check put_item was called with supersedes field
    put_call = mock_table.put_item.call_args[1]["Item"]
    assert put_call["supersedes"] == "original-threat-id"
    # SQS message should also carry supersedes
    sqs_body = json.loads(sqs.send_message.call_args[1]["MessageBody"])
    assert sqs_body["supersedes"] == "original-threat-id"


def test_missing_required_field_returns_400():
    bad = {**VULN}
    del bad["modified"]
    result, _, sqs = _call(bad)
    assert result["statusCode"] == 400
    sqs.send_message.assert_not_called()


def test_empty_bundle_returns_400():
    bundle = {"type": "bundle", "id": "bundle--aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "objects": []}
    result, _, _ = _call(bundle)
    assert result["statusCode"] == 400
