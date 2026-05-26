"""Tests for the orchestrator Lambda handler (Bedrock Agents-based)."""
import importlib
import json
import sys
import os
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("ASSET_CATEGORIES_JSON", json.dumps({
    "asset_categories": [{"id": "scada", "display_name": "SCADA", "description": "OT",
                          "notify_email": "test@example.com"}],
    "bedrock_model_id": "test-model",
    "severity_levels": ["critical", "high", "medium"],
}))
os.environ["TABLE_NAME"] = "test-table"
os.environ["NOTIFICATION_TOPIC_ARN"] = "arn:aws:sns:us-east-1:123456789012:test"
os.environ["CLASSIFIER_AGENT_ID"] = "CLASSIFIERID"
os.environ["CLASSIFIER_AGENT_ALIAS_ID"] = "CLASSIFIERALIAS"
os.environ["SPECIALIST_AGENT_IDS"] = json.dumps({"scada": "SCADAAGENTID"})
os.environ["SPECIALIST_AGENT_ALIAS_IDS"] = json.dumps({"scada": "SCADAALIAS"})

STIX_VULN = {
    "type": "vulnerability",
    "spec_version": "2.1",
    "id": "vulnerability--12345678-1234-1234-1234-123456789abc",
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "name": "Test Vuln",
    "external_references": [{"source_name": "cve", "external_id": "CVE-2024-12345"}],
}

CLASSIFIER_RESULT = json.dumps({
    "asset_category": "scada",
    "confidence": 0.9,
    "reasoning": "OT device",
})

SPECIALIST_RESULT = json.dumps({
    "severity": "high",
    "confidence": 0.85,
    "summary": "Critical OT vulnerability.",
    "affected_assets": ["Modicon PLC"],
    "cve_ids": ["CVE-2024-12345"],
})

SQS_EVENT = {
    "Records": [{
        "body": json.dumps({
            "threat_id": "tid-001",
            "stix_object": STIX_VULN,
            "supersedes": "old-tid-999",
        })
    }]
}


def _make_agent_response(text: str):
    return {"completion": [{"chunk": {"bytes": text.encode("utf-8")}}]}


def _call(event, classifier_text=CLASSIFIER_RESULT, specialist_text=SPECIALIST_RESULT, supersedes="old-tid-999"):
    import orchestrator.handler as mod
    importlib.reload(mod)
    mock_agent_runtime = MagicMock()
    mock_table = MagicMock()
    mock_sns = MagicMock()

    call_count = {"n": 0}
    def fake_invoke_agent(**kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_agent_response(classifier_text)
        return _make_agent_response(specialist_text)

    mock_agent_runtime.invoke_agent = fake_invoke_agent

    with patch.object(mod, "bedrock_agent_runtime", mock_agent_runtime), \
         patch.object(mod, "table", mock_table), \
         patch.object(mod, "sns", mock_sns):
        result = mod.handler(event, None)
    return result, mock_table, mock_sns, mock_agent_runtime


def test_orchestrator_classifies_and_updates_dynamodb():
    result, table, _, _ = _call(SQS_EVENT)
    assert result["statusCode"] == 200
    # First update_item is the classification
    classify_call = table.update_item.call_args_list[0]
    assert classify_call[1]["ExpressionAttributeValues"][":cat"] == "scada"
    assert classify_call[1]["ExpressionAttributeValues"][":status"] == "classified"


def test_orchestrator_specialist_updates_dynamodb():
    _, table, _, _ = _call(SQS_EVENT)
    # Second update_item is the specialist assessment
    assess_call = table.update_item.call_args_list[1]
    assert assess_call[1]["ExpressionAttributeValues"][":sev"] == "high"
    assert assess_call[1]["ExpressionAttributeValues"][":status"] == "assessed"


def test_orchestrator_publishes_sns_with_digest():
    _, _, sns, _ = _call(SQS_EVENT)
    sns.publish.assert_called_once()
    digest = json.loads(sns.publish.call_args[1]["Message"])
    assert digest["stix_id"] == STIX_VULN["id"]
    assert digest["severity"] == "high"
    assert digest["asset_category"] == "scada"


def test_orchestrator_sns_digest_contains_supersedes():
    _, _, sns, _ = _call(SQS_EVENT)
    digest = json.loads(sns.publish.call_args[1]["Message"])
    assert digest["supersedes"] == "old-tid-999"


def test_orchestrator_sns_digest_supersedes_none_when_absent():
    event = {"Records": [{"body": json.dumps({
        "threat_id": "tid-002",
        "stix_object": STIX_VULN,
        "supersedes": None,
    })}]}
    _, _, sns, _ = _call(event)
    digest = json.loads(sns.publish.call_args[1]["Message"])
    assert digest["supersedes"] is None


def test_orchestrator_falls_back_to_service_desk_for_unknown_category():
    # If classifier returns a category not in SPECIALIST_AGENT_IDS, we need service_desk
    # But our test env only has "scada", so an unknown category should fallback
    bad_classifier = json.dumps({"asset_category": "unknown_team", "confidence": 0.5, "reasoning": "?"})
    # This will raise KeyError because service_desk isn't in test env SPECIALIST_AGENT_IDS
    # In production the fallback would route to service_desk
    import orchestrator.handler as mod
    importlib.reload(mod)
    mock_agent_runtime = MagicMock()
    mock_table = MagicMock()
    mock_sns = MagicMock()

    call_count = {"n": 0}
    def fake_invoke(**kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_agent_response(bad_classifier)
        return _make_agent_response(SPECIALIST_RESULT)

    mock_agent_runtime.invoke_agent = fake_invoke

    # Update env to include service_desk in agent IDs for this test
    with patch.dict(os.environ, {
        "SPECIALIST_AGENT_IDS": json.dumps({"scada": "SCADAID", "service_desk": "SDID"}),
        "SPECIALIST_AGENT_ALIAS_IDS": json.dumps({"scada": "SCADAALIAS", "service_desk": "SDALIAS"}),
    }):
        importlib.reload(mod)
        with patch.object(mod, "bedrock_agent_runtime", mock_agent_runtime), \
             patch.object(mod, "table", mock_table), \
             patch.object(mod, "sns", mock_sns):
            result = mod.handler(SQS_EVENT, None)

    classify_call = mock_table.update_item.call_args_list[0]
    assert classify_call[1]["ExpressionAttributeValues"][":cat"] == "service_desk"


def test_orchestrator_invokes_correct_specialist_agent():
    import orchestrator.handler as mod
    importlib.reload(mod)

    invocations = []
    call_count = {"n": 0}

    def fake_invoke(**kwargs):
        invocations.append(kwargs)
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _make_agent_response(CLASSIFIER_RESULT)
        return _make_agent_response(SPECIALIST_RESULT)

    mock_agent_runtime = MagicMock()
    mock_agent_runtime.invoke_agent = fake_invoke

    with patch.object(mod, "bedrock_agent_runtime", mock_agent_runtime), \
         patch.object(mod, "table", MagicMock()), \
         patch.object(mod, "sns", MagicMock()):
        mod.handler(SQS_EVENT, None)

    # Second invocation should be the specialist for "scada"
    assert invocations[1]["agentId"] == "SCADAAGENTID"
    assert invocations[1]["agentAliasId"] == "SCADAALIAS"
