"""Shared utilities for threat intel pipeline Lambdas."""

from __future__ import annotations

import hashlib
import json
import os
import re
from decimal import Decimal
from typing import Any

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def normalize_text(value: str) -> str:
    return " ".join(value.lower().split())


def extract_cve_ids(text: str) -> list[str]:
    return sorted({match.upper() for match in CVE_PATTERN.findall(text or "")})


def build_dedup_hash(title: str, body: str, source: str) -> str:
    """Stable hash for deduplication across overlapping feeds."""
    cves = "|".join(extract_cve_ids(f"{title}\n{body}"))
    normalized = normalize_text(f"{title}|{cves}|{source}")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def load_config() -> dict[str, Any]:
    raw = os.environ.get("ASSET_CATEGORIES_JSON", "{}")
    return json.loads(raw)


def get_category(config: dict[str, Any], category_id: str) -> dict[str, Any] | None:
    for category in config.get("asset_categories", []):
        if category["id"] == category_id:
            return category
    return None


def parse_bedrock_json(text: str) -> dict[str, Any]:
    """Extract JSON from model output, tolerating markdown fences."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)

    return json.loads(cleaned)


def to_decimal(value: float | int) -> Decimal:
    return Decimal(str(value))


def invoke_bedrock_json(client: Any, model_id: str, system_prompt: str, user_message: str) -> dict[str, Any]:
    response = client.converse(
        modelId=model_id,
        system=[{"text": system_prompt}],
        messages=[{"role": "user", "content": [{"text": user_message}]}],
        inferenceConfig={"maxTokens": 1024, "temperature": 0.2},
    )
    output_text = response["output"]["message"]["content"][0]["text"]
    return parse_bedrock_json(output_text)


def load_prompt_template(name: str) -> str:
    prompts_dir = os.environ.get("PROMPTS_DIR", "/var/task/prompts")
    path = os.path.join(prompts_dir, name)
    with open(path, encoding="utf-8") as f:
        return f.read()


def build_classifier_prompt(config: dict[str, Any]) -> str:
    template = load_prompt_template("classifier.md")
    categories_block = "\n".join(
        f"- **{c['id']}** ({c['display_name']}): {c['description']}"
        for c in config["asset_categories"]
    )
    return template.replace("{{ASSET_CATEGORIES}}", categories_block)


def build_specialist_prompt(config: dict[str, Any], category_id: str) -> str:
    category = get_category(config, category_id)
    if not category:
        raise ValueError(f"Unknown category: {category_id}")

    template = load_prompt_template("specialist.md")
    severity_block = ", ".join(config.get("severity_levels", []))
    return (
        template.replace("{{CATEGORY_DISPLAY_NAME}}", category["display_name"])
        .replace("{{CATEGORY_DESCRIPTION}}", category["description"])
        .replace("{{SEVERITY_LEVELS}}", severity_block)
    )
