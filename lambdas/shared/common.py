"""Shared utilities for threat intel pipeline Lambdas."""

from __future__ import annotations

import hashlib
import json
import os
import re
from decimal import Decimal
from typing import Any

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_STIX_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def normalize_text(value: str) -> str:
    return " ".join(value.lower().split())


def extract_cve_ids(text: str) -> list[str]:
    return sorted({match.upper() for match in CVE_PATTERN.findall(text or "")})


def build_dedup_hash(title: str, body: str, source: str) -> str:
    """Stable hash for deduplication across overlapping feeds."""
    cves = "|".join(extract_cve_ids(f"{title}\n{body}"))
    normalized = normalize_text(f"{title}|{cves}|{source}")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def validate_stix_core(obj: dict[str, Any]) -> None:
    """Validate required STIX 2.1 core fields. Raises ValueError on failure."""
    for field in ("type", "spec_version", "id", "created", "modified"):
        if field not in obj:
            raise ValueError(f"Missing required STIX field: {field}")
    if obj["spec_version"] != "2.1":
        raise ValueError(f"Expected spec_version '2.1', got '{obj['spec_version']}'")
    if not _STIX_ID_PATTERN.match(obj["id"]):
        raise ValueError(f"Invalid STIX id format: {obj['id']}")
    obj_type = obj["id"].split("--")[0]
    if obj_type != obj["type"]:
        raise ValueError(f"STIX id type '{obj_type}' does not match type field '{obj['type']}'")


def extract_cves_from_stix(obj: dict[str, Any]) -> list[str]:
    """Extract CVE IDs from a STIX object (external_references, pattern, description)."""
    cves: set[str] = set()
    # Primary: external_references with source_name == "cve"
    for ref in obj.get("external_references", []):
        if ref.get("source_name", "").lower() == "cve":
            ext_id = ref.get("external_id", "")
            if CVE_PATTERN.match(ext_id):
                cves.add(ext_id.upper())
    # Fallback: regex scan of pattern (indicator) and description
    for text_field in ("pattern", "description", "name"):
        cves.update(extract_cve_ids(obj.get(text_field, "")))
    return sorted(cves)


def build_stix_dedup_hash(obj: dict[str, Any]) -> str:
    """Stable dedup hash for a STIX object, keyed on CVEs + STIX UUID."""
    cves = extract_cves_from_stix(obj)
    stix_uuid = obj["id"].split("--")[1]
    # Use the STIX UUID as the "source" component so different objects with
    # the same CVEs produce different hashes (CVE-only match is handled separately).
    cve_str = "|".join(cves)
    normalized = normalize_text(f"{cve_str}|{stix_uuid}")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def build_cve_cluster_hash(obj: dict[str, Any]) -> str:
    """Hash keyed only on CVEs (no STIX id) — used for cross-object update detection."""
    cves = extract_cves_from_stix(obj)
    if not cves:
        return ""
    normalized = normalize_text("|".join(cves))
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


