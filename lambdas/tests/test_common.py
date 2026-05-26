"""Tests for STIX-aware utilities in shared/common.py."""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("ASSET_CATEGORIES_JSON", "{}")

from shared.common import (
    validate_stix_core,
    extract_cves_from_stix,
    build_stix_dedup_hash,
    build_cve_cluster_hash,
)

VULN = {
    "type": "vulnerability",
    "spec_version": "2.1",
    "id": "vulnerability--12345678-1234-1234-1234-123456789abc",
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "name": "Test Vuln",
    "description": "A test vulnerability CVE-2024-99999",
    "external_references": [
        {"source_name": "cve", "external_id": "CVE-2024-12345"},
    ],
}

INDICATOR = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--abcdef12-abcd-abcd-abcd-abcdef123456",
    "created": "2024-01-01T00:00:00.000Z",
    "modified": "2024-01-01T00:00:00.000Z",
    "name": "Malicious IP",
    "pattern": "[ipv4-addr:value = '1.2.3.4'] AND CVE-2024-55555",
    "pattern_type": "stix",
    "valid_from": "2024-01-01T00:00:00.000Z",
}


def test_validate_stix_core_valid_vulnerability():
    validate_stix_core(VULN)  # should not raise


def test_validate_stix_core_valid_indicator():
    validate_stix_core(INDICATOR)  # should not raise


def test_validate_stix_core_missing_field():
    bad = {**VULN}
    del bad["modified"]
    with pytest.raises(ValueError, match="modified"):
        validate_stix_core(bad)


def test_validate_stix_core_wrong_spec_version():
    bad = {**VULN, "spec_version": "2.0"}
    with pytest.raises(ValueError, match="spec_version"):
        validate_stix_core(bad)


def test_validate_stix_core_id_type_mismatch():
    bad = {**VULN, "id": "indicator--12345678-1234-1234-1234-123456789abc"}
    with pytest.raises(ValueError, match="does not match"):
        validate_stix_core(bad)


def test_extract_cves_from_stix_external_references():
    cves = extract_cves_from_stix(VULN)
    # CVE-2024-12345 from external_references, CVE-2024-99999 from description
    assert "CVE-2024-12345" in cves
    assert "CVE-2024-99999" in cves


def test_extract_cves_from_stix_indicator_pattern():
    cves = extract_cves_from_stix(INDICATOR)
    assert "CVE-2024-55555" in cves


def test_extract_cves_from_stix_no_cves():
    obj = {**VULN, "external_references": [], "description": "no CVEs here"}
    cves = extract_cves_from_stix(obj)
    assert cves == []


def test_build_stix_dedup_hash_consistent():
    h1 = build_stix_dedup_hash(VULN)
    h2 = build_stix_dedup_hash(VULN)
    assert h1 == h2
    assert len(h1) == 64  # sha256 hex


def test_build_cve_cluster_hash_same_cves_different_ids():
    # Two objects with same CVEs but different STIX ids — cluster hash must match
    base = {
        **VULN,
        "description": "",  # no extra CVEs in description
    }
    vuln2 = {**base, "id": "vulnerability--99999999-9999-9999-9999-999999999999"}
    h1 = build_cve_cluster_hash(base)
    h2 = build_cve_cluster_hash(vuln2)
    assert h1 == h2


def test_build_cve_cluster_hash_no_cves_returns_empty():
    obj = {**VULN, "external_references": [], "description": "no CVEs", "name": "no CVEs"}
    assert build_cve_cluster_hash(obj) == ""
