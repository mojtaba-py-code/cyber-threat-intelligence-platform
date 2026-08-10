"""Tests for harvesting indicators out of reports, CSV exports and STIX bundles."""

from __future__ import annotations

import json
import time

import pytest
from app.core.exceptions import ValidationError
from app.ioc.extract import (
    MAX_CONTENT_CHARS,
    extract_from_csv,
    extract_from_stix,
    extract_from_text,
    extract_indicators,
)

REPORT = """
Threat report — Operation Example
=================================
The actor staged payloads on hxxp://malware-drop[.]example/stage1.bin and
beaconed to 198[.]51[.]100[.]23 (see also 203.0.113.9). The dropper
(sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)
was delivered by phish@evil[.]example, exploiting CVE-2024-21412 with
technique T1059.001. Analyst notes are in report.pdf; do not open payload.exe.
"""


def test_extracts_every_indicator_class_from_a_defanged_report():
    found = extract_from_text(REPORT)
    assert "http://malware-drop.example/stage1.bin" in found
    assert "198.51.100.23" in found
    assert "203.0.113.9" in found
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in found
    assert "phish@evil.example" in found
    assert "CVE-2024-21412" in found
    assert "T1059.001" in found


def test_filenames_are_not_mistaken_for_domains():
    found = extract_from_text(REPORT)
    assert "report.pdf" not in found
    assert "payload.exe" not in found


def test_url_does_not_also_yield_its_own_host():
    # The host is part of the URL span, so it must not surface as a second IOC.
    assert extract_from_text("see http://drop.example/a.bin") == ["http://drop.example/a.bin"]


def test_duplicates_collapse_and_order_is_preserved():
    assert extract_from_text("9.9.9.9 then 8.8.8.8 then 9[.]9[.]9[.]9") == ["9.9.9.9", "8.8.8.8"]


def test_limit_caps_the_result():
    text = " ".join(f"10.0.0.{i}" for i in range(1, 20))
    assert len(extract_from_text(text, limit=5)) == 5


def test_prose_without_indicators_yields_nothing():
    assert extract_from_text("No indicators were observed during this engagement.") == []


def test_csv_prefers_a_named_indicator_column():
    csv_text = "indicator,source,note\n198.51.100.7,urlhaus,c2\nbad.example,otx,phishing\n"
    assert extract_from_csv(csv_text) == ["198.51.100.7", "bad.example"]


def test_csv_without_a_named_column_scans_every_cell():
    csv_text = "a,b\n2024-01-01,203.0.113.5\nnoise,evil.example\n"
    found = extract_from_csv(csv_text)
    assert "203.0.113.5" in found
    assert "evil.example" in found


def test_stix_bundle_round_trips_through_the_extractor():
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "identity", "name": "acme"},
            {"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.30']"},
            {"type": "indicator", "pattern": "[domain-name:value = 'c2.example']"},
            {
                "type": "indicator",
                "pattern": (
                    "[file:hashes.'SHA-256' = "
                    "'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"
                ),
            },
            {
                "type": "vulnerability",
                "external_references": [{"source_name": "cve", "external_id": "CVE-2024-21412"}],
            },
            "not-an-object",
        ],
    }
    found = extract_from_stix(json.dumps(bundle))
    assert found == [
        "198.51.100.30",
        "c2.example",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "CVE-2024-21412",
    ]


def test_malformed_stix_is_rejected_with_a_clear_error():
    with pytest.raises(ValidationError):
        extract_from_stix("{ not json")
    with pytest.raises(ValidationError):
        extract_from_stix("[]")


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (
            '{"type":"bundle","objects":[{"type":"indicator","pattern":"[url:value = \'http://a.example/x\']"}]}',
            "http://a.example/x",
        ),
        ("value,source\n198.51.100.44,otx\n", "198.51.100.44"),
        ("just prose about 203.0.113.77", "203.0.113.77"),
    ],
)
def test_auto_format_detection(content, expected):
    assert extract_indicators(content) == [expected]


def test_unsupported_format_is_rejected():
    with pytest.raises(ValidationError):
        extract_indicators("anything", fmt="yaml")


def test_oversized_documents_are_refused_before_being_scanned():
    """Scanning is linear but not free, so size is what bounds the CPU cost."""
    with pytest.raises(ValidationError, match="too large"):
        extract_indicators("a" * (MAX_CONTENT_CHARS + 1))


def test_a_document_at_the_size_limit_is_scanned_quickly():
    # Adversarial shape: dotted labels that keep failing the final TLD check.
    hostile = ("a." * 40 + "1 ") * (MAX_CONTENT_CHARS // 84)
    start = time.perf_counter()
    extract_indicators(hostile[:MAX_CONTENT_CHARS])
    assert time.perf_counter() - start < 5.0
